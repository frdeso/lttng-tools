/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <urcu/compiler.h>
#include <pthread.h>

#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/index-allocator.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/shm.h>
#include <lttng/trigger/trigger-internal.h>

#include "lttng-ust-error.h"
#include "trigger-error-accounting.h"
#include "ust-app.h"

struct index_ht_entry {
	struct lttng_ht_node_u64 node;
	uint64_t error_counter_index;
	struct rcu_head rcu_head;
};

struct error_account_entry {
	struct lttng_ht_node_u64 node;
	struct rcu_head rcu_head;
	struct lttng_ust_object_data *counter;
	struct lttng_ust_object_data **cpu_counters;
	struct ustctl_daemon_counter *daemon_counter;
};

struct kernel_error_account_entry {
	int kernel_trigger_error_counter_fd;
};

static struct kernel_error_account_entry kernel_error_accountant = { 0 };

/* Hashtable mapping trigger token to index_ht_entry */
static struct lttng_ht *error_counter_indexes_ht;

/* Hashtable mapping uid to error_account_entry */
static struct lttng_ht *error_counter_uid_ht;

static uint64_t error_counter_size = 0;
struct lttng_index_allocator *index_allocator;


void trigger_error_accounting_init(uint64_t nb_bucket)
{
	struct lttng_index_allocator *error_counter_index_allocator;

	error_counter_index_allocator = lttng_index_allocator_create(nb_bucket);
	if (!error_counter_index_allocator) {
		ERR("Failed to allocate trigger error counter index");
		goto error_index_allocator;
	}

	index_allocator = error_counter_index_allocator;

	error_counter_indexes_ht = lttng_ht_new(16, LTTNG_HT_TYPE_U64);
	error_counter_uid_ht = lttng_ht_new(16, LTTNG_HT_TYPE_U64);
	error_counter_size = nb_bucket;

error_index_allocator:
	return;
}

static
enum trigger_error_accounting_status get_error_counter_index_for_token(
		uint64_t tracer_token, uint64_t *error_counter_index)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct index_ht_entry *index_entry;;
	enum trigger_error_accounting_status status;

	rcu_read_lock();
	lttng_ht_lookup(error_counter_indexes_ht, &tracer_token, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node) {
		index_entry = caa_container_of(node, struct index_ht_entry, node);
		*error_counter_index = index_entry->error_counter_index;
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;
	} else {
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}
	rcu_read_unlock();

	return status;
}

#ifdef HAVE_LIBLTTNG_UST_CTL
static
struct error_account_entry *get_uid_accounting_entry(const struct ust_app *app)
{
	struct error_account_entry *entry;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	uint64_t key = app->uid;

	lttng_ht_lookup(error_counter_uid_ht, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if(node == NULL) {
		entry = NULL;
	} else {
		entry = caa_container_of(node, struct error_account_entry, node);
	}

	return entry;
}

static
struct error_account_entry *create_uid_accounting_entry(
		const struct ust_app *app)
{
	int i, ret, nr_counter_cpu_fds;
	struct ustctl_counter_dimension dimension[1] = {0};
	struct ustctl_daemon_counter *daemon_counter;
	struct lttng_ust_object_data *counter, **counter_cpus;
	int *counter_cpu_fds;
	struct error_account_entry *entry = NULL;

	entry = zmalloc(sizeof(struct error_account_entry));
	if (!entry) {
		PERROR("Allocating trigger error acounting entry")
		goto error;
	}

	nr_counter_cpu_fds = ustctl_get_nr_cpu_per_counter();
	counter_cpu_fds = zmalloc(nr_counter_cpu_fds * sizeof(*counter_cpu_fds));
	if (!counter_cpu_fds) {
		ret = -1;
		goto error_counter_cpu_fds_alloc;
	}

	counter_cpus = zmalloc(nr_counter_cpu_fds * sizeof(*counter_cpus));
	if (!counter_cpus) {
		ret = -1;
		goto error_counter_cpus_alloc;
	}

	for (i = 0; i < nr_counter_cpu_fds; i++) {
		counter_cpu_fds[i] = shm_create_anonymous("trigger-error-accounting");
		//FIXME error handling
	}


	dimension[0].size = error_counter_size;
	dimension[0].has_underflow = false;
	dimension[0].has_overflow = false;

	daemon_counter = ustctl_create_counter(1, dimension, 0, -1,
			nr_counter_cpu_fds, counter_cpu_fds,
			USTCTL_COUNTER_BITNESS_32,
			USTCTL_COUNTER_ARITHMETIC_MODULAR,
			USTCTL_COUNTER_ALLOC_PER_CPU);
	assert(daemon_counter);

	ret = ustctl_create_counter_data(daemon_counter, &counter);
	assert(ret == 0);

	for (i = 0; i < nr_counter_cpu_fds; i++) {
		ret = ustctl_create_counter_cpu_data(daemon_counter, i,
				&counter_cpus[i]);
		assert(ret == 0);
	}

	entry->daemon_counter = daemon_counter;
	entry->counter = counter;
	entry->cpu_counters = counter_cpus;

	lttng_ht_node_init_u64(&entry->node, app->uid);
	lttng_ht_add_unique_u64(error_counter_uid_ht, &entry->node);

	goto end;

error_counter_cpus_alloc:
	free(counter_cpu_fds);
error_counter_cpu_fds_alloc:
	free(entry);
error:
	entry = NULL;
end:
	return entry;
}

static
enum trigger_error_accounting_status send_counter_data_to_ust(
		struct ust_app *app,
		struct lttng_ust_object_data *new_counter)
{
	int ret;
	enum trigger_error_accounting_status status;

	/* Attach counter to trigger group */
	pthread_mutex_lock(&app->sock_lock);
	ret = ustctl_send_counter_data_to_ust(app->sock,
			app->token_communication.handle->handle, new_counter);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
			ERR("Error ustctl send counter data to app pid: %d with ret %d",
					app->pid, ret);
			status = TRIGGER_ERROR_ACCOUNTING_STATUS_ERR;
		} else {
			DBG3("UST app send counter data to ust failed. Application is dead.");
			status = TRIGGER_ERROR_ACCOUNTING_STATUS_APP_DEAD;
		}
		goto end;
	}

	status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

static
enum trigger_error_accounting_status send_counter_cpu_data_to_ust(
		struct ust_app *app,
		struct lttng_ust_object_data *new_counter,
		struct lttng_ust_object_data *new_counter_cpu)
{
	int ret;
	enum trigger_error_accounting_status status;

	pthread_mutex_lock(&app->sock_lock);
	ret = ustctl_send_counter_cpu_data_to_ust(app->sock,
			new_counter, new_counter_cpu);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
			ERR("Error ustctl send counter cpu data to app pid: %d with ret %d",
					app->pid, ret);
			status = TRIGGER_ERROR_ACCOUNTING_STATUS_ERR;
		} else {
			DBG3("UST app send counter cpu data to ust failed. Application is dead.");
			status = TRIGGER_ERROR_ACCOUNTING_STATUS_APP_DEAD;
		}
		goto end;
	}

	status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

enum trigger_error_accounting_status trigger_error_accounting_register_app(
		struct ust_app *app)
{
	int ret;
	uint64_t i, nr_counter_cpu_fds;
	struct lttng_ust_object_data *new_counter;
	struct error_account_entry *entry;
	enum trigger_error_accounting_status status;

	/*
	 * Check if we already have a error counter for the user id of this
	 * app. If not, create one.
	 */
	rcu_read_lock();
	entry = get_uid_accounting_entry(app);
	if (entry == NULL) {
		entry = create_uid_accounting_entry(app);
	}

	/* Duplicate counter object data*/
	ret = ustctl_duplicate_ust_object_data(&new_counter,
			entry->counter);
	assert(ret == 0);
	rcu_read_unlock();

	status = send_counter_data_to_ust(app, new_counter);
	if (status != TRIGGER_ERROR_ACCOUNTING_STATUS_OK) {
		goto end;
	}

	nr_counter_cpu_fds = ustctl_get_nr_cpu_per_counter();
	for (i = 0; i < nr_counter_cpu_fds; i++) {
		struct lttng_ust_object_data *new_counter_cpu = NULL;

		ret = ustctl_duplicate_ust_object_data(&new_counter_cpu,
				entry->cpu_counters[i]);
		assert(ret == 0);

		status = send_counter_cpu_data_to_ust(app,
				new_counter, new_counter_cpu);
		if (status != TRIGGER_ERROR_ACCOUNTING_STATUS_OK) {
			goto end;
		}
	}

end:
	return status;
}

static
enum trigger_error_accounting_status trigger_error_accounting_ust_get_count(
		const struct lttng_trigger *trigger, uint64_t *count)
{
	struct lttng_ht_iter iter;
	struct error_account_entry *uid_entry;
	uint64_t error_counter_index, global_sum = 0;
	enum trigger_error_accounting_status status;
	size_t dimension_indexes[1];

	/*
	 * Go over all error counters (ignoring uid) as a trigger (and trigger
	 * errors) can be generated from any applications that this session
	 * daemon is managing.
	 */

	status = get_error_counter_index_for_token(
			lttng_trigger_get_tracer_token(trigger), &error_counter_index);
	if (status != TRIGGER_ERROR_ACCOUNTING_STATUS_OK) {
		goto end;
	}

	dimension_indexes[0] = error_counter_index;

	rcu_read_lock();

	cds_lfht_for_each_entry(error_counter_uid_ht->ht, &iter.iter,
			uid_entry, node.node) {
		int ret;
		int64_t local_value = 0;;
		bool overflow = 0, underflow = 0;
		ret = ustctl_counter_aggregate(uid_entry->daemon_counter,
				dimension_indexes, &local_value, &overflow,
				&underflow);
		assert(ret == 0);

		/* should always be zero or above. */
		assert(local_value >= 0);
		global_sum += (uint64_t) local_value;

	}

	rcu_read_unlock();

	*count = global_sum;
	status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;

end:
	return status;
}

static
enum trigger_error_accounting_status trigger_error_accounting_ust_clear(
		const struct lttng_trigger *trigger)
{
	struct lttng_ht_iter iter;
	struct error_account_entry *uid_entry;
	uint64_t error_counter_index;
	enum trigger_error_accounting_status status;
	size_t dimension_indexes[1];

	/*
	 * Go over all error counters (ignoring uid) as a trigger (and trigger
	 * errors) can be generated from any applications that this session
	 * daemon is managing.
	 */

	status = get_error_counter_index_for_token(
			lttng_trigger_get_tracer_token(trigger),
			&error_counter_index);
	if (status != TRIGGER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Error getting trigger error counter index");
		goto end;
	}

	dimension_indexes[0] = error_counter_index;

	rcu_read_lock();
	cds_lfht_for_each_entry(error_counter_uid_ht->ht, &iter.iter,
			uid_entry, node.node) {
		int ret;
		ret = ustctl_counter_clear(uid_entry->daemon_counter,
				dimension_indexes);
		assert(ret == 0);
	}

	rcu_read_unlock();
	status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

enum trigger_error_accounting_status trigger_error_accounting_register_kernel(
		int kernel_trigger_group_fd)
{
	int local_fd = -1, ret;
	enum trigger_error_accounting_status status;
	struct lttng_kernel_counter_conf error_counter_conf;

	error_counter_conf.arithmetic = LTTNG_KERNEL_COUNTER_ARITHMETIC_MODULAR;
	error_counter_conf.bitness = LTTNG_KERNEL_COUNTER_BITNESS_64BITS;
	error_counter_conf.global_sum_step = 0;
	error_counter_conf.number_dimensions = 1;
	error_counter_conf.dimensions[0].size = error_counter_size;
	error_counter_conf.dimensions[0].has_underflow = false;
	error_counter_conf.dimensions[0].has_overflow = false;

	ret = kernctl_create_trigger_group_error_counter(
			kernel_trigger_group_fd, &error_counter_conf);
	if (ret < 0) {
		PERROR("ioctl kernel create trigger group error counter");
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_ERR;
		goto error;
	}

	/* Store locally */
	local_fd = ret;

	/* Prevent fd duplication after execlp() */
	ret = fcntl(local_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl trigger error counter fd");
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_ERR;
		goto error;
	}

	DBG("Kernel trigger group error counter (fd: %d)", local_fd);

	kernel_error_accountant.kernel_trigger_error_counter_fd = local_fd;
	status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;

error:
	return status;
}

static
enum trigger_error_accounting_status create_error_counter_index_for_token(
		uint64_t tracer_token, uint64_t *error_counter_index)
{
	struct index_ht_entry *index_entry;;
	enum lttng_index_allocator_status index_alloc_status;
	uint64_t local_error_counter_index;
	enum trigger_error_accounting_status status;

	/* Allocate a new index for that counter. */
	index_alloc_status = lttng_index_allocator_alloc(index_allocator,
			&local_error_counter_index);
	switch (index_alloc_status) {
	case LTTNG_INDEX_ALLOCATOR_STATUS_EMPTY:
		DBG("No more index available in the configured trigger error counter:"
				"number-of-indices=%"PRIu64,
				lttng_index_allocator_get_index_count(
					index_allocator));
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE;
		goto end;
	case LTTNG_INDEX_ALLOCATOR_STATUS_OK:
		break;
	default:
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_ERR;
		goto end;
	}

	index_entry = zmalloc(sizeof(*index_entry));
	if (index_entry == NULL) {
		PERROR("Trigger error counter hashtable entry zmalloc");
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto end;
	}

	index_entry->error_counter_index = local_error_counter_index;
	lttng_ht_node_init_u64(&index_entry->node, tracer_token);

	lttng_ht_add_unique_u64(error_counter_indexes_ht, &index_entry->node);

	*error_counter_index = local_error_counter_index;
	status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

enum trigger_error_accounting_status trigger_error_accounting_register_trigger(
		const struct lttng_trigger *trigger,
		uint64_t *error_counter_index)
{
	enum trigger_error_accounting_status status;
	uint64_t local_error_counter_index;

	/* Check if this trigger already has a error counter index assigned. */
	status = get_error_counter_index_for_token(
			lttng_trigger_get_tracer_token(trigger),
			&local_error_counter_index);
	switch (status) {
	case TRIGGER_ERROR_ACCOUNTING_STATUS_NOT_FOUND:
		DBG("Trigger error counter index for this tracer token not found. Allocating a new one.");
		status = create_error_counter_index_for_token(
				lttng_trigger_get_tracer_token(trigger),
				&local_error_counter_index);
		if (status != TRIGGER_ERROR_ACCOUNTING_STATUS_OK) {
			goto end;
		}
	case TRIGGER_ERROR_ACCOUNTING_STATUS_OK:
		*error_counter_index = local_error_counter_index;
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;
		break;
	default:
		break;
	}

end:
	return status;
}

static
enum trigger_error_accounting_status trigger_error_accounting_kernel_get_count(
		const struct lttng_trigger *trigger, uint64_t *count)
{
	struct lttng_kernel_counter_value counter_value;
	enum trigger_error_accounting_status status;
	uint64_t error_counter_index;
	int ret;

	status = get_error_counter_index_for_token(
			lttng_trigger_get_tracer_token(trigger), &error_counter_index);
	if (status != TRIGGER_ERROR_ACCOUNTING_STATUS_OK) {
		goto end;
	}

	counter_value.number_dimensions = 1;
	counter_value.dimension_indexes[0] = error_counter_index;

	assert(kernel_error_accountant.kernel_trigger_error_counter_fd);

	ret = kernctl_counter_get_value(
			kernel_error_accountant.kernel_trigger_error_counter_fd,
			&counter_value);
	if (ret) {
		ERR("Error getting trigger error count.");
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_ERR;
		goto end;
	}

	if (counter_value.value < 0) {
		ERR("Trigger error counter less than zero.");
		status = TRIGGER_ERROR_ACCOUNTING_STATUS_ERR;
		goto end;
	}

	/* Error count can't be negative. */
	assert(counter_value.value >= 0);
	*count = (uint64_t) counter_value.value;

	status = TRIGGER_ERROR_ACCOUNTING_STATUS_OK;

end:
	return status;
}

enum trigger_error_accounting_status trigger_error_accounting_get_count(
		const struct lttng_trigger *trigger, uint64_t *count)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		return trigger_error_accounting_kernel_get_count(trigger, count);
#ifdef HAVE_LIBLTTNG_UST_CTL
	case LTTNG_DOMAIN_UST:
		return trigger_error_accounting_ust_get_count(trigger, count);
#endif /* HAVE_LIBLTTNG_UST_CTL */
	default:
		abort();
	}
}

static
enum trigger_error_accounting_status trigger_error_accounting_clear(
		const struct lttng_trigger *trigger)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		// FIXME: Should we clear it here? Right now I believe it's clear when
		// we create a new trigger in the kernel.
		return TRIGGER_ERROR_ACCOUNTING_STATUS_OK;
#ifdef HAVE_LIBLTTNG_UST_CTL
	case LTTNG_DOMAIN_UST:
		return trigger_error_accounting_ust_clear(trigger);
#endif /* HAVE_LIBLTTNG_UST_CTL */
	default:
		abort();
	}
}

static void free_index_ht_entry(struct rcu_head *head)
{
	struct index_ht_entry *entry = caa_container_of(head,
			struct index_ht_entry, rcu_head);
	free(entry);
}

void trigger_error_accounting_unregister_trigger(
		const struct lttng_trigger *trigger)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct index_ht_entry *index_entry;
	enum trigger_error_accounting_status status;
	enum lttng_index_allocator_status index_alloc_status;
	uint64_t tracer_token = lttng_trigger_get_tracer_token(trigger);

	status = trigger_error_accounting_clear(trigger);
	if (status != TRIGGER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Error clearing trigger error counter index");
	}

	rcu_read_lock();
	lttng_ht_lookup(error_counter_indexes_ht, &tracer_token, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if(node) {
		index_entry = caa_container_of(node, struct index_ht_entry, node);
		index_alloc_status = lttng_index_allocator_release(
				index_allocator,
				index_entry->error_counter_index);
		if (index_alloc_status != LTTNG_INDEX_ALLOCATOR_STATUS_OK) {
			ERR("Error releasing trigger error counter index");
		}

		lttng_ht_del(error_counter_indexes_ht, &iter);
		call_rcu(&index_entry->rcu_head, free_index_ht_entry);
	}
	rcu_read_unlock();
}

static void free_error_account_entry(struct rcu_head *head)
{
	struct error_account_entry *entry = caa_container_of(head,
			struct error_account_entry, rcu_head);
#ifdef HAVE_LIBLTTNG_UST_CTL
	ustctl_destroy_counter(entry->daemon_counter);
#endif /* HAVE_LIBLTTNG_UST_CTL */

	free(entry);
}

void trigger_error_accounting_fini(void)
{
	struct lttng_ht_iter iter;
	struct index_ht_entry *index_entry;
	struct error_account_entry *uid_entry;

	if (kernel_error_accountant.kernel_trigger_error_counter_fd) {
		int ret = close(kernel_error_accountant.kernel_trigger_error_counter_fd);
		if (ret) {
			PERROR("Closing kernel trigger error counter");
		}
	}

	rcu_read_lock();

	cds_lfht_for_each_entry(error_counter_uid_ht->ht, &iter.iter,
			uid_entry, node.node) {
		cds_lfht_del(error_counter_uid_ht->ht, &uid_entry->node.node);
		call_rcu(&uid_entry->rcu_head, free_error_account_entry);
	}

	cds_lfht_for_each_entry(error_counter_indexes_ht->ht, &iter.iter,
			index_entry, node.node) {
		cds_lfht_del(error_counter_indexes_ht->ht, &index_entry->node.node);
		call_rcu(&index_entry->rcu_head, free_index_ht_entry);
	}

	rcu_read_unlock();

	lttng_ht_destroy(error_counter_uid_ht);
	lttng_ht_destroy(error_counter_indexes_ht);
}
