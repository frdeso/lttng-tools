/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */


#include "lttng/domain.h"
#include <common/kernel-ctl/kernel-ctl.h>
#include <lttng/map/map.h>
#include <lttng/map/map-internal.h>

#include "lttng-sessiond.h"
#include "lttng-ust-error.h"
#include "notification-thread-commands.h"
#include "trace-kernel.h"
#include "trace-ust.h"

#include "map.h"

enum lttng_error_code map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map)
{
	enum lttng_error_code ret;
	struct ltt_kernel_map *kmap;
	enum lttng_map_status map_status;
	const char *map_name;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_KERNEL);

	map_status = lttng_map_get_name(map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Can't get map name");
		ret = -1;
		goto error;
	}

	kmap = trace_kernel_get_map_by_name(map_name, ksession);
	if (kmap) {
		DBG("Kernel map named \"%s\" already present", map_name);
		ret = -1;
		goto error;
	}

	kmap = trace_kernel_create_map(map);
	assert(kmap);

	ret = kernctl_create_session_counter(ksession->fd,
			&kmap->counter_conf);
	if (ret < 0) {
		PERROR("ioctl kernel create session counter");
		goto error;
	}

	kmap->fd = ret;

	/* Prevent fd duplication after execlp() */
	ret = fcntl(kmap->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session counter fd");
		goto error;
	}

	kmap->map = map;
	lttng_map_get(map);
	cds_list_add(&kmap->list, &ksession->map_list.head);
	ksession->map_count++;

	DBG("Kernel session counter created (fd: %d)", kmap->fd);

	ret = kernctl_enable(kmap->fd);
	if (ret < 0) {
		PERROR("Enable kernel map");
	}

	ret = LTTNG_OK;
error:
	return ret;
}

enum lttng_error_code map_kernel_enable(struct ltt_kernel_session *ksess,
		struct ltt_kernel_map *kmap)
{
	enum lttng_error_code ret = LTTNG_OK;
	const char *map_name;
	enum lttng_map_status map_status;


	assert(ksess);
	assert(kmap);

	map_status = lttng_map_get_name(kmap->map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Error getting kernel map name");
		ret = -1;
		goto end;
	}

	/* If already enabled, everything is OK */
	if (kmap->enabled) {
		DBG3("Map %s already enabled. Skipping", map_name);
		ret = LTTNG_ERR_UST_MAP_EXIST;
		goto end;
	} else {
		kmap->enabled = 1;
		lttng_map_set_is_enabled(kmap->map, true);
		DBG2("Map %s enabled successfully", map_name);
	}

	DBG2("Map %s being enabled in kernel domain", map_name);

	/*
	 * Enable map for UST global domain on all applications. Ignore return
	 * value here since whatever error we got, it means that the map was
	 * not created on one or many registered applications and we can not report
	 * this to the user yet. However, at this stage, the map was
	 * successfully created on the session daemon side so the enable-map
	 * command is a success.
	 */

	ret = kernctl_enable(kmap->fd);
	if (ret < 0) {
		PERROR("Enable kernel map");
	}

	ret = LTTNG_OK;
end:
	return ret;
}

enum lttng_error_code map_kernel_disable(struct ltt_kernel_session *usess,
		struct ltt_kernel_map *kmap)
{
	enum lttng_error_code ret = LTTNG_OK;
	enum lttng_map_status map_status;
	const char *map_name = NULL;

	assert(usess);
	assert(kmap);

	map_status = lttng_map_get_name(kmap->map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Error getting kernel map name");
		ret = -1;
		goto end;
	}

	/* Already disabled */
	if (kmap->enabled == 0) {
		DBG2("Map kernel %s already disabled", map_name);
		ret = LTTNG_ERR_KERNEL_MAP_EXIST;
		goto end;
	}

	kmap->enabled = 0;
	lttng_map_set_is_enabled(kmap->map, false);

	DBG2("Map %s being disabled in kernel global domain", map_name);

	/* Disable map for global domain */
	ret = kernctl_disable(kmap->fd);
	if (ret < 0) {
		ret = LTTNG_ERR_KERNEL_MAP_DISABLE_FAIL;
		goto error;
	}


	DBG2("Map %s disabled successfully", map_name);

	return LTTNG_OK;

end:
error:
	return ret;
}

int map_ust_add(struct ltt_ust_session *usession, struct lttng_map *map)
{
	int ret = 0;
	struct ltt_ust_map *umap;
	enum lttng_map_status map_status;
	const char *map_name;
	enum lttng_buffer_type buffer_type;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_UST);

	map_status = lttng_map_get_name(map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Can't get map name");
		ret = -1;
		goto end;
	}

	umap = trace_ust_find_map_by_name(usession->domain_global.maps,
			map_name);
	if (umap) {
		DBG("UST map named \"%s\" already present", map_name);
		ret = -1;
		goto end;
	}

	buffer_type = lttng_map_get_buffer_type(map);

	umap = trace_ust_create_map(map);
	assert(umap);

	umap->enabled = 1;
	umap->id = trace_ust_get_next_chan_id(usession);
	umap->map = map;
	lttng_map_get(map);

	lttng_map_set_is_enabled(umap->map, true);

	DBG2("Map %s is being created for UST with buffer type %d and id %" PRIu64,
			umap->name, buffer_type, umap->id);

	/* Flag session buffer type. */
	if (!usession->buffer_type_changed) {
		usession->buffer_type = buffer_type;
		usession->buffer_type_changed = 1;
	} else if (usession->buffer_type != buffer_type) {
		/* Buffer type was already set. Refuse to create channel. */
		ret = LTTNG_ERR_BUFFER_TYPE_MISMATCH;
		goto error_free_map;
	}

	rcu_read_lock();

	/* Adding the map to the map hash table. */
	lttng_ht_add_unique_str(usession->domain_global.maps, &umap->node);

	rcu_read_unlock();

	DBG2("Map %s created successfully", umap->name);

	ret = 0;
	goto end;

error_free_map:
	trace_ust_destroy_map(umap);
end:
	return ret;
}

/*
 * Enable UST map for session and domain.
 */
int map_ust_enable(struct ltt_ust_session *usess,
		struct ltt_ust_map *umap)
{
	int ret = LTTNG_OK;

	assert(usess);
	assert(umap);

	/* If already enabled, everything is OK */
	if (umap->enabled) {
		DBG3("Map %s already enabled. Skipping", umap->name);
		ret = LTTNG_ERR_UST_MAP_EXIST;
		goto end;
	} else {
		umap->enabled = 1;
		lttng_map_set_is_enabled(umap->map, true);
		DBG2("Map %s enabled successfully", umap->name);
	}

	if (!usess->active) {
		/*
		 * The map will be activated against the apps
		 * when the session is started as part of the
		 * application map "synchronize" operation.
		 */
		goto end;
	}

	DBG2("Map %s being enabled in UST domain", umap->name);

	/*
	 * Enable map for UST global domain on all applications. Ignore return
	 * value here since whatever error we got, it means that the map was
	 * not created on one or many registered applications and we can not report
	 * this to the user yet. However, at this stage, the map was
	 * successfully created on the session daemon side so the enable-map
	 * command is a success.
	 */
	(void) ust_app_enable_map_glb(usess, umap);


end:
	return ret;
}

int map_ust_disable(struct ltt_ust_session *usess,
		struct ltt_ust_map *umap)
{
	int ret = LTTNG_OK;

	assert(usess);
	assert(umap);

	/* Already disabled */
	if (umap->enabled == 0) {
		DBG2("Map UST %s already disabled", umap->name);
		ret = LTTNG_ERR_UST_MAP_EXIST;
		goto end;
	}

	umap->enabled = 0;
	lttng_map_set_is_enabled(umap->map, false);

	/*
	 * If session is inactive we don't notify the tracer right away. We
	 * wait for the next synchronization.
	 */
	if (!usess->active) {
		goto end;
	}

	DBG2("Map %s being disabled in UST global domain", umap->name);

	/* Disable map for global domain */
	ret = ust_app_disable_map_glb(usess, umap);
	if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
		ret = LTTNG_ERR_UST_MAP_DISABLE_FAIL;
		goto error;
	}


	DBG2("Map %s disabled successfully", umap->name);

	return LTTNG_OK;

end:
error:
	return ret;
}

void map_add_or_increment_map_values(struct lttng_ht *map_values, const char *key,
		int64_t value, bool has_underflowed, bool has_overflowed)
{
	struct map_kv_ht_entry *kv_entry;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter ht_iter;

	lttng_ht_lookup(map_values, (void *) key, &ht_iter);
	node = lttng_ht_iter_get_node_str(&ht_iter);
	if (node == NULL) {
		/*
	 	 * If the key is absent, the key value mapping.
	 	 */
	 	kv_entry = zmalloc(sizeof(*kv_entry));
	 	if (!kv_entry) {
	 		abort();
	 	}

		kv_entry->key = strdup(key);
		kv_entry->value = value;
		kv_entry->has_underflowed = has_underflowed;
		kv_entry->has_overflowed = has_overflowed;

	 	lttng_ht_node_init_str(&kv_entry->node, (char *) kv_entry->key);
	 	lttng_ht_add_unique_str(map_values, &kv_entry->node);

	} else {
		/*
	 	 * If the key is already present, increment the current value with the
	 	 * new value.
	 	 */
	 	kv_entry = caa_container_of(node, typeof(*kv_entry), node);
	 	kv_entry->value += value;
	 	kv_entry->has_underflowed |= has_underflowed;
	 	kv_entry->has_overflowed |= has_overflowed;
	}
}

int map_new_content_section(struct lttng_map_content *map_content,
		enum lttng_map_key_value_pair_list_type list_type,
		bool summed_all_cpus, unsigned int identifier,
		int cpu, struct lttng_ht *values)
{
	int ret;
	struct lttng_map_key_value_pair_list *kv_pair_list;
	enum lttng_map_status map_status;
	struct map_kv_ht_entry *kv_entry;
	struct lttng_ht_iter key_iter;

	kv_pair_list = lttng_map_key_value_pair_list_create(list_type,
			summed_all_cpus);
	switch (list_type) {
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID:
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_UID:
		map_status = lttng_map_key_value_pair_list_set_identifier(
				kv_pair_list, identifier);
		assert(map_status == LTTNG_MAP_STATUS_OK);
		break;
	default:
		break;
	}

	if (!summed_all_cpus) {
		map_status = lttng_map_key_value_pair_list_set_cpu(kv_pair_list,
				cpu);
	}

	cds_lfht_for_each_entry(values->ht, &key_iter.iter, kv_entry, node.node) {
		struct lttng_ht_iter entry_iter;

		struct lttng_map_key_value_pair *pair =
				lttng_map_key_value_pair_create(kv_entry->key,
					kv_entry->value);
		if (kv_entry->has_overflowed) {
			lttng_map_key_value_pair_set_has_overflowed(pair);
		}

		if (kv_entry->has_underflowed) {
			lttng_map_key_value_pair_set_has_underflowed(pair);
		}

		map_status = lttng_map_key_value_pair_list_append_key_value(
				kv_pair_list, pair);

		entry_iter.iter.node = &kv_entry->node.node;
		lttng_ht_del(values, &entry_iter);

		free(kv_entry->key);
		free(kv_entry);
	}

	map_status = lttng_map_content_append_key_value_list(map_content,
			kv_pair_list);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		lttng_map_key_value_pair_list_destroy(kv_pair_list);
		ret = -1;
		ERR("Error appending key-value pair list to map content object");
		goto end;
	}
	ret = 0;
end:
	return ret;
}

