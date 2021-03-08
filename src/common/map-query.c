/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <common/error.h>
#include <common/macros.h>
#include <common/optional.h>
#include <common/payload.h>

#include <lttng/map/map-query-internal.h>

struct lttng_map_query *lttng_map_query_create(
		enum lttng_map_query_config_cpu cpu,
		enum lttng_map_query_config_buffer buffer,
		enum lttng_map_query_config_app_bitness bitness)
{
	struct lttng_map_query *query = NULL;

	if ((buffer == LTTNG_MAP_QUERY_CONFIG_BUFFER_KERNEL_GLOBAL) ^
			(bitness == LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_KERNEL)) {
		/*
		 * If any of the buffer or bitness config is set to kernel,
		 * they other has to as well.
		 */
		goto end;
	}

	if (bitness != LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_ALL &&
			bitness != LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_KERNEL) {
		/* We currently don't support targetting a specific bitness. */
		goto end;
	}

	query = zmalloc(sizeof(struct lttng_map_query));
	if (!query) {
		goto end;
	}

	query->config_cpu = cpu;
	query->config_buffer = buffer;
	query->config_bitness = bitness;

	query->sum_by_uid = false;
	query->sum_by_pid = false;
	query->sum_by_cpu = false;
	// defaults to true for now.
	query->sum_by_app_bitness = true;

	if (query->config_cpu == LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET) {
		lttng_dynamic_array_init(&query->cpu_array, sizeof(int), NULL);
	}

	switch(query->config_buffer) {
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET:
		lttng_dynamic_array_init(&query->uid_array, sizeof(uid_t), NULL);
		break;
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET:
		lttng_dynamic_array_init(&query->pid_array, sizeof(pid_t), NULL);
		break;
	default:
		break;
	}
end:
	return query;
}

enum lttng_map_query_status lttng_map_query_set_sum_by_cpu(
 	struct lttng_map_query *query, bool sum_by_cpu)
{
	query->sum_by_cpu = sum_by_cpu;

	return LTTNG_MAP_QUERY_STATUS_OK;
}

enum lttng_map_query_status lttng_map_query_set_sum_by_app_bitness(
 	struct lttng_map_query *query, bool sum_by_app_bitness)
{
	enum lttng_map_query_status status;

	if (query->config_bitness != LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_ALL) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	query->sum_by_app_bitness = sum_by_app_bitness;
	status = LTTNG_MAP_QUERY_STATUS_OK;

end:
	return status;
}

enum lttng_map_query_status lttng_map_query_set_sum_by_pid(
 	struct lttng_map_query *query, bool sum_by_pid)
{
	enum lttng_map_query_status status;

	switch (query->config_buffer) {
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_ALL:
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET:
		break;
	default:
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	query->sum_by_pid = sum_by_pid;
	status = LTTNG_MAP_QUERY_STATUS_OK;

end:
	return status;
}

enum lttng_map_query_status lttng_map_query_set_sum_by_uid(
		struct lttng_map_query *query, bool sum_by_uid)
{
	enum lttng_map_query_status status;

	switch (query->config_buffer) {
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_ALL:
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET:
		break;
	default:
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	query->sum_by_uid = sum_by_uid;
	status = LTTNG_MAP_QUERY_STATUS_OK;

end:
	return status;
}

enum lttng_map_query_status lttng_map_query_add_cpu(
		struct lttng_map_query *query, int cpu_id)
{
	enum lttng_map_query_status status;
	unsigned int cpu_count;
	int ret;

	if (query->config_cpu != LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	lttng_map_query_get_cpu_count(query, &cpu_count);
	if (cpu_count > 0) {
		ERR("Only one CPU can be targeted in a query at the moment");
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	ret = lttng_dynamic_array_add_element(&query->cpu_array, &cpu_id);
	if (ret) {
		status = LTTNG_MAP_QUERY_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_QUERY_STATUS_OK;
end:
	return status;
}

enum lttng_map_query_status lttng_map_query_add_uid(
 	struct lttng_map_query *query, uid_t uid)
{
	int ret;
	unsigned int uid_count;
	enum lttng_map_query_status status;

	if (query->config_buffer != LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	lttng_map_query_get_uid_count(query, &uid_count);
	if (uid_count > 0) {
		ERR("Only one UID can be targeted in a query at the moment");
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	ret = lttng_dynamic_array_add_element(&query->uid_array, &uid);
	if (ret) {
		status = LTTNG_MAP_QUERY_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_QUERY_STATUS_OK;
end:
	return status;
}

enum lttng_map_query_status lttng_map_query_add_pid(
 	struct lttng_map_query *query, pid_t pid)
{
	int ret;
	unsigned int pid_count;
	enum lttng_map_query_status status;

	if (query->config_buffer != LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	lttng_map_query_get_pid_count(query, &pid_count);
	if (pid_count > 0) {
		ERR("Only one PID can be targeted in a query at the moment");
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	ret = lttng_dynamic_array_add_element(&query->pid_array, &pid);
	if (ret) {
		status = LTTNG_MAP_QUERY_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_QUERY_STATUS_OK;
end:
	return status;
}

enum lttng_map_query_status lttng_map_query_add_key_filter(
 	struct lttng_map_query *query, const char *key_filter)
{
	enum lttng_map_query_status status;

	query->key_filter = strdup(key_filter);
	if (!query->key_filter) {
		status = LTTNG_MAP_QUERY_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_QUERY_STATUS_OK;
end:
	return status;
}

enum lttng_map_query_config_cpu lttng_map_query_get_config_cpu(
 		const struct lttng_map_query *query)
{
	return query->config_cpu;
}

enum lttng_map_query_config_buffer lttng_map_query_get_config_buffer(
 		const struct lttng_map_query *query)
{
	return query->config_buffer;
}

enum lttng_map_query_config_app_bitness lttng_map_query_get_config_app_bitness(
 		const struct lttng_map_query *query)
{
	return query->config_bitness;
}

bool lttng_map_query_get_config_sum_by_cpu(
 		const struct lttng_map_query *query)
{
	return query->sum_by_cpu;
}

bool lttng_map_query_get_config_sum_by_pid(
 		const struct lttng_map_query *query)
{
	return query->sum_by_pid;
}

bool lttng_map_query_get_config_sum_by_uid(
 		const struct lttng_map_query *query)
{
	return query->sum_by_uid;
}

bool lttng_map_query_get_config_sum_by_app_bitness(
 		const struct lttng_map_query *query)
{
	return query->sum_by_app_bitness;
}

enum lttng_map_query_status lttng_map_query_get_cpu_count(
		const struct lttng_map_query *query, unsigned int *count)
{
	enum lttng_map_query_status status;

	assert(query);
	if (query->config_cpu != LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	if (!count) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_array_get_count(&query->cpu_array);
	status = LTTNG_MAP_QUERY_STATUS_OK;

end:
	return status;
}

enum lttng_map_query_status lttng_map_query_get_cpu_at_index(
 		const struct lttng_map_query *query, unsigned int index,
		int *cpu)
{
	enum lttng_map_query_status status;

	assert(query);

	if (query->config_cpu != LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}


	*cpu = *(int *) lttng_dynamic_array_get_element(&query->cpu_array, index);
	status = LTTNG_MAP_QUERY_STATUS_OK;
end:
	return status;
}

enum lttng_map_query_status lttng_map_query_get_uid_count(
		const struct lttng_map_query *query, unsigned int *count)
{
	enum lttng_map_query_status status;

	assert(query);
	if (query->config_buffer != LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	if (!count) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_array_get_count(&query->uid_array);
	status = LTTNG_MAP_QUERY_STATUS_OK;

end:
	return status;
}

enum lttng_map_query_status lttng_map_query_get_uid_at_index(
 		const struct lttng_map_query *query, unsigned int index,
		uid_t *uid)
{
	enum lttng_map_query_status status;

	assert(query);

	if (query->config_buffer != LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}


	*uid = *(uid_t *) lttng_dynamic_array_get_element(&query->uid_array, index);
	status = LTTNG_MAP_QUERY_STATUS_OK;
end:
	return status;
}

enum lttng_map_query_status lttng_map_query_get_pid_count(
		const struct lttng_map_query *query, unsigned int *count)
{
	enum lttng_map_query_status status;

	assert(query);
	if (query->config_buffer != LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	if (!count) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_array_get_count(&query->pid_array);
	status = LTTNG_MAP_QUERY_STATUS_OK;

end:
	return status;
}

enum lttng_map_query_status lttng_map_query_get_pid_at_index(
 		const struct lttng_map_query *query, unsigned int index,
		pid_t *pid)
{
	enum lttng_map_query_status status;

	assert(query);

	if (query->config_buffer != LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET) {
		status = LTTNG_MAP_QUERY_STATUS_INVALID;
		goto end;
	}


	*pid = *(pid_t *) lttng_dynamic_array_get_element(&query->pid_array, index);
	status = LTTNG_MAP_QUERY_STATUS_OK;
end:
	return status;
}


enum lttng_map_query_status lttng_map_query_get_key_filter(
 		const struct lttng_map_query *query, const char **key_filter)
{
	enum lttng_map_query_status status;

	if (query->key_filter == NULL) {
		status = LTTNG_MAP_QUERY_STATUS_NONE;
		goto end;
	}

	*key_filter = query->key_filter;
	status = LTTNG_MAP_QUERY_STATUS_OK;
end:
	return status;
}

LTTNG_HIDDEN
ssize_t lttng_map_query_create_from_payload(struct lttng_payload_view *src_view,
		struct lttng_map_query **query)
{
	ssize_t ret, offset = 0;
	struct lttng_map_query *local_query;
	const struct lttng_map_query_comm *query_comm;

	if (!src_view || !query) {
		ret = -1;
		goto end;
	}

	query_comm = (typeof(query_comm)) src_view->buffer.data;
	offset += sizeof(*query_comm);

	local_query = lttng_map_query_create(query_comm->config_cpu,
			query_comm->config_buffer, query_comm->config_app_bitness);
	if (!local_query) {
		ret = -1;
		goto end;
	}

	local_query->sum_by_cpu = query_comm->sum_by_cpu;
	local_query->sum_by_pid = query_comm->sum_by_pid;
	local_query->sum_by_uid = query_comm->sum_by_uid;
	local_query->sum_by_app_bitness = query_comm->sum_by_app_bitness;

	if (query_comm->key_filter_length != 0) {
		const char *key_filter;
		struct lttng_payload_view key_filter_view =
				lttng_payload_view_from_view(
						src_view, offset,
						query_comm->key_filter_length);

		key_filter = key_filter_view.buffer.data;
		if (!lttng_buffer_view_contains_string(&key_filter_view.buffer,
					key_filter, query_comm->key_filter_length)){
			ret = -1;
			goto end;
		}

		lttng_map_query_add_key_filter(local_query, key_filter);

		offset += query_comm->key_filter_length;
	}

	if (local_query->config_cpu == LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET) {
		unsigned int cpu_idx;

		assert(query_comm->cpu_count > 0);

		for (cpu_idx = 0; cpu_idx < query_comm->cpu_count; cpu_idx++) {
			int cpu_id;
			struct lttng_payload_view cpu_id_view =
					lttng_payload_view_from_view( src_view,
						offset, sizeof(cpu_id));
			 cpu_id = *(int *) cpu_id_view.buffer.data;
			 lttng_map_query_add_cpu(local_query, cpu_id);
			 offset+=sizeof(cpu_id);
		}
	}

	switch (local_query->config_buffer){
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET:
	{
		unsigned int pid_idx;

		assert(query_comm->pid_count > 0);

		for (pid_idx = 0; pid_idx < query_comm->pid_count; pid_idx++) {
			pid_t pid;
			struct lttng_payload_view pid_view =
					lttng_payload_view_from_view( src_view,
						offset, sizeof(pid));
			 pid = *(pid_t *) pid_view.buffer.data;
			 lttng_map_query_add_pid(local_query, pid);
			 offset+=sizeof(pid);
		}
		break;
	}
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET:
	{
		unsigned int uid_idx;

		assert(query_comm->uid_count > 0);

		for (uid_idx = 0; uid_idx < query_comm->uid_count; uid_idx++) {
			uid_t uid;
			struct lttng_payload_view uid_view =
					lttng_payload_view_from_view( src_view,
						offset, sizeof(uid));
			 uid = *(uid_t *) uid_view.buffer.data;
			 lttng_map_query_add_uid(local_query, uid);
			 offset+=sizeof(uid);
		}
	}
	default:
		break;
	}

	ret = offset;
	*query = local_query;
	local_query = NULL;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_map_query_serialize(const struct lttng_map_query *query,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_map_query_comm query_comm = {};
	enum lttng_map_query_status status;

	query_comm.config_cpu = (uint8_t) query->config_cpu;
	query_comm.config_buffer = (uint8_t) query->config_buffer;
	query_comm.config_app_bitness = (uint8_t) query->config_bitness;

	query_comm.sum_by_cpu = (uint8_t) query->sum_by_cpu;
	query_comm.sum_by_uid = (uint8_t) query->sum_by_uid;
	query_comm.sum_by_pid = (uint8_t) query->sum_by_pid;
	query_comm.sum_by_app_bitness = (uint8_t) query->sum_by_app_bitness;

	if (query->config_cpu == LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET) {
		unsigned int cpu_count;
		status = lttng_map_query_get_cpu_count(query, &cpu_count);
		if (status != LTTNG_MAP_QUERY_STATUS_OK) {
			ret = -1;
			goto end;
		}

		query_comm.cpu_count = cpu_count;
	}

	switch (query->config_buffer){
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET:
	{
		unsigned int pid_count;
		status = lttng_map_query_get_pid_count(query, &pid_count);
		if (status != LTTNG_MAP_QUERY_STATUS_OK) {
			ret = -1;
			goto end;
		}
		query_comm.pid_count = pid_count;
		break;
	}
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET:
	{
		unsigned int uid_count;
		status = lttng_map_query_get_uid_count(query, &uid_count);
		if (status != LTTNG_MAP_QUERY_STATUS_OK) {
			ret = -1;
			goto end;
		}
		query_comm.uid_count = uid_count;
	}
	default:
		break;
	}

	if (query->key_filter) {
		query_comm.key_filter_length = strlen(query->key_filter) + 1;
	} else {
		query_comm.key_filter_length = 0;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, &query_comm,
			sizeof(query_comm));
	if (ret) {
		goto end;
	}

	/* key_filter */
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, query->key_filter,
			query_comm.key_filter_length);
	if (ret) {
		goto end;
	}

	if (query->config_cpu == LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET) {
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				query->cpu_array.buffer.data,
				query->cpu_array.buffer.size);
		if (ret) {
			goto end;
		}
	}

	switch (query->config_buffer){
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET:
	{
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				query->pid_array.buffer.data,
				query->pid_array.buffer.size);
		if (ret) {
			goto end;
		}
	}
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET:
	{
		ret = lttng_dynamic_buffer_append(&payload->buffer,
				query->uid_array.buffer.data,
				query->uid_array.buffer.size);
		if (ret) {
			goto end;
		}
	}
	default:
		break;
	}

end:
	return ret;
}

void lttng_map_query_destroy(struct lttng_map_query *query)
{
	assert(query);

	if (query->config_cpu == LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET) {
		lttng_dynamic_array_reset(&query->cpu_array);
	}

	switch(query->config_buffer) {
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET:
		lttng_dynamic_array_reset(&query->uid_array);
		break;
	case LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET:
		lttng_dynamic_array_reset(&query->pid_array);
		break;
	default:
		break;
	}
	free(query->key_filter);
	free(query);
}
