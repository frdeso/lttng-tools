/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_QUERY_H
#define LTTNG_MAP_QUERY_H

#include <stddef.h>
#include <stdbool.h>

#include <lttng/domain.h>
#include <lttng/handle.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_map_query_status {
	LTTNG_MAP_QUERY_STATUS_OK = 0,
	LTTNG_MAP_QUERY_STATUS_ERROR = -1,
	LTTNG_MAP_QUERY_STATUS_INVALID = -2,
	LTTNG_MAP_QUERY_STATUS_NONE = -3,
};

/*
 * Query the values of all CPUs or just some.
 */
enum lttng_map_query_config_cpu {
	LTTNG_MAP_QUERY_CONFIG_CPU_ALL,
	LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET,
};

/*
 * Query the values of all uid (or pid) or just some.
 */
enum lttng_map_query_config_buffer {
	LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_ALL,
	LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET,
	LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_ALL,
	LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET,
	LTTNG_MAP_QUERY_CONFIG_BUFFER_KERNEL_GLOBAL,
};

/*
 * Query the values of all bitness or just some.
 */
enum lttng_map_query_config_app_bitness {
	LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_32, /*Not supported yet*/
	LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_64, /*Not supported yet*/
	LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_ALL,
	LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_KERNEL,
};

struct lttng_map_query;

/*
 *
 */
extern struct lttng_map_query *lttng_map_query_create(
		enum lttng_map_query_config_cpu cpu,
		enum lttng_map_query_config_buffer buffer,
		enum lttng_map_query_config_app_bitness bitness);

extern enum lttng_map_query_status lttng_map_query_set_sum_by_cpu(
		struct lttng_map_query *query, bool sum_by_cpu);

extern enum lttng_map_query_status lttng_map_query_set_sum_by_pid(
		struct lttng_map_query *query, bool sum_by_pid);

extern enum lttng_map_query_status lttng_map_query_add_cpu(
		struct lttng_map_query *query, int cpu_id);

extern enum lttng_map_query_status lttng_map_query_add_uid(
		struct lttng_map_query *query, uid_t uid);

extern enum lttng_map_query_status lttng_map_query_add_pid(
		struct lttng_map_query *query, pid_t pid);

extern enum lttng_map_query_status lttng_map_query_add_key_filter(
		struct lttng_map_query *query, const char *key_filter);


#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_QUERY_H */
