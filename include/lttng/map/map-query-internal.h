/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_QUERY_INTERNAL_H
#define LTTNG_MAP_QUERY_INTERNAL_H

#include <stdint.h>

#include <common/payload.h>
#include <common/payload-view.h>

#include <lttng/lttng.h>
#include <lttng/map/map-query.h>

struct lttng_map_query {
	enum lttng_map_query_config_cpu config_cpu;
	enum lttng_map_query_config_buffer config_buffer;
	enum lttng_map_query_config_app_bitness config_bitness;

	/*
 	 * Aggregate the values of all selected CPUs in a single table.
 	 */
	bool sum_by_cpu;

	/*
 	 * Aggregate the values of all selected bitness in a single table.
 	 */
	bool sum_by_app_bitness;

	/*
 	 * Aggregate the values of all selected uid or pid in a single table.
 	 */
	bool sum_by_uid;
	bool sum_by_pid;

	char *key_filter;
	struct lttng_dynamic_array cpu_array;
	struct lttng_dynamic_array uid_array;
	struct lttng_dynamic_array pid_array;
};

struct lttng_map_query_comm {
	uint32_t key_filter_length; /* Include '\0' */

	uint8_t config_cpu;
	uint8_t config_buffer;
	uint8_t config_app_bitness;

	uint8_t sum_by_cpu;
	uint8_t sum_by_app_bitness;
	uint8_t sum_by_uid;
	uint8_t sum_by_pid;

	uint32_t cpu_count;
	uint32_t uid_count;
	uint32_t pid_count;
	/*
	 * key_filter +
	 * (cpu_count * int) + (uid_count * uid_t) + (pid_count * pid_t)
	 */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
enum lttng_map_query_config_cpu lttng_map_query_get_config_cpu(
		const struct lttng_map_query *query);

LTTNG_HIDDEN
enum lttng_map_query_config_buffer lttng_map_query_get_config_buffer(
		const struct lttng_map_query *query);

LTTNG_HIDDEN
enum lttng_map_query_config_app_bitness lttng_map_query_get_config_app_bitness(
		const struct lttng_map_query *query);

LTTNG_HIDDEN
bool lttng_map_query_get_config_sum_by_cpu(
		const struct lttng_map_query *query);

LTTNG_HIDDEN
bool lttng_map_query_get_config_sum_by_pid(
		const struct lttng_map_query *query);

LTTNG_HIDDEN
bool lttng_map_query_get_config_sum_by_uid(
		const struct lttng_map_query *query);

// Not supported yet.
LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_set_sum_by_app_bitness(
 		struct lttng_map_query *query, bool sum_by_app_bitness);

// Not supported yet.
LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_set_sum_by_uid(
		struct lttng_map_query *query, bool sum_by_uid);

LTTNG_HIDDEN
bool lttng_map_query_get_config_sum_by_app_bitness(
		const struct lttng_map_query *query);

LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_get_cpu_count(
		const struct lttng_map_query *query, unsigned int *count);

LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_get_uid_count(
		const struct lttng_map_query *query, unsigned int *count);

LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_get_pid_count(
		const struct lttng_map_query *query, unsigned int *count);

LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_get_cpu_at_index(
		const struct lttng_map_query *query, unsigned int index,
		int *cpu);

LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_get_uid_at_index(
		const struct lttng_map_query *query, unsigned int index,
		uid_t *uid);

LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_get_pid_at_index(
		const struct lttng_map_query *query, unsigned int index,
		pid_t *pid);

LTTNG_HIDDEN
enum lttng_map_query_status lttng_map_query_get_key_filter(
		const struct lttng_map_query *query, const char **key_filter);

LTTNG_HIDDEN
ssize_t lttng_map_query_create_from_payload(struct lttng_payload_view *view,
		struct lttng_map_query **query);

LTTNG_HIDDEN
int lttng_map_query_serialize(const struct lttng_map_query *query,
		struct lttng_payload *payload);

LTTNG_HIDDEN
void lttng_map_query_destroy(struct lttng_map_query *query);

#endif /* LTTNG_MAP_QUERY_INTERNAL_H */
