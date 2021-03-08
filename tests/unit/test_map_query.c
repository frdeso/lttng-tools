/*
 * test_map_query.c
 *
 * Unit tests for the map query API.
 *
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <lttng/map/map-query-internal.h>

#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
#include <common/payload.h>

#define NUM_TESTS 56

static
void test_map_query_key_filter_all_cpus_all_uids_64_no_sum(void)
{
	int ret;
	struct lttng_payload buffer;
	struct lttng_map_query *query, *query_from_payload = NULL;
	const char *filter = "pitarifique_key";
	const char *filter_from_payload;
	enum lttng_map_query_status status;

	enum lttng_map_query_config_cpu config_cpu =
			LTTNG_MAP_QUERY_CONFIG_CPU_ALL;
	enum lttng_map_query_config_buffer config_buffer =
			LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_ALL;
	enum lttng_map_query_config_app_bitness config_bitness =
			LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_ALL;

	diag("Map query, all cpus, all uids, 64bits, no sum");
	lttng_payload_init(&buffer);

	query = lttng_map_query_create(config_cpu, config_buffer,
			config_bitness);
	ok(query, "Map query created succesfully");

	status = lttng_map_query_add_key_filter(query, filter);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Key filter created succesfully");

	/* Add a cpu manually with a _CONFIG_CPU_ALL should fail. */
	status = lttng_map_query_add_cpu(query, 121);
	ok(status == LTTNG_MAP_QUERY_STATUS_INVALID, "Adding a cpu failed as expected");

	/* Add a pid manually with a _CONFIG_BUFFER_UST_UID_ should fail. */
	status = lttng_map_query_add_pid(query, 931214);
	ok(status == LTTNG_MAP_QUERY_STATUS_INVALID, "Adding a PID of uid map query failed as expected");

	ret = lttng_map_query_serialize(query, &buffer);
	ok(ret == 0, "Map query serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);
		(void) lttng_map_query_create_from_payload(
				&view, &query_from_payload);
	}

	ok(query_from_payload, "Map query created from payload");

	ok(lttng_map_query_get_config_app_bitness(query_from_payload) ==
			config_bitness, "Getting app bitness config from payload");

	ok(lttng_map_query_get_config_buffer(query_from_payload) ==
			config_buffer, "Buffer config");

	ok(lttng_map_query_get_config_cpu(query_from_payload) ==
			config_cpu, "CPU config");

	ok(lttng_map_query_get_config_app_bitness(query_from_payload) ==
			config_bitness, "App bitness config");

	status = lttng_map_query_get_key_filter(query_from_payload, &filter_from_payload);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Key filter");
	ok(strcmp(filter_from_payload, filter) == 0, "Key filter");

	lttng_map_query_destroy(query);
	lttng_map_query_destroy(query_from_payload);
	lttng_payload_reset(&buffer);
}

static
void test_map_query_key_some_cpu_some_uid_summed_by_uid(void)
{
	int ret;
	struct lttng_payload buffer;
	struct lttng_map_query *query, *query_from_payload = NULL;
	unsigned int cpu_count, uid_count;
	bool sum_by_cpu = false, sum_by_uid = true;
	uid_t uid1 = 12131, uid1_from_payload;
	int cpu1 = 494581, cpu1_from_payload;
	enum lttng_map_query_status status;

	enum lttng_map_query_config_cpu config_cpu =
			LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET;
	enum lttng_map_query_config_buffer config_buffer =
			LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_SUBSET;
	enum lttng_map_query_config_app_bitness config_bitness =
			LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_ALL;

	diag("Map query some cpus, some uids, summed by uid");
	lttng_payload_init(&buffer);

	query = lttng_map_query_create(config_cpu, config_buffer,
			config_bitness);
	ok(query, "Map query created succesfully");

	status = lttng_map_query_set_sum_by_cpu(query, sum_by_cpu);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Setting sum-by-cpu option");

	status = lttng_map_query_set_sum_by_uid(query, sum_by_uid);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Setting sum-by-uid option");

	status = lttng_map_query_add_cpu(query, cpu1);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Adding a cpu %d", cpu1);

	status = lttng_map_query_add_uid(query, uid1);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Adding a uid %d", uid1);

	/* Add a pid manually with a _CONFIG_BUFFER_UST_UID_ should fail. */
	status = lttng_map_query_add_pid(query, 931214);
	ok(status == LTTNG_MAP_QUERY_STATUS_INVALID, "Adding a PID of uid map query failed as expected");

	ret = lttng_map_query_serialize(query, &buffer);
	ok(ret == 0, "Map query serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);
		(void) lttng_map_query_create_from_payload(
				&view, &query_from_payload);
	}

	ok(query_from_payload, "Map query created from payload");

	ok(lttng_map_query_get_config_app_bitness(query_from_payload) ==
			config_bitness, "Getting app bitness config from payload");

	ok(lttng_map_query_get_config_sum_by_cpu(query_from_payload) ==
			sum_by_cpu, "Getting sum-by-cpu config from payload");

	ok(lttng_map_query_get_config_sum_by_uid(query_from_payload) ==
			sum_by_uid, "Getting sum-by-uid config from payload");

	ok(lttng_map_query_get_config_buffer(query_from_payload) ==
			config_buffer, "Buffer config");

	ok(lttng_map_query_get_config_cpu(query_from_payload) ==
			config_cpu, "CPU config");

	ok(lttng_map_query_get_config_app_bitness(query_from_payload) ==
			config_bitness, "App bitness config");

	status = lttng_map_query_get_cpu_count(query, &cpu_count);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Getting cpu count");
	ok(cpu_count == 1, "Getting cpu count");

	status = lttng_map_query_get_cpu_at_index(query, 0, &cpu1_from_payload);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Getting cpu count");
	ok(cpu1_from_payload == cpu1, "Getting cpu value");

	status = lttng_map_query_get_uid_count(query, &uid_count);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Getting uid count");
	ok(uid_count == 1, "Getting uid count");

	status = lttng_map_query_get_uid_at_index(query, 0, &uid1_from_payload);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Getting uid count");
	ok(uid1_from_payload == uid1, "Getting uid value");

	lttng_map_query_destroy(query);
	lttng_map_query_destroy(query_from_payload);
	lttng_payload_reset(&buffer);
}

static
void test_map_query_key_one_cpu_some_pid_summed_by_cpu(void)
{
	int ret;
	struct lttng_payload buffer;
	struct lttng_map_query *query, *query_from_payload = NULL;
	unsigned int cpu_count, pid_count;
	pid_t pid1 = 12131, pid1_from_payload;
	int cpu1 = 494581, cpu1_from_payload;
	bool sum_by_cpu = true, sum_by_pid = false;
	enum lttng_map_query_status status;

	enum lttng_map_query_config_cpu config_cpu =
			LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET;
	enum lttng_map_query_config_buffer config_buffer =
			LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_PID_SUBSET;
	enum lttng_map_query_config_app_bitness config_bitness =
			LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_ALL;

	diag("Map query one cpu, some pid, summed by cpu");
	lttng_payload_init(&buffer);

	query = lttng_map_query_create(config_cpu, config_buffer,
			config_bitness);
	ok(query, "Map query created succesfully");

	status = lttng_map_query_set_sum_by_cpu(query, sum_by_cpu);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Setting sum-by-cpu option");

	status = lttng_map_query_set_sum_by_pid(query, sum_by_pid);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Setting sum-by-pid option");

	status = lttng_map_query_add_cpu(query, cpu1);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Adding a cpu %d", cpu1);

	status = lttng_map_query_add_pid(query, pid1);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Adding a pid %d", pid1);

	/* Add a pid manually with a _CONFIG_BUFFER_UST_PID_ should fail. */
	status = lttng_map_query_add_uid(query, 931214);
	ok(status == LTTNG_MAP_QUERY_STATUS_INVALID, "Adding a UID of pid map query failed as expected");

	ret = lttng_map_query_serialize(query, &buffer);
	ok(ret == 0, "Map query serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);
		(void) lttng_map_query_create_from_payload(
				&view, &query_from_payload);
	}

	ok(query_from_payload, "Map query created from payload");

	ok(lttng_map_query_get_config_app_bitness(query_from_payload) ==
			config_bitness, "Getting app bitness config from payload");

	ok(lttng_map_query_get_config_sum_by_cpu(query_from_payload) ==
			sum_by_cpu, "Getting sum-by-cpu config from payload");

	ok(lttng_map_query_get_config_sum_by_pid(query_from_payload) ==
			sum_by_pid, "Getting sum-by-pid config from payload");

	ok(lttng_map_query_get_config_buffer(query_from_payload) ==
			config_buffer, "Getting buffer config from payload");

	ok(lttng_map_query_get_config_cpu(query_from_payload) ==
			config_cpu, "Getting CPU config from payload");

	ok(lttng_map_query_get_config_app_bitness(query_from_payload) ==
			config_bitness, "App bitness config from payload");

	status = lttng_map_query_get_cpu_count(query, &cpu_count);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Getting cpu count from payload");
	ok(cpu_count == 1, "Getting cpu count from payload");

	status = lttng_map_query_get_cpu_at_index(query, 0, &cpu1_from_payload);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Getting cpu count from payload");
	ok(cpu1_from_payload == cpu1, "Getting cpu value from payload");

	status = lttng_map_query_get_pid_count(query, &pid_count);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Getting pid count from payload");
	ok(pid_count == 1, "Getting pid count from payload");

	status = lttng_map_query_get_pid_at_index(query, 0, &pid1_from_payload);
	ok(status == LTTNG_MAP_QUERY_STATUS_OK, "Getting pid count from payload");
	ok(pid1_from_payload == pid1, "Getting pid value from payload");

	lttng_map_query_destroy(query);
	lttng_map_query_destroy(query_from_payload);
	lttng_payload_reset(&buffer);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);

	test_map_query_key_filter_all_cpus_all_uids_64_no_sum();
	test_map_query_key_some_cpu_some_uid_summed_by_uid();
	test_map_query_key_one_cpu_some_pid_summed_by_cpu();

	return exit_status();
}
