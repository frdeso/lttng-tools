/*
 * test_map.c
 *
 * Unit tests for the map API.
 *
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng/domain.h"
#include "lttng/map/map.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <lttng/map/map-internal.h>

#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
#include <common/payload.h>

#define NUM_TESTS 69

static
void test_map_key_value_pair_serialize_deserialize(void)
{
	struct lttng_map_key_value_pair *kv;
	struct lttng_map_key_value_pair *kv_from_payload;
	struct lttng_payload buffer;
	enum lttng_map_status map_status;
	const char *kv_from_payload_key, *key = "ma_clé";
	int64_t kv_from_payload_value, value = 133121;
	int ret;

	diag("Simple lttng_map_key_value_pair tests");

	lttng_payload_init(&buffer);

	kv = lttng_map_key_value_pair_create(key, value);
	ok(kv, "Key-value pair created");

	/* Test incr value action serialization */
	ret = lttng_map_key_value_pair_serialize(kv, &buffer);
	ok(ret == 0, "Key-value pair serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);

		(void) lttng_map_key_value_pair_create_from_payload(
				&view, &kv_from_payload);
	}
	ok(kv_from_payload, "Key-value pair created from payload is non-null");

	map_status = lttng_map_key_value_pair_get_key(kv_from_payload,
			&kv_from_payload_key);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Key-value pair 1 key");
	ok(strcmp(kv_from_payload_key, key) == 0, "Key-value pair from payload has correct key");

	map_status = lttng_map_key_value_pair_get_value(kv_from_payload,
			&kv_from_payload_value);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Key-value pair 1 value");
	ok(kv_from_payload_value == value, "Key-value pair from payload has correct value");

	lttng_payload_reset(&buffer);
	lttng_map_key_value_pair_destroy(kv);
	lttng_map_key_value_pair_destroy(kv_from_payload);
}

static
void test_map_key_value_pair_list_serialize_deserialize(void)
{
	struct lttng_map_key_value_pair *kv;
	const struct lttng_map_key_value_pair *kv_from_payload = NULL;

	struct lttng_map_key_value_pair_list *kv_pair_list;
	struct lttng_map_key_value_pair_list *kv_pair_list_from_payload;

	struct lttng_payload buffer;
	enum lttng_map_status map_status;
	const char *kv_from_payload_key, *key1 = "ma_clé", *key2 = "autre_clé";
	int64_t kv_from_payload_value, value1 = 123456, value2 = 98765;
	enum lttng_map_key_value_pair_list_type list_type =
			LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID;
	uint64_t identifier = 3192112;
	unsigned int kv_count;
	int ret;

	diag("Simple lttng_map_key_value_pair_list tests");

	lttng_payload_init(&buffer);

	kv_pair_list = lttng_map_key_value_pair_list_create(list_type);
	ok(kv_pair_list, "Key-value pair_list list created");

	map_status = lttng_map_key_value_pair_list_set_identifier(kv_pair_list, 
			identifier);
	ok(kv_pair_list, "Key-value set identifier");

	kv = lttng_map_key_value_pair_create(key1, value1);
	ok(kv, "Key-value pair 1 created");

	map_status = lttng_map_key_value_pair_list_append_key_value(kv_pair_list, kv);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Key value 1 appended to list");

	kv = lttng_map_key_value_pair_create(key2, value2);
	ok(kv, "Key-value pair 2 created");

	map_status = lttng_map_key_value_pair_list_append_key_value(kv_pair_list, kv);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Key value 2 appended to list");

	/* Test incr value action serialization */
	ret = lttng_map_key_value_pair_list_serialize(kv_pair_list, &buffer);
	ok(ret == 0, "Key-value pair_list list serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);

		(void) lttng_map_key_value_pair_list_create_from_payload(
				&view, &kv_pair_list_from_payload);
	}
	ok(kv_pair_list_from_payload, "Key-value pair list created from payload is non-null");

	ok(lttng_map_key_value_pair_list_get_type(kv_pair_list_from_payload) == list_type,
			"Got the expected list type");
	ok(lttng_map_key_value_pair_list_get_identifer(kv_pair_list_from_payload) == identifier,
			"Got the expected list identifier");

	map_status = lttng_map_key_value_pair_list_get_count(
			kv_pair_list_from_payload, &kv_count);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Got key value pair count");
	ok(kv_count == 2, "Got the right key value pair count");

	kv_from_payload = lttng_map_key_value_pair_list_get_at_index(
			kv_pair_list_from_payload, 0);
	ok(kv_from_payload, "Key-value pair 1 created from payload");

	map_status = lttng_map_key_value_pair_get_key(kv_from_payload,
			&kv_from_payload_key);
	ok(strcmp(kv_from_payload_key, key1) == 0, "Key-value pair 1 from payload has correct key");

	map_status = lttng_map_key_value_pair_get_value(kv_from_payload,
			&kv_from_payload_value);
	ok(kv_from_payload_value == value1, "Key-value pair 1 from payload has correct value");

	kv_from_payload = lttng_map_key_value_pair_list_get_at_index(
			kv_pair_list_from_payload, 1);
	ok(kv_from_payload, "Key-value pair 2 created from payload");

	map_status = lttng_map_key_value_pair_get_key(kv_from_payload,
			&kv_from_payload_key);
	ok(strcmp(kv_from_payload_key, key2) == 0, "Key-value pair 2 from payload has correct key");

	map_status = lttng_map_key_value_pair_get_value(kv_from_payload,
			&kv_from_payload_value);
	ok(kv_from_payload_value == value2, "Key-value pair 2 from payload has correct value");

	lttng_payload_reset(&buffer);
	lttng_map_key_value_pair_list_destroy(kv_pair_list);
	lttng_map_key_value_pair_list_destroy(kv_pair_list_from_payload);
}

static
void test_map_content_serialize_deserialize(void)
{
	struct lttng_map_content *map_content, *map_content_from_payload;
	enum lttng_map_status map_status;
	struct lttng_payload buffer;
	struct lttng_map_key_value_pair *kv1, *kv2;
	const char *key1 = "ma_clé", *key2 = "autre_clé";
	uint64_t value1 = 123456, value2 = 98765;
	enum lttng_map_key_value_pair_list_type list_type1 =
			LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID;
	enum lttng_map_key_value_pair_list_type list_type2 =
			LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID;
	enum lttng_map_key_value_pair_list_type list_type3 =
			LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID_AGGREGATED;
	uint64_t id1 = 958323, id2 = 121942;
	struct lttng_map_key_value_pair_list *kv_pair_list1, *kv_pair_list2, *kv_pair_list3;
	const struct lttng_map_key_value_pair_list *kv_pair_list1_from_payload;
	const struct lttng_map_key_value_pair_list *kv_pair_list2_from_payload;
	const struct lttng_map_key_value_pair_list *kv_pair_list3_from_payload;
	unsigned int list_count;
	enum lttng_buffer_type buffer_type = LTTNG_BUFFER_PER_UID;
	int ret;

	diag("Simple lttng_map_content tests");

	lttng_payload_init(&buffer);

	kv_pair_list1 = lttng_map_key_value_pair_list_create(list_type1);
	map_status = lttng_map_key_value_pair_list_set_identifier(kv_pair_list1, id1);

	kv_pair_list2 = lttng_map_key_value_pair_list_create(list_type2);
	map_status = lttng_map_key_value_pair_list_set_identifier(kv_pair_list2, id2);

	kv_pair_list3 = lttng_map_key_value_pair_list_create(list_type3);

	kv1 = lttng_map_key_value_pair_create(key1, value1);
	map_status = lttng_map_key_value_pair_list_append_key_value(kv_pair_list1, kv1);

	kv2 = lttng_map_key_value_pair_create(key2, value2);
	map_status = lttng_map_key_value_pair_list_append_key_value(kv_pair_list2, kv2);

	map_content = lttng_map_content_create(buffer_type);

	map_status = lttng_map_content_append_key_value_list(map_content, kv_pair_list1);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Key value list 1 appended to map_content");

	map_status = lttng_map_content_append_key_value_list(map_content, kv_pair_list2);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Key value list 2 appended to map_content");

	map_status = lttng_map_content_append_key_value_list(map_content, kv_pair_list3);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Key value list 3 appended to map_content");

	ret = lttng_map_content_serialize(map_content, &buffer);
	ok(ret == 0, "Map list serialized");
	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);
		(void) lttng_map_content_create_from_payload(
				&view, &map_content_from_payload);
	}

	ok(map_content, "map content created from payload is non-null");
	map_status = lttng_map_content_get_count(map_content_from_payload, &list_count);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Got key value pair count");
	ok(list_count == 3, "Got the expected key-value list count");

	ok(lttng_map_content_get_buffer_type(map_content_from_payload) == buffer_type,
		"Got the expected buffer type");

	kv_pair_list1_from_payload = lttng_map_content_get_at_index(map_content_from_payload, 0);
	ok(kv_pair_list1_from_payload, "Key-value pair list created from payload is non-null");

	ok(lttng_map_key_value_pair_list_get_type(kv_pair_list1_from_payload) == list_type1,
			"Got the expected list type");

	ok(lttng_map_key_value_pair_list_get_identifer(kv_pair_list1_from_payload) == id1,
			"Got the expected list identifier");

	kv_pair_list2_from_payload = lttng_map_content_get_at_index(map_content_from_payload, 1);
	ok(kv_pair_list2_from_payload, "Key-value pair list created from payload is non-null");

	ok(lttng_map_key_value_pair_list_get_type(kv_pair_list2_from_payload) == list_type2,
			"Got the expected list type");

	ok(lttng_map_key_value_pair_list_get_identifer(kv_pair_list2_from_payload) == id2,
			"Got the expected list identifier");

	kv_pair_list3_from_payload = lttng_map_content_get_at_index(map_content_from_payload, 2);
	ok(kv_pair_list3_from_payload, "Key-value pair list created from payload is non-null");

	ok(lttng_map_key_value_pair_list_get_type(kv_pair_list3_from_payload) == list_type3,
			"Got the expected list type");

	lttng_payload_reset(&buffer);
	lttng_map_content_destroy(map_content);
	lttng_map_content_destroy(map_content_from_payload);
}

static
void test_map(void)
{
	int ret;
	struct lttng_payload buffer;
	struct lttng_map *map, *map_from_payload = NULL;
	enum lttng_map_status map_status;
	const char *map_name = "map_name", *map_name_from_payload;
	unsigned int dimension_count = 1;
	uint64_t first_dim_size = 423;
	uint64_t dimension_sizes[1] = {first_dim_size};
	enum lttng_domain_type domain = LTTNG_DOMAIN_UST;
	enum lttng_buffer_type buffer_type = LTTNG_BUFFER_PER_UID;
	enum lttng_map_bitness bitness = LTTNG_MAP_BITNESS_32BITS;
	enum lttng_map_boundary_policy boundary_policy = LTTNG_MAP_BOUNDARY_POLICY_OVERFLOW;
	bool coalesce_hits = true;


	diag("Simple lttng_map tests");
	lttng_payload_init(&buffer);

	map_status = lttng_map_create(map_name, dimension_count,
			dimension_sizes, domain, buffer_type, bitness,
			boundary_policy, coalesce_hits, &map);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Created map");

	lttng_map_set_is_enabled(map, true);

	ret = lttng_map_serialize(map, &buffer);
	ok(ret == 0, "Map serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);
		(void) lttng_map_create_from_payload(
				&view, &map_from_payload);
	}
	ok(map_from_payload, "Map created from payload");

	ok(lttng_map_get_dimension_count(map_from_payload) == dimension_count,
			"Got the expected dimension count from payload");

	ok(lttng_map_get_is_enabled(map_from_payload) == 1,
			"Got the expected enabled state from payload");

	ok(lttng_map_get_bitness(map_from_payload) == bitness,
			"Got the expected bitness from payload");

	ok(lttng_map_get_domain(map_from_payload) == domain,
			"Got the expected domain from payload");

	ok(lttng_map_get_buffer_type(map_from_payload) == buffer_type,
			"Got the expected buffer type from payload");

	ok(lttng_map_get_boundary_policy(map_from_payload) == boundary_policy,
			"Got the expected boundary policy from payload");

	ok(lttng_map_get_coalesce_hits(map_from_payload) == coalesce_hits,
			"Got the expected coalesce hits value from payload");

	map_status = lttng_map_get_name(map_from_payload, &map_name_from_payload);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Got map name from payload");
	ok(strcmp(map_name_from_payload, map_name) == 0,
			"Got the expected map name from payload");

	lttng_map_destroy(map);
	lttng_map_destroy(map_from_payload);
	lttng_payload_reset(&buffer);
}

static
void test_map_list(void)
{
	int ret;
	struct lttng_payload buffer;
	enum lttng_map_status map_status;
	struct lttng_map *map1, *map2;
	const struct lttng_map *map1_from_payload = NULL, *map2_from_payload = NULL;
	struct lttng_map_list *map_list, *map_list_from_payload = NULL;
	const char *map1_name = "map_name_1", *map1_name_from_payload;
	const char *map2_name = "map_name_2", *map2_name_from_payload;
	unsigned int dimension_count = 1, map_count = 0;
	uint64_t first_dim_size = 423;
	uint64_t dimension_sizes[1] = {first_dim_size};
	enum lttng_domain_type domain = LTTNG_DOMAIN_KERNEL;
	enum lttng_buffer_type buffer_type1 = LTTNG_BUFFER_PER_PID, buffer_type2 = LTTNG_BUFFER_PER_UID;
	enum lttng_map_bitness bitness = LTTNG_MAP_BITNESS_64BITS;
	enum lttng_map_boundary_policy boundary_policy = LTTNG_MAP_BOUNDARY_POLICY_OVERFLOW;
	bool coalesce_hits = false;

	diag("Simple lttng_map_list tests");

	lttng_payload_init(&buffer);

	map_status = lttng_map_create(map1_name, dimension_count,
			dimension_sizes, domain, buffer_type1, bitness,
			boundary_policy, coalesce_hits, &map1);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Created map 1");
	lttng_map_set_is_enabled(map1, true);

	map_status = lttng_map_create(map2_name, dimension_count,
			dimension_sizes, domain, buffer_type2, bitness,
			boundary_policy, coalesce_hits, &map2);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Created map 2");
	lttng_map_set_is_enabled(map2, true);

	map_list = lttng_map_list_create();
	ok(map_list, "Map list created");

	map_status = lttng_map_list_add(map_list, map1);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Map 1 added to map list");

	map_status = lttng_map_list_add(map_list, map2);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Map 1 added to map list");

	ret = lttng_map_list_serialize(map_list, &buffer);
	ok(ret == 0, "Map list serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);
		(void) lttng_map_list_create_from_payload(
				&view, &map_list_from_payload);
	}

	map_status = lttng_map_list_get_count(map_list, &map_count);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Got map count from payload");
	ok(map_count == 2, "Got the right map count from payload");

	map1_from_payload = lttng_map_list_get_at_index(map_list, 0);
	ok(map1_from_payload, "Got first map from payload");
	map_status = lttng_map_get_name(map1_from_payload, &map1_name_from_payload);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Got map 1 name from payload");
	ok(strcmp(map1_name_from_payload, map1_name) == 0,
			"Got right map 1 name from payload");
	ok(lttng_map_get_is_enabled(map1_from_payload) == 1,
			"Got right map 1 enabled state from payload");

	map2_from_payload = lttng_map_list_get_at_index(map_list, 1);
	ok(map2_from_payload, "Got first map from payload");
	map_status = lttng_map_get_name(map2_from_payload, &map2_name_from_payload);
	ok(map_status == LTTNG_MAP_STATUS_OK, "Got map 2 name from payload");
	ok(strcmp(map2_name_from_payload, map2_name) == 0,
			"Got right map 2 name from payload");
	ok(lttng_map_get_is_enabled(map2_from_payload) == 1,
			"Got right map 2 enabled state from payload");

	lttng_map_destroy(map1);
	lttng_map_destroy(map2);
	lttng_map_list_destroy(map_list);
	lttng_map_list_destroy(map_list_from_payload);
	lttng_payload_reset(&buffer);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);

	test_map();
	test_map_list();
	test_map_key_value_pair_serialize_deserialize();
	test_map_key_value_pair_list_serialize_deserialize();
	test_map_content_serialize_deserialize();

	return exit_status();
}
