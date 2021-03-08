/*
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <lttng/lttng.h>
#include <lttng/handle.h>
#include <lttng/map.h>
#include <lttng/map-query.h>

#define LOG(fmt, ...) printf("# " fmt "\n", ##__VA_ARGS__);
#define ERR(fmt, ...) fprintf(stderr, "Error: " fmt "\n", ##__VA_ARGS__);

int main(int argc, char *argv[]) {
        enum lttng_map_query_status query_status;
        enum lttng_error_code ret_code;
        enum lttng_map_status map_status;
        struct lttng_domain *domains = NULL;
        struct lttng_map_content *map_content = NULL;
        struct lttng_map_list *map_list = NULL;
        const struct lttng_map *map = NULL;
        const struct lttng_map_key_value_pair_list *kv_list;
        const struct lttng_map_key_value_pair *kv_pair;
        unsigned int map_idx, map_count, list_idx, list_count;
        int ret, nb_domains;
        struct lttng_map_query *map_query = NULL;
        struct lttng_handle *handle = NULL;
        int64_t value;
        const char *session_name, *map_name, *key, *wanted_key = NULL;

        if (argc < 3) {
        	ERR("Missing argument(s)");
        	ERR("Usage: %s SESSION-NAME MAP-NAME [KEY]", argv[0]);
        	ret = -1;
        	goto end;
        }

	session_name = argv[1];
	map_name = argv[2];
	if (argc > 3) {
		wanted_key = argv[3];
	}

        nb_domains = lttng_list_domains(session_name, &domains);
        if (nb_domains < 0) {
        	ret = -1;
        	goto end;
        }

        handle = lttng_create_handle(session_name, &domains[0]);
        if (!handle) {
        	ret = -1;
        	goto end;
        }

	LOG("Listing all maps of the \"%s\" session", session_name);

        ret_code = lttng_list_maps(handle, &map_list);
        if (ret_code != LTTNG_OK) {
                ERR("Getting list of all maps");
                ret = -1;
                goto end;
        }

        map_status = lttng_map_list_get_count(map_list, &map_count);
        if (map_status != LTTNG_MAP_STATUS_OK) {
                ERR("Getting the number of maps");
                ret = -1;
                goto end;
        }

	for (map_idx = 0; map_idx < map_count; map_idx++) {
		const char *curr_map_name;
		const struct lttng_map *curr_map;
        	curr_map = lttng_map_list_get_at_index(map_list, map_idx);
        	if (!curr_map) {
                	ERR("Getting map at index %u", map_idx);
                	ret = -1;
                	goto end;
        	}


		map_status = lttng_map_get_name(curr_map, &curr_map_name);
        	if (map_status != LTTNG_MAP_STATUS_OK) {
                	ERR("Getting the map #%u name", map_idx);
                	ret = -1;
                	goto end;
        	}

		if (strcmp(curr_map_name, map_name) == 0) {
			LOG("Found \"%s\" map", map_name);
			map = curr_map;
			break;
		}
	}
	if (!map) {
		ERR("Can't find map \"%s\" in \"%s\" session", map_name, session_name);
                ret = -1;
                goto end;
	}

	LOG("Creating a map query_object");
        map_query = lttng_map_query_create(LTTNG_MAP_QUERY_CONFIG_CPU_ALL,
                        LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_ALL,
                        LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_ALL);
        if (!map_query) {
		ERR("Creating the map query object");
                ret = -1;
                goto end;
        }

	LOG("Query option: report values for each CPU individually");
        query_status = lttng_map_query_set_sum_by_cpu(map_query, false);
        if (query_status != LTTNG_MAP_QUERY_STATUS_OK){
		ERR("Setting the sum by option");
		ret = -1;
		goto end;
        }

	if (wanted_key) {
		LOG("Query option: filter in only \"%s\" key", wanted_key);
        	query_status = lttng_map_query_add_key_filter(map_query,
                        	wanted_key);
        	if (query_status != LTTNG_MAP_QUERY_STATUS_OK) {
                	ERR("Setting the targeted key");
                	ret = -1;
                	goto end;
        	}
        }

	LOG("Execute query against the \"%s\" map", map_name);
        ret_code = lttng_list_map_content(handle, map, map_query, &map_content);
        if (ret_code != LTTNG_OK) {
                ERR("Executing the query on map");
                ret = -1;
                goto end;
        }

        map_status = lttng_map_content_get_count(map_content, &list_count);
        if (map_status != LTTNG_MAP_STATUS_OK) {
                ERR("Getting the number of key value pair list");
                ret = -1;
                goto end;
        }

	LOG("Printing query result:");
	for (list_idx = 0; list_idx < list_count; list_idx++) {
		unsigned int kv_pair_idx, kv_pair_count;
		uint64_t cpu;

        	kv_list = lttng_map_content_get_at_index(map_content, list_idx);
        	if (!kv_list) {
                	ERR("Getting key value pair list at index 0");
                	ret = -1;
                	goto end;
        	}

		cpu = lttng_map_key_value_pair_list_get_cpu(kv_list);

		LOG("=== CPU: %"PRIu64" ===", cpu);

        	map_status = lttng_map_key_value_pair_list_get_count(kv_list,
        			&kv_pair_count);

		for (kv_pair_idx = 0; kv_pair_idx < kv_pair_count; kv_pair_idx++) {
        		kv_pair = lttng_map_key_value_pair_list_get_at_index(
					kv_list, kv_pair_idx);
        		if (!kv_pair) {
                		ERR("Getting key value pair at index %u",
						kv_pair_idx);
                		ret = -1;
                		goto end;
        		}
        		lttng_map_key_value_pair_get_key(kv_pair, &key);
        		lttng_map_key_value_pair_get_value(kv_pair, &value);

        		LOG("Key: \"%s\", value: %"PRId64, key, value);
        	}
		LOG();
	}

        ret = 0;
end:
	lttng_map_query_destroy(map_query);
	lttng_destroy_handle(handle);
	lttng_map_content_destroy(map_content);
	lttng_map_list_destroy(map_list);
        return ret;
}
