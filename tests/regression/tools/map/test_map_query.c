#include <stdio.h>
#include <stdint.h>

#include <lttng/lttng.h>
#include <lttng/handle.h>
#include <lttng/map.h>
#include <lttng/map-query.h>

int main() {
	int ret;
	enum lttng_map_query_status query_status;
	enum lttng_error_code ret_code;
	unsigned int map_count, list_count;
	enum lttng_map_status map_status;
	struct lttng_map_content *map_content = NULL;
	struct lttng_map_list *map_list = NULL;
	const struct lttng_map *map = NULL;
	struct lttng_domain *domains = NULL;
	const struct lttng_map_key_value_pair_list *kv_list;
	const struct lttng_map_key_value_pair *kv_pair;
	const char *key;
	int64_t value;
	int nb_domains;


	nb_domains = lttng_list_domains("mysession", &domains);

	struct lttng_handle *handle = lttng_create_handle("mysession", &domains[0]);

	struct lttng_map_query *map_query = lttng_map_query_create(
			LTTNG_MAP_QUERY_CONFIG_CPU_SUBSET,
			LTTNG_MAP_QUERY_CONFIG_BUFFER_UST_UID_ALL,
			LTTNG_MAP_QUERY_CONFIG_APP_BITNESS_ALL);

	if (!map_query) {
		printf("Error creating the map query\n");
		ret = -1;
		goto end;
	}

	query_status = lttng_map_query_add_cpu(map_query, 0);
	if (query_status != LTTNG_MAP_QUERY_STATUS_OK) {
		printf("Error setting the targeted cpu\n");
		ret = -1;
		goto end;
	}

	query_status = lttng_map_query_add_key_filter(map_query,
			"total number of hits");
	if (query_status != LTTNG_MAP_QUERY_STATUS_OK) {
		printf("Error setting the targeted key\n");
		ret = -1;
		goto end;
	}

	ret_code = lttng_list_maps(handle, &map_list);
	if (ret_code != LTTNG_OK) {
		printf("Error getting list of all maps\n");
		ret = -1;
		goto end;
	}

	map_status = lttng_map_list_get_count(map_list, &map_count);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		printf("Error getting the number of maps\n");
		ret = -1;
		goto end;
	}

	if (map_count < 1) {
		printf("Error: expecting at least 1 map.\n");
		ret = -1;
		goto end;
	}

	map = lttng_map_list_get_at_index(map_list, 0);
	if (!map) {
		printf("Error getting map at index 0\n");
		ret = -1;
		goto end;
	}

	ret_code = lttng_list_map_content(handle, map, map_query, &map_content);
	if (ret_code != LTTNG_OK) {
		printf("Error executing the query on map\n");
		ret = -1;
		goto end;
	}

	map_status = lttng_map_content_get_count(map_content, &list_count);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		printf("Error getting the number of key value pair list\n");
		ret = -1;
		goto end;
	}

	if (list_count < 1) {
		printf("Error: expecting at least 1 list.\n");
		ret = -1;
		goto end;
	}

	kv_list = lttng_map_content_get_at_index(map_content, 0);
	if (!kv_list) {
		printf("Error getting key value pair list at index 0\n");
		ret = -1;
		goto end;
	}

	kv_pair = lttng_map_key_value_pair_list_get_at_index(kv_list, 0);
	if (!kv_pair) {
		printf("Error getting key value pair at index 0\n");
		ret = -1;
		goto end;
	}

	lttng_map_key_value_pair_get_key(kv_pair, &key);
	lttng_map_key_value_pair_get_value(kv_pair, &value);

	printf("Key: \"%s\", value: %"PRId64"\n", key, value);

	ret = 0;
end:
	return ret;
}
