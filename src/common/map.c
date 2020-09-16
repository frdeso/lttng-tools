/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <string.h>

#include <common/macros.h>
#include <lttng/map/map-internal.h>

enum lttng_map_status lttng_map_set_name(struct lttng_map *map,
		const char *name)
{
	char *name_copy = NULL;
	enum lttng_map_status status;

	if (!map || !name || strlen(name) == 0) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	name_copy = strdup(name);
	if (!name_copy) {
		status = LTTNG_MAP_STATUS_ERROR;
		goto end;
	}

	free(map->name);

	map->name = name_copy;
	name_copy = NULL;

	status = LTTNG_MAP_STATUS_OK;
end:
	return status;
}

enum lttng_map_status lttng_map_get_name(const struct lttng_map *map,
		const char **name)
{
	enum lttng_map_status status;

	if (!map || !name) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	if (!map->name) {
		status = LTTNG_MAP_STATUS_UNSET;
	}

	*name = map->name;
	status = LTTNG_MAP_STATUS_OK;
end:
	return status;
}

enum lttng_map_status lttng_map_create(const char *name,
		unsigned int dimension_count,
		uint64_t *dimension_sizes,
		enum lttng_domain_type domain,
		enum lttng_buffer_type buffer_type,
		enum lttng_map_bitness bitness,
		enum lttng_map_boundary_policy boundary_policy,
		struct lttng_map **map_out)
{
	enum lttng_map_status status;
	struct lttng_map *map;

	if (dimension_count != 1) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	map = zmalloc(sizeof(struct lttng_map));
	if (!map) {
		status = LTTNG_MAP_STATUS_ERROR;
		goto end;
	}

	if (name) {
		status = lttng_map_set_name(map, name);
		if (status != LTTNG_MAP_STATUS_OK) {
			goto free_map;
		}
	} else {
		map->name = NULL;
	}

	map->dimension_count = dimension_count;
	map->dimension_sizes = zmalloc(sizeof(*map->dimension_sizes) * dimension_count);
	if (!map->dimension_sizes) {
		status = LTTNG_MAP_STATUS_ERROR;
		goto free_name;
	}

	map->domain = domain;
	map->buffer_type = buffer_type;
	map->bitness = bitness;
	map->boundary_policy = boundary_policy;


	*map_out = map;
	status = LTTNG_MAP_STATUS_OK;

	goto end;
free_name:
	free(map->name);
free_map:
	free(map);
end:
	return status;
}

unsigned int lttng_map_get_dimension_count(
		const struct lttng_map *map)
{
	return map->dimension_count;
}

enum lttng_map_status lttng_map_get_dimension_length(
		const struct lttng_map *map, unsigned int dimension,
		uint64_t *dimension_length)
{
	enum lttng_map_status status;

	if (dimension >= map->dimension_count) {
		status = LTTNG_MAP_STATUS_INVALID;
		goto end;
	}

	*dimension_length = map->dimension_sizes[dimension];

	status = LTTNG_MAP_STATUS_OK;
end:
	return status;
}

enum lttng_map_bitness lttng_map_get_bitness(
		const struct lttng_map *map)
{
	return map->bitness;
}

enum lttng_domain_type lttng_map_get_domain(
		const struct lttng_map *map)
{
	return map->domain;
}

enum lttng_buffer_type lttng_map_get_buffer_type(
		const struct lttng_map *map)
{
	return map->buffer_type;
}

enum lttng_map_boundary_policy lttng_map_get_boundary_policy(
		const struct lttng_map *map)
{
	return map->boundary_policy;
}

void lttng_map_destroy(struct lttng_map *map)
{
	free(map->dimension_sizes);
	free(map->name);
	free(map);
}
