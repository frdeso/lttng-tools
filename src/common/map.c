/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <string.h>

#include <common/macros.h>
#include <common/payload.h>

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

LTTNG_HIDDEN
int lttng_map_serialize(const struct lttng_map *map,
		struct lttng_payload *payload)
{
	int ret;
	size_t header_offset, size_before_payload, size_name;
	struct lttng_map_comm map_comm = {};
	struct lttng_map_comm *header;

	if (map->name != NULL) {
		size_name = strlen(map->name) + 1;
	} else {
		size_name = 0;
	}

	map_comm.name_length = size_name;
	map_comm.bitness = map->bitness;
	map_comm.domain = map->domain;
	map_comm.buffer_type = map->buffer_type;
	map_comm.boundary_policy = map->boundary_policy;
	map_comm.dimension_count = map->dimension_count;

	header_offset = payload->buffer.size;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &map_comm,
			sizeof(map_comm));
	if (ret) {
		goto end;
	}

	size_before_payload = payload->buffer.size;

	/* map name */
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, map->name, size_name);
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, map->dimension_sizes,
			sizeof(*map->dimension_sizes) * map->dimension_count);
	if (ret) {
		goto end;
	}

	/* Update payload size. */
	header = (typeof(header)) (payload->buffer.data + header_offset);
	header->length = payload->buffer.size - size_before_payload;

end:
	return ret;
}

LTTNG_HIDDEN
ssize_t lttng_map_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_map **map)
{
	ssize_t ret, offset = 0, name_size = 0;
	const struct lttng_map_comm *map_comm;
	enum lttng_map_status status;
	unsigned int dimension_count;
	uint64_t *dimension_sizes;
	const char *name = NULL;
	enum lttng_domain_type domain;
	enum lttng_buffer_type buffer_type;
	enum lttng_map_bitness bitness;
	enum lttng_map_boundary_policy boundary_policy;

	if (!src_view || !map) {
		ret = -1;
		goto end;
	}

	map_comm = (typeof(map_comm)) src_view->buffer.data;
	offset += sizeof(*map_comm);

	domain = map_comm->domain;
	buffer_type = map_comm->buffer_type;
	bitness = map_comm->bitness;
	boundary_policy = map_comm->boundary_policy;
	dimension_count = map_comm->dimension_count;

	if (map_comm->name_length != 0) {
		struct lttng_payload_view name_view =
				lttng_payload_view_from_view(
						src_view, offset,
						map_comm->name_length);

		name = name_view.buffer.data;
		if (!lttng_buffer_view_contains_string(&name_view.buffer,
					name, map_comm->name_length)){
			ret = -1;
			goto end;
		}
		offset += map_comm->name_length;
		name_size = map_comm->name_length;
	}

	struct lttng_payload_view dimension_sizes_view =
			lttng_payload_view_from_view(src_view, offset, -1);

	dimension_sizes = zmalloc(dimension_sizes_view.buffer.size);
	if (!dimension_sizes) {
		ret = -1;
		goto end;
	}

	memcpy(&dimension_sizes, dimension_sizes_view.buffer.data,
			dimension_sizes_view.buffer.size);

	offset += dimension_sizes_view.buffer.size;

	status = lttng_map_create(name, dimension_count,
			dimension_sizes, domain, buffer_type, bitness,
			boundary_policy, map);
	if (status != LTTNG_MAP_STATUS_OK) {
		ret = -1;
		goto end;
	}

	ret = offset;

end:
	return ret;
}

void lttng_map_destroy(struct lttng_map *map)
{
	free(map->dimension_sizes);
	free(map->name);
	free(map);
}
