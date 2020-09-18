/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_H
#define LTTNG_MAP_H

#include <stddef.h>

#include <lttng/domain.h>
#include <lttng/handle.h>

struct lttng_map;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_map_status {
	LTTNG_MAP_STATUS_OK = 0,
	LTTNG_MAP_STATUS_ERROR = -1,
	LTTNG_MAP_STATUS_INVALID = -2,
	LTTNG_MAP_STATUS_UNSET = -3,
};

enum lttng_map_bitness {
	LTTNG_MAP_BITNESS_32BIT = 0,
	LTTNG_MAP_BITNESS_64BIT = 1,
};

enum lttng_map_boundary_policy {
	LTTNG_MAP_BOUNDARY_POLICY_OVERFLOW = 0,
};

/*
 *
 * Return LTTNG_MAP_STATUS_OK on success, LTTNG_MAP_STATUS_INVALID if invalid
 * parameters are passed.
 */
extern enum lttng_map_status lttng_map_create(const char *name,
		unsigned int dimension_count,
		uint64_t *dimension_sizes,
		enum lttng_domain_type domain,
		enum lttng_buffer_type buffer_type,
		enum lttng_map_bitness bitness,
		enum lttng_map_boundary_policy boundary_policy,
		struct lttng_map **map);

extern enum lttng_map_status lttng_map_enable(struct lttng_map *map);

extern enum lttng_map_status lttng_map_disable(struct lttng_map *map);

extern enum lttng_map_status lttng_map_get_name(
		const struct lttng_map *map, const char **name);

extern enum lttng_map_status lttng_map_set_name(
		struct lttng_map *map, const char *name);

/*
 * Get the number of dimensions.
 *
 */
extern unsigned int lttng_map_get_dimension_count(
		const struct lttng_map *map);

/*
 * Get the number of elements for the provided dimension.
 *
 * Return LTTNG_MAP_STATUS_OK on success, LTTNG_MAP_STATUS_INVALID if invalid
 * parameters are passed.
 *
 */
extern enum lttng_map_status lttng_map_get_dimension_length(
		const struct lttng_map *map, unsigned int dimension,
		uint64_t *dimension_length);

extern enum lttng_map_bitness lttng_map_get_bitness(
		const struct lttng_map *map);

extern enum lttng_domain_type lttng_map_get_domain(
		const struct lttng_map *map);

extern enum lttng_buffer_type lttng_map_get_buffer_type(
		const struct lttng_map *map);

extern enum lttng_map_boundary_policy lttng_map_get_boundary_policy(
		const struct lttng_map *map);

extern void lttng_map_destroy(struct lttng_map *map);

extern int lttng_enable_map(struct lttng_handle *handle,
		struct lttng_map *map);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_H */
