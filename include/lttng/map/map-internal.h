/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_INTERNAL_H
#define LTTNG_MAP_INTERNAL_H

#include <common/macros.h>
#include <common/payload.h>
#include <common/payload-view.h>

#include "map.h"

struct lttng_map {
	char *name;
	enum lttng_map_bitness bitness;
	enum lttng_map_boundary_policy boundary_policy;
	enum lttng_domain_type domain;
	enum lttng_buffer_type buffer_type;
	unsigned int dimension_count;
	uint64_t *dimension_sizes;
};

struct lttng_map_comm {
	uint32_t name_length /* Includes '\0' */;
	uint32_t length;
	uint8_t bitness;
	uint8_t boundary_policy;
	uint8_t domain;
	uint8_t buffer_type;
	uint64_t dimension_count;

	/* length excludes its own length. */
	/* A name and dimension sizes follow. */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_map_create_from_payload(struct lttng_payload_view *view,
		struct lttng_map **map);

LTTNG_HIDDEN
int lttng_map_serialize(const struct lttng_map *map,
		struct lttng_payload *payload);

#endif /* LTTNG_MAP_INTERNAL_H */
