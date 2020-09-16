/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_INTERNAL_H
#define LTTNG_MAP_INTERNAL_H

#include "map.h"

struct lttng_map {
	char *name;
	enum lttng_map_bitness bitness;
	enum lttng_map_boundary_policy boundary_policy;
	unsigned int dimension_count;
	uint64_t *dimension_sizes;
	enum lttng_domain_type domain;
	enum lttng_buffer_type buffer_type;
};

#endif /* LTTNG_MAP_INTERNAL_H */
