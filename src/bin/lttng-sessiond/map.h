/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */
#ifndef _LTT_MAP_H
#define _LTT_MAP_H

#include <lttng/map/map.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include "trace-kernel.h"
#include "trace-ust.h"

enum lttng_error_code map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map);
enum lttng_error_code map_kernel_enable(struct ltt_kernel_session *ksession,
		struct ltt_kernel_map *kmap);
enum lttng_error_code map_kernel_disable(struct ltt_kernel_session *ksession,
		struct ltt_kernel_map *kmap);

int map_ust_add(struct ltt_ust_session *usession,
		struct lttng_map *map);
int map_ust_enable(struct ltt_ust_session *usess,
		struct ltt_ust_map *umap);
int map_ust_disable(struct ltt_ust_session *usess,
		struct ltt_ust_map *umap);

#endif /* _LTT_MAP_H */
