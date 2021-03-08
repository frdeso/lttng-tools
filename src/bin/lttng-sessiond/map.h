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

struct map_kv_ht_entry {
	struct lttng_ht_node_str node;
	char *key;
	int64_t value;
	bool has_overflowed;
	bool has_underflowed;
};

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

void map_add_or_increment_map_values(struct lttng_ht *map_values, const char *key,
		int64_t value, bool has_underflowed, bool has_overflowed);

int map_new_content_section(struct lttng_map_content *map_content,
		enum lttng_map_key_value_pair_list_type list_type,
		bool summed_all_cpus, unsigned int identifier,
		int cpu, struct lttng_ht *values);

#endif /* _LTT_MAP_H */
