/*
 * Copyright (C) 2017 - Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_EVENT_INTERNAL_H
#define LTTNG_EVENT_INTERNAL_H

/*
 * Event uprobe.
 *
 * The structures should be initialized to zero before use.
 */

struct sdt_probe_description {
	char probe_provider[LTTNG_SYMBOL_NAME_LEN];
	char probe_name[LTTNG_SYMBOL_NAME_LEN];
};

struct lttng_event_userspace_probe_attr {
	int fd;
	uid_t uid;
	gid_t gid;
	union {
		uint64_t offset;
		char symbol_name[LTTNG_SYMBOL_NAME_LEN];
		struct sdt_probe_description sdt_probe_desc;
	} u;

	char expr[LTTNG_PATH_MAX];
};

struct lttng_event_extended {
	char *filter_expr;
	char *exclusion_expr;
	struct lttng_event_userspace_probe_attr userspace_probe;
} LTTNG_PACKED;

#endif /* LTTNG_EVENT_INTERNAL_H */
