/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_NOTIFY_INTERNAL_H
#define LTTNG_ACTION_NOTIFY_INTERNAL_H

#include <lttng/action/notify.h>
#include <lttng/action/action-internal.h>
#include <common/dynamic-array.h>

struct lttng_action_notify {
	struct lttng_action parent;

	/* Array of `struct lttng_event_expr *` */
	struct lttng_dynamic_pointer_array capture_descriptors;
};

LTTNG_HIDDEN
ssize_t lttng_action_notify_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_action **action);

#endif /* LTTNG_ACTION_NOTIFY_INTERNAL_H */
