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
#include <inttypes.h>

struct lttng_capture_descriptor {
	/* The index at which the capture for this descriptor in the received
	 * payload from the tracer. This is populated on sessiond side.
	 * -1 is uninitialized.
	 * This is necessary since a single trigger can have multiple notify
	 * action, only an ordered set of capture desciptor is passed to the tracer.
	 */
	int32_t capture_index;
	struct lttng_event_expr *event_expression;
};

struct lttng_action_notify {
	struct lttng_action parent;

	/* Array of `struct lttng_capture_descriptor *` */
	struct lttng_dynamic_pointer_array capture_descriptors;
};

LTTNG_HIDDEN
ssize_t lttng_action_notify_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_action **action);

#endif /* LTTNG_ACTION_NOTIFY_INTERNAL_H */
