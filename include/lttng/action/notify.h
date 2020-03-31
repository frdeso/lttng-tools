/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_NOTIFY_H
#define LTTNG_ACTION_NOTIFY_H

struct lttng_action;
struct lttng_event_expr;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated notification action object.
 *
 * A "notify" action will emit a notification to all clients which have an
 * open notification channel. In order to receive this notification, clients
 * must have subscribed to a condition equivalent to the one paired to this
 * notify action in a trigger.
 *
 * Returns a new action on success, NULL on failure. This action must be
 * destroyed using lttng_action_destroy().
 */
extern struct lttng_action *lttng_action_notify_create(void);

/*
 * Appends (transfering the ownership) the capture descriptor `expr` to
 * `action`.
 *
 * Returns:
 *
 * `LTTNG_ACTION_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_ACTION_STATUS_ERROR`:
 *     Memory error.
 *
 * `LTTNG_ACTION_STATUS_INVALID`:
 *     * `action` is `NULL`.
 *     * The type of `action` is not `LTTNG_ACTION_TYPE_NOTIFY`.
 *     * `expr` is `NULL`.
 *     * `expr` is not a locator expression, that is, its type is not
 *       one of:
 *
 *       * `LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT`
 */
extern enum lttng_action_status lttng_action_notify_append_capture_descriptor(
		struct lttng_action *action,
		struct lttng_event_expr *expr);

/*
 * Sets `*count` to the number of capture descriptors in the action
 * `action`.
 *
 * Returns:
 *
 * `LTTNG_ACTION_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_ACTION_STATUS_INVALID`:
 *     * `action` is `NULL`.
 *     * The type of `action` is not `LTTNG_ACTION_TYPE_NOTIFY`.
 *     * `count` is `NULL`.
 */
extern enum lttng_action_status
lttng_action_notify_get_capture_descriptor_count(
		const struct lttng_action *action, unsigned int *count);

/*
 * Returns the capture descriptor (borrowed) of the notify action
 * `action` at the index `index`, or `NULL` if:
 *
 * * `action` is `NULL`.
 * * The type of `action` is not `LTTNG_ACTION_TYPE_NOTIFY`.
 * * `index` is greater than or equal to the number of capture
 *   descriptors in `action` (as returned by
 *   lttng_action_notify_get_capture_descriptor_count()).
 */
extern const struct lttng_event_expr *
lttng_action_notify_get_capture_descriptor_at_index(
		const struct lttng_action *action, unsigned int index);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_NOTIFY_H */
