/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_INCR_VALUE_H
#define LTTNG_ACTION_INCR_VALUE_H

struct lttng_action;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_action_incr_value_key_allocation_policy {
	/*
	 * Use the same key provided for all on-event condition firing this
	 * actions. All events matching the on-event condition will share the
	 * same key.
	 */
	LTTNG_ACTION_INCR_VALUE_KEY_ALLOCATION_POLICY_STATIC = 0,
	/*
	 * Use the event name as the key.
	 * For wild card event rules, the same on-event condition may use
	 * multiple keys.
	 */
	LTTNG_ACTION_INCR_VALUE_KEY_ALLOCATION_POLICY_EVENT_NAME = 1,
	/*
	 * Concatenate the event name and a provided string.
	 * Useful when multiples on-event conditions may fire the same events
	 * but still need to be differenciated.
	 */
	LTTNG_ACTION_INCR_VALUE_KEY_ALLOCATION_POLICY_UNIQUE = 2,
};

/*
 * Create a newly allocated incr-value action object.
 *
 * Returns a new action on success, NULL on failure. This action must be
 * destroyed using lttng_action_destroy().
 */
extern struct lttng_action *lttng_action_incr_value_create(void);

/*
 * Set the session name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status lttng_action_incr_value_set_session_name(
		struct lttng_action *action, const char *session_name);

/*
 * Get the session name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status lttng_action_incr_value_get_session_name(
		const struct lttng_action *action, const char **session_name);

/*
 * Set the map name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status lttng_action_incr_value_set_map_name(
		struct lttng_action *action, const char *map_name);

/*
 * Get the map name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status lttng_action_incr_value_get_map_name(
		const struct lttng_action *action, const char **map_name);

/*
 * Set key allocation policy for an lttng_action object type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status
lttng_action_incr_value_set_key_allocation_policy(struct lttng_action *action,
		enum lttng_action_incr_value_key_allocation_policy alloc_policy);

/*
 * Get key allocation policy for an lttng_action object type
 * LTTNG_ACTION_TYPE_INCREMENT_VALUE.
 */
extern enum lttng_action_status
lttng_action_incr_value_get_key_allocation_policy(
		const struct lttng_action *action,
		enum lttng_action_incr_value_key_allocation_policy *alloc_policy);

extern enum lttng_action_status
lttng_action_incr_value_set_key_allocation_key(struct lttng_action *action,
		const char *key);

extern enum lttng_action_status
lttng_action_incr_value_set_key_allocation_postfix(struct lttng_action *action,
		const char *postfix);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_INCR_VALUE_H */
