/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/error.h>
#include <common/macros.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/incr-value-internal.h>
#include <lttng/action/incr-value.h>

#define IS_INCR_VALUE_ACTION(action) \
	(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_INCREMENT_VALUE)

struct lttng_action_incr_value {
	struct lttng_action parent;
	enum lttng_action_incr_value_key_allocation_policy key_alloc_policy;

	/* Owned by this. */
	char *session_name;
	/* Owned by this. */
	char *map_name;

	/* Owned by this. */
	char *key;
	/* Owned by this. */
	char *key_alloc_policy_unique_postfix;

};

struct lttng_action_incr_value_comm {
	uint32_t key_alloc_policy;
	/* Includes the trailing \0. */
	uint32_t session_name_len;
	/* Includes the trailing \0. */
	uint32_t map_name_len;

	/*
	 * Variable data:
	 *
	 *  - session name (null terminated)
	 *  - map name (null terminated)
	 */
	char data[];
} LTTNG_PACKED;

static struct lttng_action_incr_value *action_incr_value_from_action(
		struct lttng_action *action)
{
	assert(action);

	return container_of(action, struct lttng_action_incr_value, parent);
}

static const struct lttng_action_incr_value *
action_incr_value_from_action_const(const struct lttng_action *action)
{
	assert(action);

	return container_of(action, struct lttng_action_incr_value, parent);
}

static bool lttng_action_incr_value_validate(struct lttng_action *action)
{
	bool valid;
	struct lttng_action_incr_value *action_incr_value;

	if (!action) {
		valid = false;
		goto end;
	}

	action_incr_value = action_incr_value_from_action(action);

	/* A non-empty session name is mandatory. */
	if (!action_incr_value->session_name ||
			strlen(action_incr_value->session_name) == 0) {
		valid = false;
		goto end;
	}

	/* A non-empty map name is mandatory. */
	if (!action_incr_value->map_name ||
			strlen(action_incr_value->map_name) == 0) {
		valid = false;
		goto end;
	}

	valid = true;
end:
	return valid;
}

static bool lttng_action_incr_value_is_equal(
		const struct lttng_action *_a, const struct lttng_action *_b)
{
	bool is_equal = false;
	const struct lttng_action_incr_value *a, *b;

	a = action_incr_value_from_action_const(_a);
	b = action_incr_value_from_action_const(_b);

	/* Action is not valid if this is not true. */
	assert(a->session_name);
	assert(b->session_name);
	assert(a->map_name);
	assert(b->map_name);

	if (strcmp(a->session_name, b->session_name)) {
		goto end;
	}

	if (strcmp(a->map_name, b->map_name)) {
		goto end;
	}

	is_equal = true;

end:
	return is_equal;
}

static int lttng_action_incr_value_serialize(
		struct lttng_action *action, struct lttng_payload *payload)
{
	struct lttng_action_incr_value *action_incr_value;
	struct lttng_action_incr_value_comm comm;
	size_t session_name_len, map_name_len;
	int ret;

	assert(action);
	assert(payload);

	action_incr_value = action_incr_value_from_action(action);

	DBG("Serializing increment value action");

	comm.key_alloc_policy = (uint32_t) action_incr_value->key_alloc_policy;
	session_name_len = strlen(action_incr_value->session_name) + 1;
	comm.session_name_len = session_name_len;

	map_name_len = strlen(action_incr_value->map_name) + 1;
	comm.map_name_len = map_name_len;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer,
			action_incr_value->session_name, session_name_len);
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer,
			action_incr_value->map_name, map_name_len);
	if (ret) {
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	return ret;
}

static void lttng_action_incr_value_destroy(struct lttng_action *action)
{
	struct lttng_action_incr_value *action_incr_value;

	if (!action) {
		goto end;
	}

	action_incr_value = action_incr_value_from_action(action);

	free(action_incr_value->session_name);
	free(action_incr_value->map_name);
	free(action_incr_value);

end:
	return;
}

ssize_t lttng_action_incr_value_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **p_action)
{
	ssize_t consumed_len;
	enum lttng_action_incr_value_key_allocation_policy key_alloc_policy;
	const struct lttng_action_incr_value_comm *comm;
	const char *session_name, *map_name;
	struct lttng_action *action;
	enum lttng_action_status status;

	action = lttng_action_incr_value_create();
	if (!action) {
		consumed_len = -1;
		goto error;
	}

	comm = (typeof(comm)) view->buffer.data;
	consumed_len = sizeof(struct lttng_action_incr_value_comm);

	key_alloc_policy = (enum lttng_action_incr_value_key_allocation_policy) comm->key_alloc_policy;

	session_name = (const char *) &comm->data;

	if (!lttng_buffer_view_contains_string(
			&view->buffer, session_name, comm->session_name_len)) {
		consumed_len = -1;
		goto error;
	}

	consumed_len += comm->session_name_len;

	map_name = (const char *) &comm->data + comm->session_name_len;

	if (!lttng_buffer_view_contains_string(
			&view->buffer, map_name, comm->map_name_len)) {
		consumed_len = -1;
		goto error;
	}

	consumed_len += comm->map_name_len;

	status = lttng_action_incr_value_set_key_allocation_policy(
			action, key_alloc_policy);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_len = -1;
		goto error;
	}

	//FIXME this is broken, some allocation policy have string attached

	status = lttng_action_incr_value_set_session_name(
			action, session_name);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_len = -1;
		goto error;
	}

	status = lttng_action_incr_value_set_map_name(
			action, map_name);
	if (status != LTTNG_ACTION_STATUS_OK) {
		consumed_len = -1;
		goto error;
	}


	*p_action = action;
	action = NULL;
	goto end;

error:
	lttng_action_incr_value_destroy(action);
	consumed_len = -1;

end:

	return consumed_len;
}

struct lttng_action *lttng_action_incr_value_create(void)
{
	struct lttng_action *action;

	action = zmalloc(sizeof(struct lttng_action_incr_value));
	if (!action) {
		goto end;
	}

	lttng_action_init(action, LTTNG_ACTION_TYPE_INCREMENT_VALUE,
			lttng_action_incr_value_validate,
			lttng_action_incr_value_serialize,
			lttng_action_incr_value_is_equal,
			lttng_action_incr_value_destroy);

end:
	return action;
}

enum lttng_action_status lttng_action_incr_value_set_session_name(
		struct lttng_action *action, const char *session_name)
{
	struct lttng_action_incr_value *action_incr_value;
	enum lttng_action_status status;

	if (!action || !IS_INCR_VALUE_ACTION(action) || !session_name ||
			strlen(session_name) == 0) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_incr_value = action_incr_value_from_action(action);

	free(action_incr_value->session_name);

	action_incr_value->session_name = strdup(session_name);
	if (!action_incr_value->session_name) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status lttng_action_incr_value_get_session_name(
		const struct lttng_action *action, const char **session_name)
{
	const struct lttng_action_incr_value *action_incr_value;
	enum lttng_action_status status;

	if (!action || !IS_INCR_VALUE_ACTION(action) || !session_name) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_incr_value = action_incr_value_from_action_const(action);

	*session_name = action_incr_value->session_name;

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status lttng_action_incr_value_set_map_name(
		struct lttng_action *action, const char *map_name)
{
	struct lttng_action_incr_value *action_incr_value;
	enum lttng_action_status status;

	if (!action || !IS_INCR_VALUE_ACTION(action) || !map_name ||
			strlen(map_name) == 0) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_incr_value = action_incr_value_from_action(action);

	free(action_incr_value->map_name);

	action_incr_value->map_name = strdup(map_name);
	if (!action_incr_value->map_name) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status lttng_action_incr_value_get_map_name(
		const struct lttng_action *action, const char **map_name)
{
	const struct lttng_action_incr_value *action_incr_value;
	enum lttng_action_status status;

	if (!action || !IS_INCR_VALUE_ACTION(action) || !map_name) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_incr_value = action_incr_value_from_action_const(action);

	*map_name = action_incr_value->map_name;

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status
lttng_action_incr_value_set_key_allocation_policy(struct lttng_action *action,
		enum lttng_action_incr_value_key_allocation_policy key_alloc_policy)
{
	struct lttng_action_incr_value *action_incr_value;
	enum lttng_action_status status;

	if (!action || !IS_INCR_VALUE_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_incr_value = action_incr_value_from_action(action);
	action_incr_value->key_alloc_policy = key_alloc_policy;

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status
lttng_action_incr_value_get_key_allocation_policy(
		const struct lttng_action *action,
		enum lttng_action_incr_value_key_allocation_policy *key_alloc_policy)
{
	const struct lttng_action_incr_value *action_incr_value;
	enum lttng_action_status status;

	if (!action || !IS_INCR_VALUE_ACTION(action) || !key_alloc_policy) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_incr_value = action_incr_value_from_action_const(action);

	*key_alloc_policy = action_incr_value->key_alloc_policy;

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status
lttng_action_incr_value_set_key_allocation_key(struct lttng_action *action,
		const char *key)
{
	struct lttng_action_incr_value *action_incr_value;
	enum lttng_action_status status;

	if (!action || !IS_INCR_VALUE_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_incr_value = action_incr_value_from_action(action);

	if (action_incr_value->key_alloc_policy != LTTNG_ACTION_INCR_VALUE_KEY_ALLOCATION_POLICY_STATIC) {
		status = LTTNG_ACTION_STATUS_INVALID;
	}

	free(action_incr_value->key);

	action_incr_value->key = strdup(key);
	if (!action_incr_value->key) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}

enum lttng_action_status
lttng_action_incr_value_set_key_allocation_postfix(struct lttng_action *action,
		const char *postfix)
{
	struct lttng_action_incr_value *action_incr_value;
	enum lttng_action_status status;

	if (!action || !IS_INCR_VALUE_ACTION(action)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	action_incr_value = action_incr_value_from_action(action);

	if (action_incr_value->key_alloc_policy != LTTNG_ACTION_INCR_VALUE_KEY_ALLOCATION_POLICY_UNIQUE) {
		status = LTTNG_ACTION_STATUS_INVALID;
	}

	free(action_incr_value->key_alloc_policy_unique_postfix);

	action_incr_value->key_alloc_policy_unique_postfix = strdup(postfix);
	if (!action_incr_value->key_alloc_policy_unique_postfix) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_ACTION_STATUS_OK;
end:
	return status;
}
