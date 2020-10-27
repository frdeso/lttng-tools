/*
 * test_action.c
 *
 * Unit tests for the notification API.
 *
 * Copyright (C) 2017 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <common/dynamic-buffer.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <lttng/action/action-internal.h>
#include <lttng/action/action.h>
#include <lttng/action/incr-value-internal.h>
#include <lttng/action/incr-value.h>
#include <lttng/action/notify.h>
#include <lttng/action/rate-policy-internal.h>
#include <lttng/action/rate-policy.h>
#include <lttng/action/rotate-session.h>
#include <lttng/action/snapshot-session.h>
#include <lttng/action/start-session.h>
#include <lttng/action/stop-session.h>
#include <lttng/map-key-internal.h>


/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 74

static void test_action_notify(void)
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *notify_action = NULL,
			    *notify_action_from_buffer = NULL;
	struct lttng_rate_policy *policy = NULL, *default_policy;
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	assert(policy && default_policy);

	notify_action = lttng_action_notify_create();
	ok(notify_action, "Create notify action");
	ok(lttng_action_get_type(notify_action) == LTTNG_ACTION_TYPE_NOTIFY,
			"Action has type LTTNG_ACTION_TYPE_NOTIFY");

	/* Validate the default policy for a notify action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_notify_get_rate_policy(
				notify_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								default_policy,
								cur_policy),
				"Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_notify_set_rate_policy(notify_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a notify action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_notify_get_rate_policy(
				notify_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								policy,
								cur_policy),
				"Notify action policy get");
	}

	ret = lttng_action_serialize(notify_action, &payload);
	ok(ret == 0, "Action notify serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		(void) lttng_action_create_from_payload(
				&view, &notify_action_from_buffer);
	}
	ok(notify_action_from_buffer,
			"Notify action created from payload is non-null");

	ok(lttng_action_is_equal(notify_action, notify_action_from_buffer),
			"Serialized and de-serialized notify action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(notify_action);
	lttng_action_destroy(notify_action_from_buffer);
	lttng_payload_reset(&payload);
}

static void test_action_rotate_session(void)
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *rotate_session_action = NULL,
			    *rotate_session_action_from_buffer = NULL;
	struct lttng_rate_policy *policy = NULL, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	assert(policy && default_policy);

	rotate_session_action = lttng_action_rotate_session_create();
	ok(rotate_session_action, "Create rotate_session action");
	ok(lttng_action_get_type(rotate_session_action) ==
					LTTNG_ACTION_TYPE_ROTATE_SESSION,
			"Action has type LTTNG_ACTION_TYPE_ROTATE_SESSION");

	/* Session name setter. */
	status = lttng_action_rotate_session_set_session_name(NULL, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,NULL) expect invalid");
	status = lttng_action_rotate_session_set_session_name(
			rotate_session_action, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (object,NULL) expect invalid");
	status = lttng_action_rotate_session_set_session_name(
			NULL, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_rotate_session_set_session_name(
			rotate_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_rotate_session_get_session_name(
			rotate_session_action, &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK &&
					!strcmp(session_name, get_session_name),
			"Get session name, expected `%s` got `%s`",
			session_name, get_session_name);

	/* Validate the default policy for a rotate_session action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_rotate_session_get_rate_policy(
				rotate_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								default_policy,
								cur_policy),
				"Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_rotate_session_set_rate_policy(
			rotate_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a rotate_session action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_rotate_session_get_rate_policy(
				rotate_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								policy,
								cur_policy),
				"rotate_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(rotate_session_action, &payload);
	ok(ret == 0, "Action rotate_session serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		(void) lttng_action_create_from_payload(
				&view, &rotate_session_action_from_buffer);
	}
	ok(rotate_session_action_from_buffer,
			"rotate_session action created from payload is non-null");

	ok(lttng_action_is_equal(rotate_session_action,
			   rotate_session_action_from_buffer),
			"Serialized and de-serialized rotate_session action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(rotate_session_action);
	lttng_action_destroy(rotate_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

static void test_action_start_session(void)
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *start_session_action = NULL,
			    *start_session_action_from_buffer = NULL;
	struct lttng_rate_policy *policy = NULL, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	assert(policy && default_policy);

	start_session_action = lttng_action_start_session_create();
	ok(start_session_action, "Create start_session action");
	ok(lttng_action_get_type(start_session_action) ==
					LTTNG_ACTION_TYPE_START_SESSION,
			"Action has type LTTNG_ACTION_TYPE_START_SESSION");

	/* Session name setter. */
	status = lttng_action_start_session_set_session_name(NULL, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,NULL) expect invalid");
	status = lttng_action_start_session_set_session_name(
			start_session_action, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (object,NULL) expect invalid");
	status = lttng_action_start_session_set_session_name(
			NULL, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_start_session_set_session_name(
			start_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_start_session_get_session_name(
			start_session_action, &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK &&
					!strcmp(session_name, get_session_name),
			"Get session name, expected `%s` got `%s`",
			session_name, get_session_name);

	/* Validate the default policy for a start_session action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_start_session_get_rate_policy(
				start_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								default_policy,
								cur_policy),
				"Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_start_session_set_rate_policy(
			start_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a start_session action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_start_session_get_rate_policy(
				start_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								policy,
								cur_policy),
				"start_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(start_session_action, &payload);
	ok(ret == 0, "Action start_session serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		(void) lttng_action_create_from_payload(
				&view, &start_session_action_from_buffer);
	}
	ok(start_session_action_from_buffer,
			"start_session action created from payload is non-null");

	ok(lttng_action_is_equal(start_session_action,
			   start_session_action_from_buffer),
			"Serialized and de-serialized start_session action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(start_session_action);
	lttng_action_destroy(start_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

static void test_action_stop_session(void)
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *stop_session_action = NULL,
			    *stop_session_action_from_buffer = NULL;
	struct lttng_rate_policy *policy = NULL, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	assert(policy && default_policy);

	stop_session_action = lttng_action_stop_session_create();
	ok(stop_session_action, "Create stop_session action");
	ok(lttng_action_get_type(stop_session_action) ==
					LTTNG_ACTION_TYPE_STOP_SESSION,
			"Action has type LTTNG_ACTION_TYPE_STOP_SESSION");

	/* Session name setter. */
	status = lttng_action_stop_session_set_session_name(NULL, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,NULL) expect invalid");
	status = lttng_action_stop_session_set_session_name(
			stop_session_action, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (object,NULL) expect invalid");
	status = lttng_action_stop_session_set_session_name(NULL, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_stop_session_set_session_name(
			stop_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_stop_session_get_session_name(
			stop_session_action, &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK &&
					!strcmp(session_name, get_session_name),
			"Get session name, expected `%s` got `%s`",
			session_name, get_session_name);

	/* Validate the default policy for a stop_session action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_stop_session_get_rate_policy(
				stop_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								default_policy,
								cur_policy),
				"Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_stop_session_set_rate_policy(
			stop_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a stop_session action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_stop_session_get_rate_policy(
				stop_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								policy,
								cur_policy),
				"stop_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(stop_session_action, &payload);
	ok(ret == 0, "Action stop_session serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		(void) lttng_action_create_from_payload(
				&view, &stop_session_action_from_buffer);
	}
	ok(stop_session_action_from_buffer,
			"stop_session action created from payload is non-null");

	ok(lttng_action_is_equal(stop_session_action,
			   stop_session_action_from_buffer),
			"Serialized and de-serialized stop_session action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(stop_session_action);
	lttng_action_destroy(stop_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

static void test_action_snapshot_session(void)
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *snapshot_session_action = NULL,
			    *snapshot_session_action_from_buffer = NULL;
	struct lttng_rate_policy *policy = NULL, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	assert(policy && default_policy);

	snapshot_session_action = lttng_action_snapshot_session_create();
	ok(snapshot_session_action, "Create snapshot_session action");
	ok(lttng_action_get_type(snapshot_session_action) ==
					LTTNG_ACTION_TYPE_SNAPSHOT_SESSION,
			"Action has type LTTNG_ACTION_TYPE_SNAPSHOT_SESSION");

	/* Session name setter. */
	status = lttng_action_snapshot_session_set_session_name(NULL, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,NULL) expect invalid");
	status = lttng_action_snapshot_session_set_session_name(
			snapshot_session_action, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (object,NULL) expect invalid");
	status = lttng_action_snapshot_session_set_session_name(
			NULL, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_snapshot_session_set_session_name(
			snapshot_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_snapshot_session_get_session_name(
			snapshot_session_action, &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK &&
					!strcmp(session_name, get_session_name),
			"Get session name, expected `%s` got `%s`",
			session_name, get_session_name);

	/* Validate the default policy for a snapshot_session action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_snapshot_session_get_rate_policy(
				snapshot_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								default_policy,
								cur_policy),
				"Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_snapshot_session_set_rate_policy(
			snapshot_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a snapshot_session action. */
	{
		const struct lttng_rate_policy *cur_policy = NULL;
		status = lttng_action_snapshot_session_get_rate_policy(
				snapshot_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_rate_policy_is_equal(
								policy,
								cur_policy),
				"snapshot_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(snapshot_session_action, &payload);
	ok(ret == 0, "Action snapshot_session serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		(void) lttng_action_create_from_payload(
				&view, &snapshot_session_action_from_buffer);
	}
	ok(snapshot_session_action_from_buffer,
			"snapshot_session action created from payload is non-null");

	ok(lttng_action_is_equal(snapshot_session_action,
			   snapshot_session_action_from_buffer),
			"Serialized and de-serialized snapshot_session action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(snapshot_session_action);
	lttng_action_destroy(snapshot_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

static
void test_action_incr_value(void)
{
	int ret;
	struct lttng_action *action = NULL;
	struct lttng_action *action_from_buffer = NULL;
	const char *map_name = "my_map_name";
	const char *session_name = "my_session_name";
	const char *first_part_key = "first_part_🥇_";
	const char *second_part_key = "_🥈_second_part";
	struct lttng_map_key *key = NULL;
	enum lttng_action_status action_status;
	enum lttng_map_key_status key_status;
	struct lttng_payload buffer;
	const struct lttng_map_key *key_from_buffer;
	const struct lttng_map_key_token *token;

	lttng_payload_init(&buffer);

	/* Test key creation */
	key = lttng_map_key_create();
	ok(key, "Key created");

	key_status = lttng_map_key_append_token_string(key, first_part_key);
	ok(key_status == LTTNG_MAP_KEY_STATUS_OK, "Key append first string");

	key_status = lttng_map_key_append_token_variable(key, LTTNG_MAP_KEY_TOKEN_VARIABLE_TYPE_EVENT_NAME);
	ok(key_status == LTTNG_MAP_KEY_STATUS_OK, "Key append event name variable");

	key_status = lttng_map_key_append_token_string(key, second_part_key);
	ok(key_status == LTTNG_MAP_KEY_STATUS_OK, "Key append second string");

	/*Test incr value action creation */
	action = lttng_action_incr_value_create();
	ok(action, "Incr-value action created");

	action_status = lttng_action_incr_value_set_session_name(action, session_name);
	ok(action_status == LTTNG_ACTION_STATUS_OK, "incr-value set session name");

	action_status = lttng_action_incr_value_set_map_name(action, map_name);
	ok(action_status == LTTNG_ACTION_STATUS_OK, "incr-value set map name");

	action_status = lttng_action_incr_value_set_key(action, key);
	ok(action_status == LTTNG_ACTION_STATUS_OK, "incr-value set key");

	/* Test incr value action serialization */
	ret = lttng_action_serialize(action, &buffer);
	ok(ret == 0, "Incr value action serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);

		(void) lttng_action_create_from_payload(
				&view, &action_from_buffer);
	}
	ok(action_from_buffer, "Incr value action created from payload is non-null");

	action_status = lttng_action_incr_value_get_key(action, &key_from_buffer);
	ok(key_from_buffer, "Retrived key from incr value action");

	token = lttng_map_key_get_token_at_index(key_from_buffer, 0);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "First key token is a string");

	token = lttng_map_key_get_token_at_index(key_from_buffer, 1);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_VARIABLE, "Second key token is a variable");

	token = lttng_map_key_get_token_at_index(key_from_buffer, 2);
	ok(token->type == LTTNG_MAP_KEY_TOKEN_TYPE_STRING, "Third key token is a string");

	lttng_payload_reset(&buffer);

	lttng_action_destroy(action);
	lttng_action_destroy(action_from_buffer);
	lttng_map_key_destroy(key);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_action_notify();
	test_action_rotate_session();
	test_action_start_session();
	test_action_stop_session();
	test_action_snapshot_session();
	test_action_incr_value();
	return exit_status();
}
