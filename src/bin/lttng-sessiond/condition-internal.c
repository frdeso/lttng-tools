/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/hashtable/utils.h>
#include <common/hashtable/hashtable.h>

#include <lttng/condition/condition.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/buffer-usage-internal.h>
#include <lttng/condition/session-consumed-size-internal.h>
#include <lttng/condition/session-rotation-internal.h>
#include <lttng/condition/on-event-internal.h>
#include <lttng/condition/on-event.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/condition/on-event-internal.h>
#include "condition-internal.h"

static
unsigned long lttng_condition_buffer_usage_hash(
	const struct lttng_condition *_condition)
{
	unsigned long hash;
	unsigned long condition_type;
	struct lttng_condition_buffer_usage *condition;

	condition = container_of(_condition,
			struct lttng_condition_buffer_usage, parent);

	condition_type = (unsigned long) condition->parent.type;
	hash = hash_key_ulong((void *) condition_type, lttng_ht_seed);
	if (condition->session_name) {
		hash ^= hash_key_str(condition->session_name, lttng_ht_seed);
	}
	if (condition->channel_name) {
		hash ^= hash_key_str(condition->channel_name, lttng_ht_seed);
	}
	if (condition->domain.set) {
		hash ^= hash_key_ulong(
				(void *) condition->domain.type,
				lttng_ht_seed);
	}
	if (condition->threshold_ratio.set) {
		uint64_t val;

		val = condition->threshold_ratio.value * (double) UINT32_MAX;
		hash ^= hash_key_u64(&val, lttng_ht_seed);
	} else if (condition->threshold_bytes.set) {
		uint64_t val;

		val = condition->threshold_bytes.value;
		hash ^= hash_key_u64(&val, lttng_ht_seed);
	}
	return hash;
}

static
unsigned long lttng_condition_session_consumed_size_hash(
	const struct lttng_condition *_condition)
{
	unsigned long hash;
	unsigned long condition_type =
			(unsigned long) LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE;
	struct lttng_condition_session_consumed_size *condition;
	uint64_t val;

	condition = container_of(_condition,
			struct lttng_condition_session_consumed_size, parent);

	hash = hash_key_ulong((void *) condition_type, lttng_ht_seed);
	if (condition->session_name) {
		hash ^= hash_key_str(condition->session_name, lttng_ht_seed);
	}
	val = condition->consumed_threshold_bytes.value;
	hash ^= hash_key_u64(&val, lttng_ht_seed);
	return hash;
}

static
unsigned long lttng_condition_session_rotation_hash(
	const struct lttng_condition *_condition)
{
	unsigned long hash, condition_type;
	struct lttng_condition_session_rotation *condition;

	condition = container_of(_condition,
			struct lttng_condition_session_rotation, parent);
	condition_type = (unsigned long) condition->parent.type;
	hash = hash_key_ulong((void *) condition_type, lttng_ht_seed);
	assert(condition->session_name);
	hash ^= hash_key_str(condition->session_name, lttng_ht_seed);
	return hash;
}

static
unsigned long lttng_condition_on_event_hash(
	const struct lttng_condition *condition)
{
	unsigned long hash, condition_type;
	enum lttng_condition_status condition_status;
	const struct lttng_event_rule *event_rule;

	condition_type = (unsigned long) condition->type;
	condition_status = lttng_condition_on_event_get_rule(condition,
			&event_rule);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	hash = hash_key_ulong((void *) condition_type, lttng_ht_seed);
	return hash ^ lttng_event_rule_hash(event_rule);
}

/*
 * The lttng_condition hashing code is kept in this file (rather than
 * condition.c) since it makes use of GPLv2 code (hashtable utils), which we
 * don't want to link in liblttng-ctl.
 */
unsigned long lttng_condition_hash(const struct lttng_condition *condition)
{
	switch (condition->type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		return lttng_condition_buffer_usage_hash(condition);
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		return lttng_condition_session_consumed_size_hash(condition);
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		return lttng_condition_session_rotation_hash(condition);
	case LTTNG_CONDITION_TYPE_ON_EVENT:
		return lttng_condition_on_event_hash(condition);
	default:
		//ERR("[notification-thread] Unexpected condition type caught");
		abort();
	}
}

LTTNG_HIDDEN
struct lttng_condition *lttng_condition_copy(const struct lttng_condition *condition)
{
	int ret;
	struct lttng_payload copy_buffer;
	struct lttng_condition *copy = NULL;

	lttng_payload_init(&copy_buffer);

	ret = lttng_condition_serialize(condition, &copy_buffer);
	if (ret < 0) {
		goto end;
	}

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&copy_buffer, 0, -1);
		ret = lttng_condition_create_from_payload(
				&view, &copy);
		if (ret < 0) {
			copy = NULL;
			goto end;
		}
	}

end:
	lttng_payload_reset(&copy_buffer);
	return copy;
}
