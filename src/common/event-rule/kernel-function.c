/*
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/credentials.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <common/runas.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <ctype.h>
#include <lttng/constant.h>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/kernel-function-internal.h>
#include <lttng/kernel-function.h>
#include <lttng/kernel-function-internal.h>
#include <stdio.h>

#define IS_KERNEL_FUNCTION_EVENT_RULE(rule) \
	(lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_KERNEL_FUNCTION)

#if (LTTNG_SYMBOL_NAME_LEN == 256)
#define LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "255"
#endif

static void lttng_event_rule_kernel_function_destroy(struct lttng_event_rule *rule)
{
	struct lttng_event_rule_kernel_function *kfunction;

	kfunction = container_of(rule, struct lttng_event_rule_kernel_function, parent);

	lttng_kernel_function_location_destroy(kfunction->location);
	free(kfunction->name);
	free(kfunction);
}

static bool lttng_event_rule_kernel_function_validate(
		const struct lttng_event_rule *rule)
{
	bool valid = false;
	struct lttng_event_rule_kernel_function *kfunction;

	if (!rule) {
		goto end;
	}

	kfunction = container_of(rule, struct lttng_event_rule_kernel_function, parent);

	/* Required field. */
	if (!kfunction->name) {
		ERR("Invalid name event rule: a name must be set.");
		goto end;
	}

	/* Required field. */
	if(!kfunction->location) {
		ERR("Invalid name event rule: a location must be set.");
		goto end;
	}

	valid = true;
end:
	return valid;
}

static int lttng_event_rule_kernel_function_serialize(
		const struct lttng_event_rule *rule,
		struct lttng_payload *payload)
{
	int ret;
	size_t name_len, header_offset, size_before_location;
	struct lttng_event_rule_kernel_function *kfunction;
	struct lttng_event_rule_kernel_function_comm kfunction_comm;
	struct lttng_event_rule_kernel_function_comm *header;

	if (!rule || !IS_KERNEL_FUNCTION_EVENT_RULE(rule)) {
		ret = -1;
		goto end;
	}

	header_offset = payload->buffer.size;

	DBG("Serializing kfunction event rule.");
	kfunction = container_of(rule, struct lttng_event_rule_kernel_function, parent);

	name_len = strlen(kfunction->name) + 1;
	kfunction_comm.name_len = name_len;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &kfunction_comm, sizeof(kfunction_comm));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, kfunction->name, name_len);
	if (ret) {
		goto end;
	}

	size_before_location = payload->buffer.size;

	ret = lttng_kernel_function_location_serialize(kfunction->location, payload);
	if (ret < 0) {
		goto end;
	}

	/* Update the header regarding the function size. */
	header = (struct lttng_event_rule_kernel_function_comm*) (
			(char *) payload->buffer.data + header_offset);
	header->location_len = payload->buffer.size - size_before_location;

	ret = 0;

end:
	return ret;
}

static bool lttng_event_rule_kernel_function_is_equal(const struct lttng_event_rule *_a,
		const struct lttng_event_rule *_b)
{
	bool is_equal = false;
	struct lttng_event_rule_kernel_function *a, *b;

	a = container_of(_a, struct lttng_event_rule_kernel_function, parent);
	b = container_of(_b, struct lttng_event_rule_kernel_function, parent);

	/* Quick checks */
	if (!!a->name != !!b->name) {
		goto end;
	}

	/* Long check */
	assert(a->name);
	assert(b->name);
	if (strcmp(a->name, b->name)) {
		goto end;
	}

	is_equal = lttng_kernel_function_location_is_equal(
			a->location, b->location);
end:
	return is_equal;
}

static enum lttng_error_code lttng_event_rule_kernel_function_generate_filter_bytecode(
		struct lttng_event_rule *rule,
		const struct lttng_credentials *creds)
{
	/* Nothing to do. */
	return LTTNG_OK;
}

static const char *lttng_event_rule_kernel_function_get_filter(
		const struct lttng_event_rule *rule)
{
	/* Not supported. */
	return NULL;
}

static const struct lttng_bytecode *
lttng_event_rule_kernel_function_get_filter_bytecode(const struct lttng_event_rule *rule)
{
	/* Not supported. */
	return NULL;
}

static enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_kernel_function_generate_exclusions(const struct lttng_event_rule *rule,
		struct lttng_event_exclusion **exclusions)
{
	/* Not supported. */
	*exclusions = NULL;
	return LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE;
}

static unsigned long
lttng_event_rule_kernel_function_hash(
		const struct lttng_event_rule *rule)
{
	unsigned long hash;
	struct lttng_event_rule_kernel_function *krule =
			container_of(rule, typeof(*krule), parent);

	hash = hash_key_ulong((void *) LTTNG_EVENT_RULE_TYPE_KERNEL_FUNCTION,
			lttng_ht_seed);
	hash ^= hash_key_str(krule->name, lttng_ht_seed);
	hash ^= lttng_kernel_function_location_hash(krule->location);

	return hash;
}

static
int kernel_function_set_location(
		struct lttng_event_rule_kernel_function *kfunction,
		const struct lttng_kernel_function_location *location)
{
	int ret;
	struct lttng_kernel_function_location *location_copy = NULL;

	if (!kfunction || !location || kfunction->location) {
		ret = -1;
		goto end;
	}

	location_copy = lttng_kernel_function_location_copy(location);
	if (!location_copy) {
		ret = -1;
		goto end;
	}

	kfunction->location = location_copy;
	location_copy = NULL;
	ret = 0;
end:
	lttng_kernel_function_location_destroy(location_copy);
	return ret;
}

struct lttng_event_rule *lttng_event_rule_kernel_function_create(
		const struct lttng_kernel_function_location *location)
{
	struct lttng_event_rule *rule = NULL;
	struct lttng_event_rule_kernel_function *krule;

	krule = zmalloc(sizeof(struct lttng_event_rule_kernel_function));
	if (!krule) {
		goto end;
	}

	rule = &krule->parent;
	lttng_event_rule_init(&krule->parent, LTTNG_EVENT_RULE_TYPE_KERNEL_FUNCTION);
	krule->parent.validate = lttng_event_rule_kernel_function_validate;
	krule->parent.serialize = lttng_event_rule_kernel_function_serialize;
	krule->parent.equal = lttng_event_rule_kernel_function_is_equal;
	krule->parent.destroy = lttng_event_rule_kernel_function_destroy;
	krule->parent.generate_filter_bytecode =
			lttng_event_rule_kernel_function_generate_filter_bytecode;
	krule->parent.get_filter = lttng_event_rule_kernel_function_get_filter;
	krule->parent.get_filter_bytecode =
			lttng_event_rule_kernel_function_get_filter_bytecode;
	krule->parent.generate_exclusions =
			lttng_event_rule_kernel_function_generate_exclusions;
	krule->parent.hash = lttng_event_rule_kernel_function_hash;

	if (kernel_function_set_location(krule, location)) {
		lttng_event_rule_destroy(rule);
		rule = NULL;
	}

end:
	return rule;
}

LTTNG_HIDDEN
ssize_t lttng_event_rule_kernel_function_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **_event_rule)
{
	ssize_t ret, offset = 0;
	enum lttng_event_rule_status status;
	const struct lttng_event_rule_kernel_function_comm *kfunction_comm;
	const char *name;
	struct lttng_buffer_view current_buffer_view;
	struct lttng_event_rule *rule = NULL;
	struct lttng_kernel_function_location *location = NULL;

	if (!_event_rule) {
		ret = -1;
		goto end;
	}

	current_buffer_view = lttng_buffer_view_from_view(
			&view->buffer, offset, sizeof(*kfunction_comm));
	if (!lttng_buffer_view_is_valid(&current_buffer_view)) {
		ERR("Failed to initialize from malformed event rule kfunction: buffer too short to contain header.");
		ret = -1;
		goto end;
	}

	kfunction_comm = (typeof(kfunction_comm)) current_buffer_view.data;

	/* Skip to payload */
	offset += current_buffer_view.size;

	{
		/* Map the name. */
		struct lttng_payload_view current_payload_view =
				lttng_payload_view_from_view(view, offset,
						kfunction_comm->name_len);

		if (!lttng_payload_view_is_valid(&current_payload_view)) {
			ret = -1;
			goto end;
		}

		name = current_payload_view.buffer.data;
		if (!lttng_buffer_view_contains_string(
				&current_payload_view.buffer, name,
				kfunction_comm->name_len)) {
			ret = -1;
			goto end;
		}
	}

	/* Skip after the name. */
	offset += kfunction_comm->name_len;

	/* Map the kernel function location. */
	{
		struct lttng_payload_view current_payload_view =
				lttng_payload_view_from_view(view, offset,
						kfunction_comm->location_len);

		if (!lttng_payload_view_is_valid(&current_payload_view)) {
			ret = -1;
			goto end;
		}

		ret = lttng_kernel_function_location_create_from_payload(
				&current_payload_view, &location);
		if (ret < 0) {
			ret = -1;
			goto end;
		}
	}

	if (ret != kfunction_comm->location_len) {
		ret = -1;
		goto end;
	}

	/* Skip after the location */
	offset += kfunction_comm->location_len;

	rule = lttng_event_rule_kernel_function_create(location);
	if (!rule) {
		ERR("Failed to create event rule kfunction.");
		ret = -1;
		goto end;
	}

	status = lttng_event_rule_kernel_function_set_event_name(rule, name);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		ERR("Failed to set event rule kfunction name.");
		ret = -1;
		goto end;
	}

	*_event_rule = rule;
	rule = NULL;
	ret = offset;
end:
	lttng_kernel_function_location_destroy(location);
	lttng_event_rule_destroy(rule);
	return ret;
}

enum lttng_event_rule_status lttng_event_rule_kernel_function_get_location(
		const struct lttng_event_rule *rule,
		const struct lttng_kernel_function_location **location)
{
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;
	struct lttng_event_rule_kernel_function *kfunction;

	if (!rule || !IS_KERNEL_FUNCTION_EVENT_RULE(rule) || !location) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	kfunction = container_of(rule, struct lttng_event_rule_kernel_function, parent);
	*location = kfunction->location;

	if (!*location) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kernel_function_set_event_name(
		struct lttng_event_rule *rule, const char *name)
{
	char *name_copy = NULL;
	struct lttng_event_rule_kernel_function *kfunction;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KERNEL_FUNCTION_EVENT_RULE(rule) || !name ||
			strlen(name) == 0) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	kfunction = container_of(rule, struct lttng_event_rule_kernel_function, parent);
	name_copy = strdup(name);
	if (!name_copy) {
		status = LTTNG_EVENT_RULE_STATUS_ERROR;
		goto end;
	}

	free(kfunction->name);

	kfunction->name = name_copy;
	name_copy = NULL;
end:
	return status;
}

enum lttng_event_rule_status lttng_event_rule_kernel_function_get_event_name(
		const struct lttng_event_rule *rule, const char **name)
{
	struct lttng_event_rule_kernel_function *kfunction;
	enum lttng_event_rule_status status = LTTNG_EVENT_RULE_STATUS_OK;

	if (!rule || !IS_KERNEL_FUNCTION_EVENT_RULE(rule) || !name) {
		status = LTTNG_EVENT_RULE_STATUS_INVALID;
		goto end;
	}

	kfunction = container_of(rule, struct lttng_event_rule_kernel_function, parent);
	if (!kfunction->name) {
		status = LTTNG_EVENT_RULE_STATUS_UNSET;
		goto end;
	}

	*name = kfunction->name;
end:
	return status;
}
