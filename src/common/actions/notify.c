/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/action/action-internal.h>
#include <lttng/action/notify-internal.h>
#include <lttng/event-expr-internal.h>
#include <lttng/event-expr.h>
#include <common/macros.h>
#include <common/dynamic-array.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

static
void lttng_action_notify_destroy(struct lttng_action *action)
{
	struct lttng_action_notify *notify_action =
			container_of(action, struct lttng_action_notify, parent);

	lttng_dynamic_pointer_array_reset(&notify_action->capture_descriptors);
	free(action);
}

/*
 * Serializes the C string `str` into `buf`.
 *
 * Encoding is the length of `str` plus one (for the null character),
 * and then the string, including its null character.
 */
static
int serialize_cstr(const char *str, struct lttng_dynamic_buffer *buf)
{
	int ret;
	uint32_t len = strlen(str) + 1;

	/* Serialize the length, including the null character */
	DBG("Serializing C string's length (including null character): "
			"%" PRIu32, len);
	ret = lttng_dynamic_buffer_append(buf, &len, sizeof(len));
	if (ret) {
		goto end;
	}

	/* Serialize the string */
	DBG("Serializing C string: \"%s\"", str);
	ret = lttng_dynamic_buffer_append(buf, str, len);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

/*
 * Serializes the event expression `expr` into `buf`.
 */
static
int serialize_event_expr(const struct lttng_event_expr *expr,
		struct lttng_dynamic_buffer *buf)
{
	uint8_t type;
	int ret;

	/* Serialize the expression's type */
	DBG("Serializing event expression's type: %d", expr->type);
	type = expr->type;
	ret = lttng_dynamic_buffer_append(buf, &type, sizeof(type));
	if (ret) {
		goto end;
	}

	/* Serialize the expression */
	switch (expr->type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
	{
		const struct lttng_event_expr_field *field_expr =
				container_of(expr,
					const struct lttng_event_expr_field,
					parent);

		/* Serialize the field name */
		DBG("Serializing field event expression's field name: \"%s\"",
				field_expr->name);
		ret = serialize_cstr(field_expr->name, buf);
		if (ret) {
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		const struct lttng_event_expr_app_specific_context_field *field_expr =
				container_of(expr,
					const struct lttng_event_expr_app_specific_context_field,
					parent);

		/* Serialize the provider name */
		DBG("Serializing app-specific context field event expression's "
				"provider name: \"%s\"",
				field_expr->provider_name);
		ret = serialize_cstr(field_expr->provider_name, buf);
		if (ret) {
			goto end;
		}

		/* Serialize the type name */
		DBG("Serializing app-specific context field event expression's "
				"type name: \"%s\"",
				field_expr->provider_name);
		ret = serialize_cstr(field_expr->type_name, buf);
		if (ret) {
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		const struct lttng_event_expr_array_field_element *elem_expr =
				container_of(expr,
					const struct lttng_event_expr_array_field_element,
					parent);
		uint32_t index = elem_expr->index;

		/* Serialize the index */
		DBG("Serializing array field element event expression's "
				"index: %u", elem_expr->index);
		ret = lttng_dynamic_buffer_append(buf, &index, sizeof(index));
		if (ret) {
			goto end;
		}

		/* Serialize the parent array field expression */
		DBG("Serializing array field element event expression's "
				"parent array field event expression.");
		ret = serialize_event_expr(elem_expr->array_field_expr, buf);
		if (ret) {
			goto end;
		}

		break;
	}
	default:
		break;
	}

end:
	return ret;
}

static
int lttng_action_notify_serialize(struct lttng_action *action,
		struct lttng_dynamic_buffer *buf)
{
	int ret = 0;
	struct lttng_action_notify *notify_action =
			container_of(action, struct lttng_action_notify,
				parent);
	uint32_t capture_descr_count = lttng_dynamic_pointer_array_get_count(
			&notify_action->capture_descriptors);
	uint32_t i;

	DBG("Serializing notify action's capture descriptor count: %" PRIu32,
			capture_descr_count);
	ret = lttng_dynamic_buffer_append(buf, &capture_descr_count,
			sizeof(capture_descr_count));
	if (ret) {
		goto end;
	}

	for (i = 0; i < capture_descr_count; i++) {
		const struct lttng_event_expr *expr =
			lttng_action_notify_get_capture_descriptor_at_index(action,
					i);

		DBG("Serializing notify action's capture descriptor %" PRIu32,
				i);
		ret = serialize_event_expr(expr, buf);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static
bool lttng_action_notify_is_equal(const struct lttng_action *action_a,
		const struct lttng_action *action_b)
{
	enum lttng_action_status status;
	bool is_equal = false;
	unsigned int capture_descr_count_a;
	unsigned int capture_descr_count_b;
	unsigned int i;

	status = lttng_action_notify_get_capture_descriptor_count(action_a, &capture_descr_count_a);
	if (status != LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	status = lttng_action_notify_get_capture_descriptor_count(action_b, &capture_descr_count_b);
	if (status != LTTNG_ACTION_STATUS_OK) {
		goto end;
	}

	if (capture_descr_count_a != capture_descr_count_b) {
		goto end;
	}

	for (i = 0; i < capture_descr_count_a; i++) {
		const struct lttng_event_expr *expr_a =
			lttng_action_notify_get_capture_descriptor_at_index(action_a,
					i);
		const struct lttng_event_expr *expr_b =
			lttng_action_notify_get_capture_descriptor_at_index(action_b,
					i);

		if (!lttng_event_expr_is_equal(expr_a, expr_b)) {
			goto end;
		}
	}

	is_equal = true;

end:
	return is_equal;
}

static
void destroy_capture_descriptor(void *ptr)
{
	struct lttng_capture_descriptor *desc =
			(struct lttng_capture_descriptor *) ptr;
	lttng_event_expr_destroy(desc->event_expression);
	free(desc);
}

struct lttng_action *lttng_action_notify_create(void)
{
	struct lttng_action_notify *notify;

	notify = zmalloc(sizeof(struct lttng_action_notify));
	if (!notify) {
		goto end;
	}

	lttng_action_init(&notify->parent, LTTNG_ACTION_TYPE_NOTIFY, NULL,
			lttng_action_notify_serialize,
			lttng_action_notify_is_equal,
			lttng_action_notify_destroy);
	lttng_dynamic_pointer_array_init(&notify->capture_descriptors,
			destroy_capture_descriptor);

end:
	return &notify->parent;
}

enum lttng_action_status lttng_action_notify_append_capture_descriptor(
		struct lttng_action *action, struct lttng_event_expr *expr)
{
	enum lttng_action_status status = LTTNG_ACTION_STATUS_OK;
	struct lttng_action_notify *notify_action =
			container_of(action, struct lttng_action_notify,
				parent);
	int ret;
	struct lttng_capture_descriptor *descriptor = NULL;

	/* Only accept l-values */
	if (!action || action->type != LTTNG_ACTION_TYPE_NOTIFY || !expr ||
			!lttng_event_expr_is_lvalue(expr)) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	descriptor = malloc(sizeof(*descriptor));
	if (descriptor == NULL) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	descriptor->capture_index = -1;
	descriptor->event_expression = expr;

	ret = lttng_dynamic_pointer_array_add_pointer(
			&notify_action->capture_descriptors, descriptor);
	if (ret) {
		status = LTTNG_ACTION_STATUS_ERROR;
		goto end;
	}

	/* Ownership is transfered to the internal capture_descriptors array */
	descriptor = NULL;

end:
	free(descriptor);
	return status;
}

enum lttng_action_status
lttng_action_notify_get_capture_descriptor_count(
		const struct lttng_action *action, unsigned int *count)
{
	enum lttng_action_status status = LTTNG_ACTION_STATUS_OK;
	const struct lttng_action_notify *notify_action =
			container_of(action, const struct lttng_action_notify,
				parent);

	if (!action || action->type != LTTNG_ACTION_TYPE_NOTIFY || !count) {
		status = LTTNG_ACTION_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(
			&notify_action->capture_descriptors);

end:
	return status;
}

const struct lttng_event_expr *
lttng_action_notify_get_capture_descriptor_at_index(
		const struct lttng_action *action, unsigned int index)
{
	const struct lttng_action_notify *notify_action =
			container_of(action, const struct lttng_action_notify,
				parent);
	struct lttng_capture_descriptor *desc = NULL;

	struct lttng_event_expr *expr = NULL;

	if (!action || action->type != LTTNG_ACTION_TYPE_NOTIFY ||
			index >= lttng_dynamic_pointer_array_get_count(
				&notify_action->capture_descriptors)) {
		goto end;
	}

	desc = lttng_dynamic_pointer_array_get_pointer(
			&notify_action->capture_descriptors, index);
	expr = desc->event_expression;
end:
	return expr;
}

static
uint64_t uint_from_buffer(const struct lttng_buffer_view *view, size_t size,
		size_t *offset)
{
	uint64_t ret;

	if (*offset + size > view->size) {
		ret = UINT64_C(-1);
		goto end;
	}

	switch (size) {
	case 1:
		ret = (uint64_t) view->data[*offset];
		break;
	case sizeof(uint32_t):
	{
		uint32_t u32;

		memcpy(&u32, &view->data[*offset], sizeof(u32));
		ret = (uint64_t) u32;
		break;
	}
	case sizeof(ret):
		memcpy(&ret, &view->data[*offset], sizeof(ret));
		break;
	default:
		abort();
	}

	*offset += size;

end:
	return ret;
}

static
const char *str_from_buffer(const struct lttng_buffer_view *view,
		size_t *offset)
{
	uint64_t len;
	const char *ret;

	len = uint_from_buffer(view, sizeof(uint32_t), offset);
	if (len == UINT64_C(-1)) {
		goto error;
	}

	ret = &view->data[*offset];

	if (!lttng_buffer_view_validate_string(view, ret, len)) {
		goto error;
	}

	*offset += len;
	goto end;

error:
	ret = NULL;

end:
	return ret;
}

static
struct lttng_event_expr *event_expr_from_buffer(
		const struct lttng_buffer_view *view, size_t *offset)
{
	struct lttng_event_expr *expr = NULL;
	const char *str;
	uint64_t type;

	type = uint_from_buffer(view, sizeof(uint8_t), offset);
	if (type == UINT64_C(-1)) {
		goto error;
	}

	switch (type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
		str = str_from_buffer(view, offset);
		if (!str) {
			goto error;
		}

		expr = lttng_event_expr_event_payload_field_create(str);
		break;
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
		str = str_from_buffer(view, offset);
		if (!str) {
			goto error;
		}

		expr = lttng_event_expr_channel_context_field_create(str);
		break;
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		const char *provider_name;
		const char *type_name;

		provider_name = str_from_buffer(view, offset);
		if (!provider_name) {
			goto error;
		}

		type_name = str_from_buffer(view, offset);
		if (!type_name) {
			goto error;
		}

		expr = lttng_event_expr_app_specific_context_field_create(
				provider_name, type_name);
		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		struct lttng_event_expr *array_field_expr;
		uint64_t index;

		index = uint_from_buffer(view, sizeof(uint32_t), offset);
		if (index == UINT64_C(-1)) {
			goto error;
		}

		/* Array field expression is the encoded after this */
		array_field_expr = event_expr_from_buffer(view, offset);
		if (!array_field_expr) {
			goto error;
		}

		/* Move ownership of `array_field_expr` to new expression */
		expr = lttng_event_expr_array_field_element_create(
				array_field_expr, (unsigned int) index);
		if (!expr) {
			/* `array_field_expr` not moved: destroy it */
			lttng_event_expr_destroy(array_field_expr);
		}

		break;
	}
	default:
		abort();
	}

	goto end;

error:
	lttng_event_expr_destroy(expr);
	expr = NULL;

end:
	return expr;
}

ssize_t lttng_action_notify_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_action **action)
{
	ssize_t consumed_length;
	size_t offset = 0;
	uint64_t capture_descr_count;
	uint64_t i;

	*action = lttng_action_notify_create();
	if (!*action) {
		goto error;
	}

	/* Capture descriptor count */
	capture_descr_count = uint_from_buffer(view, sizeof(uint32_t), &offset);
	if (capture_descr_count == UINT64_C(-1)) {
		goto error;
	}

	for (i = 0; i < capture_descr_count; i++) {
		struct lttng_event_expr *expr = event_expr_from_buffer(
				view, &offset);
		enum lttng_action_status status;

		if (!expr) {
			goto error;
		}

		/* Move ownership of `expr` to `*action` */
		status = lttng_action_notify_append_capture_descriptor(
				*action, expr);
		if (status != LTTNG_ACTION_STATUS_OK) {
			/* `expr` not moved: destroy it */
			lttng_event_expr_destroy(expr);
			goto error;
		}
	}

	consumed_length = offset;
	goto end;

error:
	lttng_action_notify_destroy(*action);
	consumed_length = -1;

end:
	return consumed_length;
}
