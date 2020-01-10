/*
 * Copyright (C) 2019 - Jonathan Rajotte-Julien <jonathan.rajotte-julien@efficios.com>
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

#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/syscall-internal.h>
#include <common/macros.h>
#include <common/error.h>
#include <assert.h>

#define IS_SYSCALL_EVENT_RULE(rule) ( \
	lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_SYSCALL \
	)

static
void lttng_event_rule_syscall_destroy(struct lttng_event_rule *rule)
{
	struct lttng_event_rule_syscall *syscall;

	syscall = container_of(rule, struct lttng_event_rule_syscall,
			parent);

	/*
	 * TODO
	 */
	free(syscall);
}

static
bool lttng_event_rule_syscall_validate(
		const struct lttng_event_rule *rule)
{
	/* TODO */
	return false;
}

static
int lttng_event_rule_syscall_serialize(
		const struct lttng_event_rule *rule,
		struct lttng_dynamic_buffer *buf)
{
	/* TODO */
	return -1;
}

static
bool lttng_event_rule_syscall_is_equal(const struct lttng_event_rule *_a,
		const struct lttng_event_rule *_b)
{
	/* TODO */
	return false;
}

struct lttng_event_rule *lttng_event_rule_syscall_create()
{
	struct lttng_event_rule_syscall *rule;

	rule = zmalloc(sizeof(struct lttng_event_rule_syscall));
	if (!rule) {
		return NULL;
	}

	lttng_event_rule_init(&rule->parent, LTTNG_EVENT_RULE_TYPE_SYSCALL);
	rule->parent.validate = lttng_event_rule_syscall_validate;
	rule->parent.serialize = lttng_event_rule_syscall_serialize;
	rule->parent.equal = lttng_event_rule_syscall_is_equal;
	rule->parent.destroy = lttng_event_rule_syscall_destroy;
	return &rule->parent;
}

LTTNG_HIDDEN
ssize_t lttng_event_rule_syscall_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_event_rule **_event_rule)
{
	/* TODO */
	return -1;
}

enum lttng_event_rule_status lttng_event_rule_syscall_set_pattern(
		struct lttng_event_rule *rule, const char *pattern)
{
	return LTTNG_EVENT_RULE_STATUS_UNSUPPORTED;
}

enum lttng_event_rule_status lttng_event_rule_syscall_get_pattern(
		const struct lttng_event_rule *rule, const char *pattern)
{
	return LTTNG_EVENT_RULE_STATUS_UNSUPPORTED;
}

enum lttng_event_rule_status lttng_event_rule_syscall_set_filter(
		struct lttng_event_rule *rule, const char *expression)
{
	return LTTNG_EVENT_RULE_STATUS_UNSUPPORTED;
}

enum lttng_event_rule_status lttng_event_rule_syscall_get_filter(
		const struct lttng_event_rule *rule, const char *expression)
{
	return LTTNG_EVENT_RULE_STATUS_UNSUPPORTED;
}