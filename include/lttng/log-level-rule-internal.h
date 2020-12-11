/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOG_LEVEL_RULE_INTERNAL_H
#define LTTNG_LOG_LEVEL_RULE_INTERNAL_H

#include <stdint.h>

#include <common/buffer-view.h>
#include <common/dynamic-array.h>
#include <common/macros.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <lttng/event.h>
#include <lttng/log-level-rule.h>

/*
 * For now only a single backing struct is used for both type of log level
 * rule (exactly, as_severe) since both only have a "level" as property.
 */
struct lttng_log_level_rule {
	enum lttng_log_level_rule_type type;

	/* Property */
	int level;
};

struct lttng_log_level_rule_comm {
	/* enum lttng_log_level_rule_type */
	int8_t type;
	int32_t level;
};

LTTNG_HIDDEN
ssize_t lttng_log_level_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_log_level_rule **rule);

LTTNG_HIDDEN
int lttng_log_level_rule_serialize(const struct lttng_log_level_rule *rule,
		struct lttng_payload *payload);

LTTNG_HIDDEN
bool lttng_log_level_rule_is_equal(const struct lttng_log_level_rule *a,
		const struct lttng_log_level_rule *b);

LTTNG_HIDDEN
struct lttng_log_level_rule *lttng_log_level_rule_copy(
		const struct lttng_log_level_rule *source);

LTTNG_HIDDEN
void lttng_log_level_rule_to_loglevel(
		const struct lttng_log_level_rule *log_level_rule,
		enum lttng_loglevel_type *loglevel_type,
		int *loglevel_value);
LTTNG_HIDDEN
unsigned long lttng_log_level_rule_hash(
		const struct lttng_log_level_rule *log_level_rule);

#endif /* LTTNG_LOG_LEVEL_RULE_INTERNAL_H */
