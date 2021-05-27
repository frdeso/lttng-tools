/*
 * Copyright (C) 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "../command.h"
#include "../loglevel.h"
#include "../uprobe.h"

#include "common/argpar/argpar.h"
#include "common/dynamic-array.h"
#include "common/string-utils/string-utils.h"
#include "common/utils.h"
/* For lttng_event_rule_type_str(). */
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/lttng.h>
#include "lttng/event-rule/kernel-function.h"
#include "lttng/event-rule/kernel-probe.h"
#include "lttng/event-rule/syscall.h"
#include <lttng/event-rule/tracepoint.h>
#include "lttng/event-rule/userspace-probe.h"
#include "lttng/kernel-function.h"
#include "lttng/kernel-probe.h"
#include "lttng/log-level-rule.h"
#include "lttng/map-key-internal.h"
#include "common/filter/filter-ast.h"
#include "common/filter/filter-ir.h"
#include "common/dynamic-array.h"

#if (LTTNG_SYMBOL_NAME_LEN == 256)
#define LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API "255"
#endif

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-add-trigger.1.h>
;
#endif

enum {
	OPT_HELP,
	OPT_LIST_OPTIONS,

	OPT_CONDITION,
	OPT_ACTION,
	OPT_ID,
	OPT_OWNER_UID,
	OPT_RATE_POLICY,

	OPT_NAME,
	OPT_FILTER,
	OPT_EXCLUDE_NAME,
	OPT_EVENT_NAME,
	OPT_LOG_LEVEL,

	OPT_DOMAIN,
	OPT_TYPE,
	OPT_LOCATION,

	OPT_MAX_SIZE,
	OPT_DATA_URL,
	OPT_CTRL_URL,
	OPT_URL,
	OPT_PATH,

	OPT_SESSION_NAME,
	OPT_MAP_NAME,
	OPT_KEY,

	OPT_CAPTURE,
};

static const struct argpar_opt_descr event_rule_opt_descrs[] = {
	{ OPT_FILTER, 'f', "filter", true },
	{ OPT_NAME, 'n', "name", true },
	{ OPT_EXCLUDE_NAME, 'x', "exclude-name", true },
	{ OPT_LOG_LEVEL, 'l', "log-level", true },
	{ OPT_EVENT_NAME, 'E', "event-name", true },

	{ OPT_DOMAIN, 'd', "domain", true },
	{ OPT_TYPE, 't', "type", true },
	{ OPT_LOCATION, 'L', "location", true },

	/* Capture descriptor */
	{ OPT_CAPTURE, '\0', "capture", true },

	ARGPAR_OPT_DESCR_SENTINEL
};

static
bool assign_domain_type(enum lttng_domain_type *dest, const char *arg)
{
	bool ret;

	if (*dest != LTTNG_DOMAIN_NONE) {
		ERR("More than one `--domain` was specified.");
		goto error;
	}

	if (strcmp(arg, "kernel") == 0) {
		*dest = LTTNG_DOMAIN_KERNEL;
	} else if (strcmp(arg, "user") == 0 || strcmp(arg, "userspace") == 0) {
		*dest = LTTNG_DOMAIN_UST;
	} else if (strcmp(arg, "jul") == 0) {
		*dest = LTTNG_DOMAIN_JUL;
	} else if (strcmp(arg, "log4j") == 0) {
		*dest = LTTNG_DOMAIN_LOG4J;
	} else if (strcmp(arg, "python") == 0) {
		*dest = LTTNG_DOMAIN_PYTHON;
	} else {
		ERR("Invalid `--domain` value: %s", arg);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

static
bool assign_event_rule_type(enum lttng_event_rule_type *dest, const char *arg)
{
	bool ret;

	if (*dest != LTTNG_EVENT_RULE_TYPE_UNKNOWN) {
		ERR("More than one `--type` was specified.");
		goto error;
	}

	if (strcmp(arg, "tracepoint") == 0 || strcmp(arg, "logging") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_TRACEPOINT;
	} else if (strcmp(arg, "kprobe") == 0 ||
			strcmp(arg, "kernel-probe") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_KERNEL_PROBE;
	} else if (strcmp(arg, "uprobe") == 0 ||
			strcmp(arg, "userspace-probe") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE;
	} else if (strcmp(arg, "function") == 0) {
		*dest = LTTNG_EVENT_RULE_TYPE_KERNEL_FUNCTION;
	} else if (strncmp(arg, "syscall", strlen("syscall")) == 0) {
		/*
		 * Matches the following:
		 *   - syscall
		 *   - syscall:entry
		 *   - syscall:exit
		 *   - syscall:entry+exit
		 *   - syscall:*
		 *
		 * Validation for the right side is left to further usage sites.
		 */
		*dest = LTTNG_EVENT_RULE_TYPE_SYSCALL;
	} else {
		ERR("Invalid `--type` value: %s", arg);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

static
bool assign_string(char **dest, const char *src, const char *opt_name)
{
	bool ret;

	if (*dest) {
		ERR("Duplicate '%s' given.", opt_name);
		goto error;
	}

	*dest = strdup(src);
	if (!*dest) {
		PERROR("Failed to allocate string '%s'.", opt_name);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

static bool parse_syscall_emission_site_from_type(const char *str,
		enum lttng_event_rule_syscall_emission_site_type *type)
{
	bool ret = false;
	if (strcmp(str, "syscall") == 0 ||
			strcmp(str, "syscall:entry+exit") == 0) {
		*type = LTTNG_EVENT_RULE_SYSCALL_EMISSION_SITE_ENTRY_EXIT;
	} else if (strcmp(str, "syscall:entry") == 0) {
		*type = LTTNG_EVENT_RULE_SYSCALL_EMISSION_SITE_ENTRY;
	} else if (strcmp(str, "syscall:exit") == 0) {
		*type = LTTNG_EVENT_RULE_SYSCALL_EMISSION_SITE_EXIT;
	} else {
		goto error;
	}

	ret = true;

error:
	return ret;
}

/*
 * Parse `str` as a log level in domain `domain_type`.
 *
 * Return the log level in `*log_level`.  Return true in `*log_level_only` if
 * the string specifies exactly this log level, false if it specifies at least
 * this log level.
 *
 * Return true if the string was successfully parsed as a log level string.
 */
static bool parse_log_level_string(const char *str,
		enum lttng_domain_type domain_type,
		int *log_level,
		bool *log_level_only)
{
	bool ret;

	switch (domain_type) {
	case LTTNG_DOMAIN_UST:
	{
		enum lttng_loglevel log_level_min, log_level_max;
		if (!loglevel_parse_range_string(
				    str, &log_level_min, &log_level_max)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_min != log_level_max &&
				log_level_max != LTTNG_LOGLEVEL_EMERG) {
			goto error;
		}

		*log_level = (int) log_level_min;
		*log_level_only = log_level_min == log_level_max;
		break;
	}
	case LTTNG_DOMAIN_LOG4J:
	{
		enum lttng_loglevel_log4j log_level_min, log_level_max;
		if (!loglevel_log4j_parse_range_string(
				    str, &log_level_min, &log_level_max)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_min != log_level_max &&
				log_level_max != LTTNG_LOGLEVEL_LOG4J_FATAL) {
			goto error;
		}

		*log_level = (int) log_level_min;
		*log_level_only = log_level_min == log_level_max;
		break;
	}
	case LTTNG_DOMAIN_JUL:
	{
		enum lttng_loglevel_jul log_level_min, log_level_max;
		if (!loglevel_jul_parse_range_string(
				    str, &log_level_min, &log_level_max)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_min != log_level_max &&
				log_level_max != LTTNG_LOGLEVEL_JUL_SEVERE) {
			goto error;
		}

		*log_level = (int) log_level_min;
		*log_level_only = log_level_min == log_level_max;
		break;
	}
	case LTTNG_DOMAIN_PYTHON:
	{
		enum lttng_loglevel_python log_level_min, log_level_max;
		if (!loglevel_python_parse_range_string(
				    str, &log_level_min, &log_level_max)) {
			goto error;
		}

		/* Only support VAL and VAL.. for now. */
		if (log_level_min != log_level_max &&
				log_level_max !=
						LTTNG_LOGLEVEL_PYTHON_CRITICAL) {
			goto error;
		}

		*log_level = (int) log_level_min;
		*log_level_only = log_level_min == log_level_max;
		break;
	}
	default:
		/* Invalid domain type. */
		abort();
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

static int parse_kernel_probe_opts(const char *source,
		struct lttng_kernel_probe_location **location)
{
	int ret = 0;
	int match;
	char s_hex[19];
	char name[LTTNG_SYMBOL_NAME_LEN];
	char *symbol_name = NULL;
	uint64_t offset;

	/* Check for symbol+offset. */
	match = sscanf(source,
			"%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API
			"[^'+']+%18s",
			name, s_hex);
	if (match == 2) {
		if (*s_hex == '\0') {
			ERR("Kernel probe symbol offset is missing.");
			goto error;
		}

		symbol_name = strndup(name, LTTNG_SYMBOL_NAME_LEN);
		if (!symbol_name) {
			PERROR("Failed to copy kernel probe location symbol name.");
			goto error;
		}
		offset = strtoul(s_hex, NULL, 0);

		*location = lttng_kernel_probe_location_symbol_create(
				symbol_name, offset);
		if (!*location) {
			ERR("Failed to create symbol kernel probe location.");
			goto error;
		}

		goto end;
	}

	/* Check for symbol. */
	if (isalpha(name[0]) || name[0] == '_') {
		match = sscanf(source,
				"%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API
				"s",
				name);
		if (match == 1) {
			symbol_name = strndup(name, LTTNG_SYMBOL_NAME_LEN);
			if (!symbol_name) {
				ERR("Failed to copy kernel probe location symbol name.");
				goto error;
			}

			*location = lttng_kernel_probe_location_symbol_create(
					symbol_name, 0);
			if (!*location) {
				ERR("Failed to create symbol kernel probe location.");
				goto error;
			}

			goto end;
		}
	}

	/* Check for address. */
	match = sscanf(source, "%18s", s_hex);
	if (match > 0) {
		uint64_t address;

		if (*s_hex == '\0') {
			ERR("Invalid kernel probe location address.");
			goto error;
		}

		address = strtoul(s_hex, NULL, 0);
		*location = lttng_kernel_probe_location_address_create(address);
		if (!*location) {
			ERR("Failed to create symbol kernel probe location.");
			goto error;
		}

		goto end;
	}

error:
	/* No match */
	ret = -1;
	*location = NULL;

end:
	free(symbol_name);
	return ret;
}

static int parse_kernel_function_opts(const char *source,
		struct lttng_kernel_function_location **location)
{
	int ret = 0;
	int match;
	char s_hex[19];
	char name[LTTNG_SYMBOL_NAME_LEN];
	char *symbol_name = NULL;
	uint64_t offset;

	/* Check for symbol+offset. */
	match = sscanf(source,
			"%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API
			"[^'+']+%18s",
			name, s_hex);
	if (match == 2) {
		if (*s_hex == '\0') {
			ERR("Kernel function symbol offset is missing.");
			goto error;
		}

		symbol_name = strndup(name, LTTNG_SYMBOL_NAME_LEN);
		if (!symbol_name) {
			PERROR("Failed to copy kernel function location symbol name.");
			goto error;
		}
		offset = strtoul(s_hex, NULL, 0);

		*location = lttng_kernel_function_location_symbol_create(
				symbol_name, offset);
		if (!*location) {
			ERR("Failed to create symbol kernel function location.");
			goto error;
		}

		goto end;
	}

	/* Check for symbol. */
	if (isalpha(name[0]) || name[0] == '_') {
		match = sscanf(source,
				"%" LTTNG_SYMBOL_NAME_LEN_SCANF_IS_A_BROKEN_API
				"s",
				name);
		if (match == 1) {
			symbol_name = strndup(name, LTTNG_SYMBOL_NAME_LEN);
			if (!symbol_name) {
				ERR("Failed to copy kernel function location symbol name.");
				goto error;
			}

			*location = lttng_kernel_function_location_symbol_create(
					symbol_name, 0);
			if (!*location) {
				ERR("Failed to create symbol kernel function location.");
				goto error;
			}

			goto end;
		}
	}

	/* Check for address. */
	match = sscanf(source, "%18s", s_hex);
	if (match > 0) {
		uint64_t address;

		if (*s_hex == '\0') {
			ERR("Invalid kernel function location address.");
			goto error;
		}

		address = strtoul(s_hex, NULL, 0);
		*location = lttng_kernel_function_location_address_create(address);
		if (!*location) {
			ERR("Failed to create symbol kernel function location.");
			goto error;
		}

		goto end;
	}

error:
	/* No match */
	ret = -1;
	*location = NULL;

end:
	free(symbol_name);
	return ret;
}

static
struct lttng_event_expr *ir_op_load_expr_to_event_expr(
		const struct ir_load_expression *load_expr,
		const char *capture_str)
{
	char *provider_name = NULL;
	struct lttng_event_expr *event_expr = NULL;
	const struct ir_load_expression_op *load_expr_op = load_expr->child;
	const enum ir_load_expression_type load_expr_child_type =
			load_expr_op->type;

	switch (load_expr_child_type) {
	case IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT:
	case IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT:
	{
		const char *field_name;

		load_expr_op = load_expr_op->next;
		assert(load_expr_op);
		assert(load_expr_op->type == IR_LOAD_EXPRESSION_GET_SYMBOL);
		field_name = load_expr_op->u.symbol;
		assert(field_name);

		event_expr = load_expr_child_type == IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT ?
				lttng_event_expr_event_payload_field_create(field_name) :
				lttng_event_expr_channel_context_field_create(field_name);
		if (!event_expr) {
			ERR("Failed to create %s event expression: field name = `%s`.",
					load_expr_child_type == IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT ?
							"payload field" : "channel context",
							field_name);
			goto error;
		}

		break;
	}
	case IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT:
	{
		const char *colon;
		const char *type_name;
		const char *field_name;

		load_expr_op = load_expr_op->next;
		assert(load_expr_op);
		assert(load_expr_op->type == IR_LOAD_EXPRESSION_GET_SYMBOL);
		field_name = load_expr_op->u.symbol;
		assert(field_name);

		/*
		 * The field name needs to be of the form PROVIDER:TYPE. We
		 * split it here.
		 */
		colon = strchr(field_name, ':');
		if (!colon) {
			ERR("Invalid app-specific context field name: missing colon in `%s`.",
					field_name);
			goto error;
		}

		type_name = colon + 1;
		if (*type_name == '\0') {
			ERR("Invalid app-specific context field name: missing type name after colon in `%s`.",
					field_name);
			goto error;
		}

		provider_name = strndup(field_name, colon - field_name);
		if (!provider_name) {
			PERROR("Failed to allocate field name string");
			goto error;
		}

		event_expr = lttng_event_expr_app_specific_context_field_create(
				provider_name, type_name);
		if (!event_expr) {
			ERR("Failed to create app-specific context field event expression: provider name = `%s`, type name = `%s`",
					provider_name, type_name);
			goto error;
		}

		break;
	}
	default:
		ERR("%s: unexpected load expr type %d.", __func__,
				load_expr_op->type);
		abort();
	}

	load_expr_op = load_expr_op->next;

	/* There may be a single array index after that. */
	if (load_expr_op->type == IR_LOAD_EXPRESSION_GET_INDEX) {
		struct lttng_event_expr *index_event_expr;
		const uint64_t index = load_expr_op->u.index;

		index_event_expr = lttng_event_expr_array_field_element_create(event_expr, index);
		if (!index_event_expr) {
			ERR("Failed to create array field element event expression.");
			goto error;
		}

		event_expr = index_event_expr;
		load_expr_op = load_expr_op->next;
	}

	switch (load_expr_op->type) {
	case IR_LOAD_EXPRESSION_LOAD_FIELD:
		/*
		 * This is what we expect, IR_LOAD_EXPRESSION_LOAD_FIELD is
		 * always found at the end of the chain.
		 */
		break;
	case IR_LOAD_EXPRESSION_GET_SYMBOL:
		ERR("While parsing expression `%s`: Capturing subfields is not supported.",
				capture_str);
		goto error;

	default:
		ERR("%s: unexpected load expression operator %s.", __func__,
				ir_load_expression_type_str(load_expr_op->type));
		abort();
	}

	goto end;

error:
	lttng_event_expr_destroy(event_expr);
	event_expr = NULL;

end:
	free(provider_name);

	return event_expr;
}

static
struct lttng_event_expr *ir_op_load_to_event_expr(
		const struct ir_op *ir, const char *capture_str)
{
	struct lttng_event_expr *event_expr = NULL;

	assert(ir->op == IR_OP_LOAD);

	switch (ir->data_type) {
	case IR_DATA_EXPRESSION:
	{
		const struct ir_load_expression *ir_load_expr =
				ir->u.load.u.expression;

		event_expr = ir_op_load_expr_to_event_expr(
				ir_load_expr, capture_str);
		break;
	}
	default:
		ERR("%s: unexpected data type: %s.", __func__,
				ir_data_type_str(ir->data_type));
		abort();
	}

	return event_expr;
}

static
const char *ir_operator_type_human_str(enum ir_op_type op)
{
	const char *name;

	switch (op) {
	case IR_OP_BINARY:
		name = "Binary";
		break;
	case IR_OP_UNARY:
		name = "Unary";
		break;
	case IR_OP_LOGICAL:
		name = "Logical";
		break;
	default:
		abort();
	}

	return name;
}

static
struct lttng_event_expr *ir_op_root_to_event_expr(const struct ir_op *ir,
		const char *capture_str)
{
	struct lttng_event_expr *event_expr = NULL;

	assert(ir->op == IR_OP_ROOT);
	ir = ir->u.root.child;

	switch (ir->op) {
	case IR_OP_LOAD:
		event_expr = ir_op_load_to_event_expr(ir, capture_str);
		break;
	case IR_OP_BINARY:
	case IR_OP_UNARY:
	case IR_OP_LOGICAL:
		ERR("While parsing expression `%s`: %s operators are not allowed in capture expressions.",
				capture_str,
				ir_operator_type_human_str(ir->op));
		break;
	default:
		ERR("%s: unexpected IR op type: %s.", __func__,
				ir_op_type_str(ir->op));
		abort();
	}

	return event_expr;
}

static
void destroy_event_expr(void *ptr)
{
	lttng_event_expr_destroy(ptr);
}

struct parse_event_rule_res {
	/* Owned by this. */
	struct lttng_event_rule *er;

	/* Array of `struct lttng_event_expr *` */
	struct lttng_dynamic_pointer_array capture_descriptors;
};

static
struct parse_event_rule_res parse_event_rule(int *argc, const char ***argv)
{
	enum lttng_domain_type domain_type = LTTNG_DOMAIN_NONE;
	enum lttng_event_rule_type event_rule_type =
			LTTNG_EVENT_RULE_TYPE_UNKNOWN;
	struct argpar_state *state;
	struct argpar_item *item = NULL;
	char *error = NULL;
	int consumed_args = -1;
	struct lttng_kernel_probe_location *kernel_probe_location = NULL;
	struct lttng_kernel_function_location *kernel_function_location = NULL;
	struct lttng_userspace_probe_location *userspace_probe_location = NULL;
	struct parse_event_rule_res res = { 0 };
	struct lttng_event_expr *event_expr = NULL;
	struct filter_parser_ctx *parser_ctx = NULL;
	struct lttng_log_level_rule *log_level_rule = NULL;

	/* Event rule type option */
	char *event_rule_type_str = NULL;

	/* Tracepoint and syscall options. */
	char *name = NULL;
	/* Array of strings. */
	struct lttng_dynamic_pointer_array exclude_names;

	/* For userspace / kernel probe and function. */
	char *location = NULL;
	char *event_name = NULL;

	/* Filter. */
	char *filter = NULL;

	/* Log level. */
	char *log_level_str = NULL;

	lttng_dynamic_pointer_array_init(&res.capture_descriptors,
				destroy_event_expr);

	lttng_dynamic_pointer_array_init(&exclude_names, free);

	state = argpar_state_create(*argc, *argv, event_rule_opt_descrs);
	if (!state) {
		ERR("Failed to allocate an argpar state.");
		goto error;
	}

	while (true) {
		enum argpar_state_parse_next_status status;

		ARGPAR_ITEM_DESTROY_AND_RESET(item);
		status = argpar_state_parse_next(state, &item, &error);
		if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR) {
			ERR("%s", error);
			goto error;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT) {
			/* Just stop parsing here. */
			break;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_END) {
			break;
		}

		assert(status == ARGPAR_STATE_PARSE_NEXT_STATUS_OK);

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_item_opt *item_opt =
					(const struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			/* Domains. */
			case OPT_DOMAIN:
				if (!assign_domain_type(&domain_type,
						item_opt->arg)) {
					goto error;
				}

				break;
			case OPT_TYPE:
				if (!assign_event_rule_type(&event_rule_type,
						item_opt->arg)) {
					goto error;
				}

				/* Save the string for later use. */
				if (!assign_string(&event_rule_type_str,
						    item_opt->arg,
						    "--type/-t")) {
					goto error;
				}

				break;
			case OPT_LOCATION:
				if (!assign_string(&location,
						item_opt->arg,
						"--location/-L")) {
					goto error;
				}

				break;
			case OPT_EVENT_NAME:
				if (!assign_string(&event_name,
						    item_opt->arg,
						    "--event-name/-E")) {
					goto error;
				}

				break;
			case OPT_FILTER:
				if (!assign_string(&filter, item_opt->arg,
						    "--filter/-f")) {
					goto error;
				}

				break;
			case OPT_NAME:
				if (!assign_string(&name, item_opt->arg,
						    "--name/-n")) {
					goto error;
				}

				break;
			case OPT_EXCLUDE_NAME:
			{
				int ret;

				ret = lttng_dynamic_pointer_array_add_pointer(
						&exclude_names,
						strdup(item_opt->arg));
				if (ret != 0) {
					ERR("Failed to add pointer to dynamic pointer array.");
					goto error;
				}

				break;
			}
			case OPT_LOG_LEVEL:
				if (!assign_string(&log_level_str,
						    item_opt->arg, "--log-level/-l")) {
					goto error;
				}

				break;
			case OPT_CAPTURE:
			{
				int ret;
				const char *capture_str = item_opt->arg;

				ret = filter_parser_ctx_create_from_filter_expression(
						capture_str, &parser_ctx);
				if (ret) {
					ERR("Failed to parse capture expression `%s`.",
							capture_str);
					goto error;
				}

				event_expr = ir_op_root_to_event_expr(
						parser_ctx->ir_root,
						capture_str);
				if (!event_expr) {
					/*
					 * ir_op_root_to_event_expr has printed
					 * an error message.
					 */
					goto error;
				}

				ret = lttng_dynamic_pointer_array_add_pointer(
						&res.capture_descriptors,
						event_expr);
				if (ret) {
					goto error;
				}

				/*
				 * The ownership of event expression was
				 * transferred to the dynamic array.
				 */
				event_expr = NULL;

				break;
			}
			default:
				abort();
			}
		} else {
			const struct argpar_item_non_opt *item_non_opt =
					(const struct argpar_item_non_opt *)
							item;

			/* Don't accept non-option arguments. */
			ERR("Unexpected argument '%s'", item_non_opt->arg);
			goto error;
		}
	}

	if (event_rule_type == LTTNG_EVENT_RULE_TYPE_UNKNOWN) {
		event_rule_type = LTTNG_EVENT_RULE_TYPE_TRACEPOINT;
	}

	/*
	 * Option --name is applicable to event rules of type tracepoint
	 * and syscall.  For tracepoint and syscall rules, if --name is
	 * omitted, it is implicitly "*".
	 */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
		if (!name) {
			name = strdup("*");
		}
		break;

	default:
		if (name) {
			ERR("Can't use --name with %s event rules.",
					lttng_event_rule_type_str(
							event_rule_type));
			goto error;
		}

		if (lttng_dynamic_pointer_array_get_count(&exclude_names) > 0) {
			ERR("Can't use --exclude-name/-x with %s event rules.",
					lttng_event_rule_type_str(
							event_rule_type));
			goto error;
		}
	}

	/*
	 * Option --location is only applicable to (and mandatory for) event
	 * rules of type {k,u}probe and function.
	 *
	 * Option --event-name is only applicable to event rules of type probe.
	 * If omitted, it defaults to the location.
	 */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_KERNEL_PROBE:
	case LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_FUNCTION:
		if (!location) {
			ERR("Event rule of type %s requires a --location.",
			lttng_event_rule_type_str(event_rule_type));
			goto error;
		}

		if (!event_name) {
			event_name = strdup(location);
		}

		break;

	default:
		if (location) {
			ERR("Can't use --location with %s event rules.",
			lttng_event_rule_type_str(event_rule_type));
			goto error;
		}

		if (event_name) {
			ERR("Can't use --event-name with %s event rules.",
					lttng_event_rule_type_str(
							event_rule_type));
			goto error;
		}
	}

	/*
	 * Update *argc and *argv so our caller can keep parsing what follows.
	 */
	consumed_args = argpar_state_get_ingested_orig_args(state);
	assert(consumed_args >= 0);
	*argc -= consumed_args;
	*argv += consumed_args;

	/* Need to specify a domain. */
	if (domain_type == LTTNG_DOMAIN_NONE) {
		ERR("Please specify a domain (--domain=(kernel,user,jul,log4j,python)).");
		goto error;
	}

	/* Validate event rule type against domain. */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_KERNEL_PROBE:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_FUNCTION:
	case LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE:
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
		if (domain_type != LTTNG_DOMAIN_KERNEL) {
			ERR("Event type not available for user-space tracing.");
			goto error;
		}
		break;

	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
		break;

	default:
		abort();
	}

	/*
	 * Adding a filter to a probe, function or userspace-probe would be
	 * denied by the kernel tracer as it's not supported at the moment. We
	 * do an early check here to warn the user.
	 */
	if (filter && domain_type == LTTNG_DOMAIN_KERNEL) {
		switch (event_rule_type) {
		case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
		case LTTNG_EVENT_RULE_TYPE_SYSCALL:
			break;
		default:
			ERR("Filter expressions are not supported for %s event rules.",
					lttng_event_rule_type_str(event_rule_type));
			goto error;
		}
	}

	/* If --exclude-name/-x was passed, split it into an exclusion list. */
	if (lttng_dynamic_pointer_array_get_count(&exclude_names) > 0) {
		if (domain_type != LTTNG_DOMAIN_UST) {
			ERR("Event name exclusions are not yet implemented for %s event rules.",
					get_domain_str(domain_type));
			goto error;
		}

		if (validate_exclusion_list(name, &exclude_names) != 0) {
			/*
			 * Assume validate_exclusion_list already prints an
			 * error message.
			 */
			goto error;
		}
	}

	if (log_level_str) {
		if (event_rule_type != LTTNG_EVENT_RULE_TYPE_TRACEPOINT) {
			ERR("Log levels are only applicable to tracepoint event rules.");
			goto error;
		}

		if (domain_type == LTTNG_DOMAIN_KERNEL) {
			ERR("Log levels are not supported by the kernel tracer.");
			goto error;
		}
	}

	/* Finally, create the event rule object. */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
	{
		enum lttng_event_rule_status event_rule_status;

		res.er = lttng_event_rule_tracepoint_create(domain_type);
		if (!res.er) {
			ERR("Failed to create tracepoint event rule.");
			goto error;
		}

		/* Set pattern. */
		event_rule_status = lttng_event_rule_tracepoint_set_pattern(
				res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set tracepoint event rule's pattern to '%s'.",
					name);
			goto error;
		}

		/* Set filter. */
		if (filter) {
			event_rule_status = lttng_event_rule_tracepoint_set_filter(
					res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set tracepoint event rule's filter to '%s'.",
						filter);
				goto error;
			}
		}

		/* Set exclusion list. */
		if (lttng_dynamic_pointer_array_get_count(&exclude_names) > 0) {
			int n;
			int count = lttng_dynamic_pointer_array_get_count(
					&exclude_names);

			for (n = 0; n < count; n++) {
				const char *exclude_name =
						lttng_dynamic_pointer_array_get_pointer(
								&exclude_names,
								n);

				event_rule_status =
						lttng_event_rule_tracepoint_add_exclusion(
								res.er,
								exclude_name);
				if (event_rule_status !=
						LTTNG_EVENT_RULE_STATUS_OK) {
					ERR("Failed to set tracepoint exclusion list element '%s'",
							exclude_name);
					goto error;
				}
			}
		}

		/*
		 * ".." is the same as passing no log level option and
		 * correspond the the "ANY" case.
		 */
		if (log_level_str && strcmp(log_level_str, "..") != 0) {
			int log_level;
			bool log_level_only;

			if (!parse_log_level_string(log_level_str, domain_type,
					    &log_level, &log_level_only)) {
				ERR("Failed to parse log level string `%s`.",
						log_level_str);
				goto error;
			}

			if (log_level_only) {
				log_level_rule = lttng_log_level_rule_exactly_create(log_level);
			} else {
				log_level_rule = lttng_log_level_rule_at_least_as_severe_as_create(log_level);
			}

			if (log_level_rule == NULL) {
				ERR("Failed to create log level rule object.");
				goto error;
			}

			event_rule_status =
					lttng_event_rule_tracepoint_set_log_level_rule(
							res.er, log_level_rule);

			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set log level on event fule.");
				goto error;
			}
		}

		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_PROBE:
	{
		int ret;
		enum lttng_event_rule_status event_rule_status;

		ret = parse_kernel_probe_opts(
				location, &kernel_probe_location);
		if (ret) {
			ERR("Failed to parse kernel probe location.");
			goto error;
		}

		assert(kernel_probe_location);
		res.er = lttng_event_rule_kernel_probe_create(kernel_probe_location);
		if (!res.er) {
			ERR("Failed to create kprobe event rule.");
			goto error;
		}

		event_rule_status =
				lttng_event_rule_kernel_probe_set_event_name(
						res.er, event_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set kprobe event rule's name to '%s'.",
					event_name);
			goto error;
		}

		break;
	}
	case LTTNG_EVENT_RULE_TYPE_KERNEL_FUNCTION:
	{
		int ret;
		enum lttng_event_rule_status event_rule_status;


		ret = parse_kernel_function_opts(source, &kernel_function_location);
		if (ret) {
			ERR("Failed to parse kernel function location.");
			goto error;
		}

		assert(kernel_function_location);
		res.er = lttng_event_rule_kernel_function_create(kernel_function_location);
		if (!res.er) {
			ERR("Failed to create kfunction event rule.");
			goto error;
		}

		event_rule_status = lttng_event_rule_kernel_function_set_event_name(res.er, tracepoint_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set kfunction event rule's name to '%s'.", tracepoint_name);
			goto error;
		}

		break;
	}
	case LTTNG_EVENT_RULE_TYPE_USERSPACE_PROBE:
	{
		int ret;
		enum lttng_event_rule_status event_rule_status;

		ret = parse_userspace_probe_opts(
				location, &userspace_probe_location);
		if (ret) {
			ERR("Failed to parse user space probe location.");
			goto error;
		}

		res.er = lttng_event_rule_userspace_probe_create(userspace_probe_location);
		if (!res.er) {
			ERR("Failed to create userspace probe event rule.");
			goto error;
		}

		event_rule_status =
				lttng_event_rule_userspace_probe_set_event_name(
						res.er, event_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set user space probe event rule's name to '%s'.",
					event_name);
			goto error;
		}

		break;
	}
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
	{
		enum lttng_event_rule_status event_rule_status;
		enum lttng_event_rule_syscall_emission_site_type emission_site_type;

		if (!parse_syscall_emission_site_from_type(
				    event_rule_type_str, &emission_site_type)) {
			ERR("Failed to parse syscall type '%s'.", event_rule_type_str);
			goto error;
		}

		res.er = lttng_event_rule_syscall_create(emission_site_type);
		if (!res.er) {
			ERR("Failed to create syscall event rule.");
			goto error;
		}

		event_rule_status = lttng_event_rule_syscall_set_pattern(
				res.er, name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set syscall event rule's pattern to '%s'.",
					name);
			goto error;
		}

		if (filter) {
			event_rule_status = lttng_event_rule_syscall_set_filter(
					res.er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set syscall event rule's filter to '%s'.",
						filter);
				goto error;
			}
		}

		break;
	}
	default:
		abort();
		goto error;
	}

	goto end;

error:
	lttng_event_rule_destroy(res.er);
	res.er = NULL;
	lttng_dynamic_pointer_array_reset(&res.capture_descriptors);

end:
	if (parser_ctx) {
		filter_parser_ctx_free(parser_ctx);
	}

	lttng_event_expr_destroy(event_expr);
	argpar_item_destroy(item);
	free(error);
	argpar_state_destroy(state);
	free(filter);
	free(name);
	lttng_dynamic_pointer_array_reset(&exclude_names);
	free(log_level_str);
	free(location);
	free(event_name);
	free(event_rule_type_str);

	lttng_kernel_probe_location_destroy(kernel_probe_location);
	lttng_userspace_probe_location_destroy(userspace_probe_location);
	lttng_log_level_rule_destroy(log_level_rule);
	return res;
}

static
struct lttng_condition *handle_condition_event(int *argc, const char ***argv)
{
	struct parse_event_rule_res res;
	struct lttng_condition *c;
	size_t i;

	res = parse_event_rule(argc, argv);
	if (!res.er) {
		c = NULL;
		goto error;
	}

	c = lttng_condition_event_rule_matches_create(res.er);
	lttng_event_rule_destroy(res.er);
	res.er = NULL;
	if (!c) {
		goto error;
	}

	for (i = 0; i < lttng_dynamic_pointer_array_get_count(&res.capture_descriptors);
			i++) {
		enum lttng_condition_status status;
		struct lttng_event_expr **expr =
				lttng_dynamic_array_get_element(
					&res.capture_descriptors.array, i);

		assert(expr);
		assert(*expr);
		status = lttng_condition_event_rule_matches_append_capture_descriptor(
				c, *expr);
		if (status != LTTNG_CONDITION_STATUS_OK) {
			if (status == LTTNG_CONDITION_STATUS_UNSUPPORTED) {
				ERR("The capture feature is unsupported by the event-rule condition type");
			}

			goto error;
		}

		/* Ownership of event expression moved to `c` */
		*expr = NULL;
	}

	goto end;

error:
	lttng_condition_destroy(c);
	c = NULL;

end:
	lttng_dynamic_pointer_array_reset(&res.capture_descriptors);
	lttng_event_rule_destroy(res.er);
	return c;
}

struct condition_descr {
	const char *name;
	struct lttng_condition *(*handler) (int *argc, const char ***argv);
};

static const
struct condition_descr condition_descrs[] = {
	{ "event-rule-matches", handle_condition_event },
};

static
struct lttng_condition *parse_condition(const char *condition_name, int *argc,
		const char ***argv)
{
	int i;
	struct lttng_condition *cond;
	const struct condition_descr *descr = NULL;

	for (i = 0; i < ARRAY_SIZE(condition_descrs); i++) {
		if (strcmp(condition_name, condition_descrs[i].name) == 0) {
			descr = &condition_descrs[i];
			break;
		}
	}

	if (!descr) {
		ERR("Unknown condition name '%s'", condition_name);
		goto error;
	}

	cond = descr->handler(argc, argv);
	if (!cond) {
		/* The handler has already printed an error message. */
		goto error;
	}

	goto end;
error:
	cond = NULL;
end:
	return cond;
}

static struct lttng_rate_policy *parse_rate_policy(const char *policy_str)
{
	int ret;
	size_t num_token = 0;
	struct lttng_dynamic_pointer_array tokens;
	struct lttng_rate_policy *policy = NULL;
	enum lttng_rate_policy_type policy_type;
	unsigned long long value;
	char *policy_type_str;
	char *policy_value_str;

	assert(policy_str);
	lttng_dynamic_pointer_array_init(&tokens, NULL);

	/* Rate policy fields are separated by ':'. */
	ret = strutils_split(policy_str, ':', 1, &tokens);
	if (ret == 0) {
		num_token = lttng_dynamic_pointer_array_get_count(&tokens);
	}

	/*
	 * Early sanity check that the number of parameter is exactly 2.
	 * i.e : type:value
	 */
	if (num_token != 2) {
		ERR("Rate policy format is invalid.");
		goto end;
	}

	policy_type_str = lttng_dynamic_pointer_array_get_pointer(&tokens, 0);
	policy_value_str = lttng_dynamic_pointer_array_get_pointer(&tokens, 1);

	/* Parse the type. */
	if (strcmp(policy_type_str, "once-after") == 0) {
		policy_type = LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N;
	} else if (strcmp(policy_type_str, "every") == 0) {
		policy_type = LTTNG_RATE_POLICY_TYPE_EVERY_N;
	} else {
		ERR("Rate policy type `%s` unknown.", policy_type_str);
		goto end;
	}

	/* Parse the value. */
	if (utils_parse_unsigned_long_long(policy_value_str, &value) != 0) {
		ERR("Failed to parse rate policy value `%s` as an integer.",
				policy_value_str);
		goto end;
	}

	if (value == 0) {
		ERR("Rate policy value `%s` must be > 0.", policy_value_str);
		goto end;
	}

	switch (policy_type) {
	case LTTNG_RATE_POLICY_TYPE_EVERY_N:
		policy = lttng_rate_policy_every_n_create(value);
		break;
	case LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N:
		policy = lttng_rate_policy_once_after_n_create(value);
		break;
	default:
		abort();
	}

	if (policy == NULL) {
		ERR("Failed to create rate policy `%s`.", policy_str);
	}

end:
	lttng_dynamic_pointer_array_reset(&tokens);
	return policy;
}

static const struct argpar_opt_descr notify_action_opt_descrs[] = {
	{ OPT_RATE_POLICY, '\0', "rate-policy", true },
	ARGPAR_OPT_DESCR_SENTINEL
};

static
struct lttng_action *handle_action_notify(int *argc, const char ***argv)
{
	struct lttng_action *action = NULL;
	struct argpar_state *state = NULL;
	struct argpar_item *item = NULL;
	char *error = NULL;
	struct lttng_rate_policy *policy = NULL;

	state = argpar_state_create(*argc, *argv, notify_action_opt_descrs);
	if (!state) {
		ERR("Failed to allocate an argpar state.");
		goto error;
	}

	while (true) {
		enum argpar_state_parse_next_status status;

		ARGPAR_ITEM_DESTROY_AND_RESET(item);
		status = argpar_state_parse_next(state, &item, &error);
		if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR) {
			ERR("%s", error);
			goto error;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT) {
			/* Just stop parsing here. */
			break;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_END) {
			break;
		}

		assert(status == ARGPAR_STATE_PARSE_NEXT_STATUS_OK);

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_item_opt *item_opt =
					(const struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_RATE_POLICY:
			{
				policy = parse_rate_policy(item_opt->arg);
				if (!policy) {
					goto error;
				}
				break;
			}
			default:
				abort();
			}
		} else {
			const struct argpar_item_non_opt *item_non_opt;

			assert(item->type == ARGPAR_ITEM_TYPE_NON_OPT);

			item_non_opt = (const struct argpar_item_non_opt *) item;

			switch (item_non_opt->non_opt_index) {
			default:
				ERR("Unexpected argument `%s`.",
						item_non_opt->arg);
				goto error;
			}
		}
	}

	*argc -= argpar_state_get_ingested_orig_args(state);
	*argv += argpar_state_get_ingested_orig_args(state);

	action = lttng_action_notify_create();
	if (!action) {
		ERR("Failed to create notify action");
		goto error;
	}

	if (policy) {
		enum lttng_action_status status;
		status = lttng_action_notify_set_rate_policy(action, policy);
		if (status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to set rate policy");
			goto error;
		}
	}

	goto end;

error:
	lttng_action_destroy(action);
	action = NULL;
end:
	free(error);
	lttng_rate_policy_destroy(policy);
	argpar_state_destroy(state);
	argpar_item_destroy(item);
	return action;
}

/*
 * Generic handler for a kind of action that takes a session name and an
 * optional rate policy.
 */

static struct lttng_action *handle_action_simple_session_with_policy(int *argc,
		const char ***argv,
		struct lttng_action *(*create_action_cb)(void),
		enum lttng_action_status (*set_session_name_cb)(
				struct lttng_action *, const char *),
		enum lttng_action_status (*set_rate_policy_cb)(
				struct lttng_action *,
				const struct lttng_rate_policy *),
		const char *action_name)
{
	struct lttng_action *action = NULL;
	struct argpar_state *state = NULL;
	struct argpar_item *item = NULL;
	const char *session_name_arg = NULL;
	char *error = NULL;
	enum lttng_action_status action_status;
	struct lttng_rate_policy *policy = NULL;

	assert(set_session_name_cb);
	assert(set_rate_policy_cb);

	const struct argpar_opt_descr rate_policy_opt_descrs[] = {
		{ OPT_RATE_POLICY, '\0', "rate-policy", true },
		ARGPAR_OPT_DESCR_SENTINEL
	};

	state = argpar_state_create(*argc, *argv, rate_policy_opt_descrs);
	if (!state) {
		ERR("Failed to allocate an argpar state.");
		goto error;
	}

	while (true) {
		enum argpar_state_parse_next_status status;

		ARGPAR_ITEM_DESTROY_AND_RESET(item);
		status = argpar_state_parse_next(state, &item, &error);
		if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR) {
			ERR("%s", error);
			goto error;
		} else if (status ==
				ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT) {
			/* Just stop parsing here. */
			break;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_END) {
			break;
		}

		assert(status == ARGPAR_STATE_PARSE_NEXT_STATUS_OK);
		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_item_opt *item_opt =
					(const struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_RATE_POLICY:
			{
				policy = parse_rate_policy(item_opt->arg);
				if (!policy) {
					goto error;
				}
				break;
			}
			default:
				abort();
			}
		} else {
			const struct argpar_item_non_opt *item_non_opt;
			item_non_opt = (const struct argpar_item_non_opt *) item;

			switch (item_non_opt->non_opt_index) {
			case 0:
				session_name_arg = item_non_opt->arg;
				break;
			default:
				ERR("Unexpected argument `%s`.",
						item_non_opt->arg);
				goto error;
			}
		}
	}

	*argc -= argpar_state_get_ingested_orig_args(state);
	*argv += argpar_state_get_ingested_orig_args(state);

	if (!session_name_arg) {
		ERR("Missing session name.");
		goto error;
	}

	action = create_action_cb();
	if (!action) {
		ERR("Failed to allocate %s session action.", action_name);
		goto error;
	}

	action_status = set_session_name_cb(action, session_name_arg);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to set action %s session's session name to '%s'.",
				action_name, session_name_arg);
		goto error;
	}

	if (policy) {
		action_status = set_rate_policy_cb(action, policy);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to set rate policy");
			goto error;
		}
	}

	goto end;

error:
	lttng_action_destroy(action);
	action = NULL;
	argpar_item_destroy(item);
end:
	lttng_rate_policy_destroy(policy);
	free(error);
	argpar_state_destroy(state);
	return action;
}

static
struct lttng_action *handle_action_start_session(int *argc,
		const char ***argv)
{
	return handle_action_simple_session_with_policy(argc, argv,
			lttng_action_start_session_create,
			lttng_action_start_session_set_session_name,
			lttng_action_start_session_set_rate_policy, "start");
}

static
struct lttng_action *handle_action_stop_session(int *argc,
		const char ***argv)
{
	return handle_action_simple_session_with_policy(argc, argv,
			lttng_action_stop_session_create,
			lttng_action_stop_session_set_session_name,
			lttng_action_stop_session_set_rate_policy, "stop");
}

static
struct lttng_action *handle_action_rotate_session(int *argc,
		const char ***argv)
{
	return handle_action_simple_session_with_policy(argc, argv,
		lttng_action_rotate_session_create,
		lttng_action_rotate_session_set_session_name,
		lttng_action_rotate_session_set_rate_policy,
		"rotate");
}

static const struct argpar_opt_descr snapshot_action_opt_descrs[] = {
	{ OPT_NAME, 'n', "name", true },
	{ OPT_MAX_SIZE, 'm', "max-size", true },
	{ OPT_CTRL_URL, '\0', "ctrl-url", true },
	{ OPT_DATA_URL, '\0', "data-url", true },
	{ OPT_URL, '\0', "url", true },
	{ OPT_PATH, '\0', "path", true },
	{ OPT_RATE_POLICY, '\0', "rate-policy", true },
	ARGPAR_OPT_DESCR_SENTINEL
};

static
struct lttng_action *handle_action_snapshot_session(int *argc,
		const char ***argv)
{
	struct lttng_action *action = NULL;
	struct argpar_state *state = NULL;
	struct argpar_item *item = NULL;
	const char *session_name_arg = NULL;
	char *snapshot_name_arg = NULL;
	char *ctrl_url_arg = NULL;
	char *data_url_arg = NULL;
	char *max_size_arg = NULL;
	char *url_arg = NULL;
	char *path_arg = NULL;
	char *error = NULL;
	enum lttng_action_status action_status;
	struct lttng_snapshot_output *snapshot_output = NULL;
	struct lttng_rate_policy *policy = NULL;
	int ret;
	unsigned int locations_specified = 0;

	state = argpar_state_create(*argc, *argv, snapshot_action_opt_descrs);
	if (!state) {
		ERR("Failed to allocate an argpar state.");
		goto error;
	}

	while (true) {
		enum argpar_state_parse_next_status status;

		ARGPAR_ITEM_DESTROY_AND_RESET(item);
		status = argpar_state_parse_next(state, &item, &error);
		if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR) {
			ERR("%s", error);
			goto error;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT) {
			/* Just stop parsing here. */
			break;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_END) {
			break;
		}

		assert(status == ARGPAR_STATE_PARSE_NEXT_STATUS_OK);

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			const struct argpar_item_opt *item_opt =
					(const struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_NAME:
				if (!assign_string(&snapshot_name_arg, item_opt->arg, "--name/-n")) {
					goto error;
				}

				break;
			case OPT_MAX_SIZE:
				if (!assign_string(&max_size_arg, item_opt->arg, "--max-size/-m")) {
					goto error;
				}

				break;
			case OPT_CTRL_URL:
				if (!assign_string(&ctrl_url_arg, item_opt->arg, "--ctrl-url")) {
					goto error;
				}

				break;
			case OPT_DATA_URL:
				if (!assign_string(&data_url_arg, item_opt->arg, "--data-url")) {
					goto error;
				}

				break;
			case OPT_URL:
				if (!assign_string(&url_arg, item_opt->arg, "--url")) {
					goto error;
				}

				break;
			case OPT_PATH:
				if (!assign_string(&path_arg, item_opt->arg, "--path")) {
					goto error;
				}

				break;
			case OPT_RATE_POLICY:
			{
				policy = parse_rate_policy(item_opt->arg);
				if (!policy) {
					goto error;
				}
				break;
			}
			default:
				abort();
			}
		} else {
			const struct argpar_item_non_opt *item_non_opt;

			assert(item->type == ARGPAR_ITEM_TYPE_NON_OPT);

			item_non_opt = (const struct argpar_item_non_opt *) item;

			switch (item_non_opt->non_opt_index) {
			case 0:
				session_name_arg = item_non_opt->arg;
				break;
			default:
				ERR("Unexpected argument `%s`.",
						item_non_opt->arg);
				goto error;
			}
		}
	}

	*argc -= argpar_state_get_ingested_orig_args(state);
	*argv += argpar_state_get_ingested_orig_args(state);

	if (!session_name_arg) {
		ERR("Missing session name.");
		goto error;
	}

	/* --ctrl-url and --data-url must come in pair. */
	if (ctrl_url_arg && !data_url_arg) {
		ERR("--ctrl-url is specified, but --data-url is missing.");
		goto error;
	}

	if (!ctrl_url_arg && data_url_arg) {
		ERR("--data-url is specified, but --ctrl-url is missing.");
		goto error;
	}

	locations_specified += !!(ctrl_url_arg || data_url_arg);
	locations_specified += !!url_arg;
	locations_specified += !!path_arg;

	/* --ctrl-url/--data-url, --url and --path are mutually exclusive. */
	if (locations_specified > 1) {
		ERR("The --ctrl-url/--data-url, --url, and --path options can't be used together.");
		goto error;
	}

	/*
	 * Did the user specify an option that implies using a
	 * custom/unregistered output?
	 */
	if (url_arg || ctrl_url_arg || path_arg) {
		snapshot_output = lttng_snapshot_output_create();
		if (!snapshot_output) {
			ERR("Failed to allocate a snapshot output.");
			goto error;
		}
	}

	action = lttng_action_snapshot_session_create();
	if (!action) {
		ERR("Failed to allocate snapshot session action.");
		goto error;
	}

	action_status = lttng_action_snapshot_session_set_session_name(
			action, session_name_arg);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to set action snapshot session's session name to '%s'.",
				session_name_arg);
		goto error;
	}

	if (snapshot_name_arg) {
		if (!snapshot_output) {
			ERR("Can't provide a snapshot output name without a snapshot output destination.");
			goto error;
		}

		ret = lttng_snapshot_output_set_name(
				snapshot_name_arg, snapshot_output);
		if (ret != 0) {
			ERR("Failed to set name of snapshot output.");
			goto error;
		}
	}

	if (max_size_arg) {
		uint64_t max_size;

		if (!snapshot_output) {
			ERR("Can't provide a snapshot output max size without a snapshot output destination.");
			goto error;
		}

		ret = utils_parse_size_suffix(max_size_arg, &max_size);
		if (ret != 0) {
			ERR("Failed to parse `%s` as a size.", max_size_arg);
			goto error;
		}

		ret = lttng_snapshot_output_set_size(max_size, snapshot_output);
		if (ret != 0) {
			ERR("Failed to set snapshot output's max size to %" PRIu64 " bytes.",
					max_size);
			goto error;
		}
	}

	if (url_arg) {
		int num_uris;
		struct lttng_uri *uris;

		if (!strstr(url_arg, "://")) {
			ERR("Failed to parse '%s' as an URL.", url_arg);
			goto error;
		}

		num_uris = uri_parse_str_urls(url_arg, NULL, &uris);
		if (num_uris < 1) {
			ERR("Failed to parse '%s' as an URL.", url_arg);
			goto error;
		}

		if (uris[0].dtype == LTTNG_DST_PATH) {
			ret = lttng_snapshot_output_set_local_path(
					uris[0].dst.path, snapshot_output);
			free(uris);
			if (ret != 0) {
				ERR("Failed to assign '%s' as a local destination.",
						url_arg);
				goto error;
			}
		} else {
			ret = lttng_snapshot_output_set_network_url(
					url_arg, snapshot_output);
			free(uris);
			if (ret != 0) {
				ERR("Failed to assign '%s' as a network URL.",
						url_arg);
				goto error;
			}
		}
	}

	if (path_arg) {
		ret = lttng_snapshot_output_set_local_path(
				path_arg, snapshot_output);
		if (ret != 0) {
			ERR("Failed to parse '%s' as a local path.", path_arg);
			goto error;
		}
	}

	if (ctrl_url_arg) {
		/*
		 * Two argument form, network output with separate control and
		 * data URLs.
		 */
		ret = lttng_snapshot_output_set_network_urls(
				ctrl_url_arg, data_url_arg, snapshot_output);
		if (ret != 0) {
			ERR("Failed to parse `%s` and `%s` as control and data URLs.",
					ctrl_url_arg, data_url_arg);
			goto error;
		}
	}

	if (snapshot_output) {
		action_status = lttng_action_snapshot_session_set_output(
				action, snapshot_output);
		if (action_status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to set snapshot session action's output.");
			goto error;
		}

		/* Ownership of `snapshot_output` has been transferred to the action. */
		snapshot_output = NULL;
	}

	if (policy) {
		enum lttng_action_status status;
		status = lttng_action_snapshot_session_set_rate_policy(
				action, policy);
		if (status != LTTNG_ACTION_STATUS_OK) {
			ERR("Failed to set rate policy");
			goto error;
		}
	}

	goto end;

error:
	lttng_action_destroy(action);
	action = NULL;
	free(error);
end:
	free(snapshot_name_arg);
	free(path_arg);
	free(url_arg);
	free(ctrl_url_arg);
	free(data_url_arg);
	free(snapshot_output);
	free(max_size_arg);
	lttng_rate_policy_destroy(policy);
	argpar_state_destroy(state);
	argpar_item_destroy(item);
	return action;
}

static const struct argpar_opt_descr incr_value_action_opt_descrs[] = {
	{ OPT_SESSION_NAME, 's', "session", true },
	{ OPT_MAP_NAME, 'm', "map", true },
	{ OPT_KEY, '\0', "key", true },
	ARGPAR_OPT_DESCR_SENTINEL
};

static
struct lttng_action *handle_action_incr_value(int *argc,
		const char ***argv)
{
	struct lttng_action *action = NULL;
	struct argpar_state *state = NULL;
	struct argpar_item *item = NULL;
	struct lttng_map_key *key = NULL;
	char *session_name_arg = NULL, *map_name_arg = NULL;
	char *key_arg = NULL;
	char *error = NULL;
	enum lttng_action_status action_status;

	state = argpar_state_create(*argc, *argv, incr_value_action_opt_descrs);
	if (!state) {
		ERR("Failed to allocate an argpar state.");
		goto error;
	}

	while (true) {
		enum argpar_state_parse_next_status status;

		ARGPAR_ITEM_DESTROY_AND_RESET(item);
		status = argpar_state_parse_next(state, &item, &error);
		if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR) {
			ERR("%s", error);
			goto error;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT) {
			/* Just stop parsing here. */
			break;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_END) {
			break;
		}

		assert(status == ARGPAR_STATE_PARSE_NEXT_STATUS_OK);

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			struct argpar_item_opt *item_opt =
				(struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_SESSION_NAME:
				if (!assign_string(&session_name_arg, item_opt->arg, "--session/-s")) {
					goto error;
				}
				break;
			case OPT_MAP_NAME:
				if (!assign_string(&map_name_arg, item_opt->arg, "--map/-m")) {
					goto error;
				}
				break;
			case OPT_KEY:
				if (!assign_string(&key_arg, item_opt->arg, "--key")) {
					goto error;
				}
				break;
			default:
				abort();
			}
		}
	}

	*argc -= argpar_state_get_ingested_orig_args(state);
	*argv += argpar_state_get_ingested_orig_args(state);

	if (!session_name_arg) {
		ERR("Missing session name.");
		goto error;
	}

	if (!map_name_arg) {
		ERR("Missing map name.");
		goto error;
	}

	if (!key_arg) {
		ERR("Missing key");
		goto error;
	}

	key = lttng_map_key_parse_from_string(key_arg);
	if (!key) {
		ERR("Error parsing key argument");
		goto error;
	}

	action = lttng_action_incr_value_create();
	if (!action) {
		ERR("Failed to allocate incr-value action.");
		goto error;
	}

	action_status = lttng_action_incr_value_set_session_name(action,
			session_name_arg);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to set action incr-value's session name.");
		goto error;
	}

	action_status = lttng_action_incr_value_set_map_name(action,
			map_name_arg);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to set action incr-value's map name.");
		goto error;
	}

	action_status = lttng_action_incr_value_set_key(action, key);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR("Failed to set action incr-value's key");
		goto error;
	}

	goto end;

error:
	lttng_action_destroy(action);
	action = NULL;

end:
	lttng_map_key_destroy(key);
	free(session_name_arg);
	free(map_name_arg);
	free(key_arg);
	return action;
}

struct action_descr {
	const char *name;
	struct lttng_action *(*handler) (int *argc, const char ***argv);
};

static const
struct action_descr action_descrs[] = {
	{ "notify", handle_action_notify },
	{ "start-session", handle_action_start_session },
	{ "stop-session", handle_action_stop_session },
	{ "rotate-session", handle_action_rotate_session },
	{ "snapshot-session", handle_action_snapshot_session },
	{ "incr-value", handle_action_incr_value },
};

static
struct lttng_action *parse_action(const char *action_name, int *argc, const char ***argv)
{
	int i;
	struct lttng_action *action;
	const struct action_descr *descr = NULL;

	for (i = 0; i < ARRAY_SIZE(action_descrs); i++) {
		if (strcmp(action_name, action_descrs[i].name) == 0) {
			descr = &action_descrs[i];
			break;
		}
	}

	if (!descr) {
		ERR("Unknown action name: %s", action_name);
		goto error;
	}

	action = descr->handler(argc, argv);
	if (!action) {
		/* The handler has already printed an error message. */
		goto error;
	}

	goto end;
error:
	action = NULL;
end:
	return action;
}

static const
struct argpar_opt_descr add_trigger_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_LIST_OPTIONS, '\0', "list-options", false },
	{ OPT_CONDITION, '\0', "condition", true },
	{ OPT_ACTION, '\0', "action", true },
	{ OPT_NAME, '\0', "name", true },
	{ OPT_OWNER_UID, '\0', "owner-uid", true },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static
bool action_is_tracer_executed(const struct lttng_action *action)
{
	bool is_tracer_executed;
	switch (lttng_action_get_type(action)) {
	case LTTNG_ACTION_TYPE_NOTIFY:
	case LTTNG_ACTION_TYPE_START_SESSION:
	case LTTNG_ACTION_TYPE_STOP_SESSION:
	case LTTNG_ACTION_TYPE_ROTATE_SESSION:
	case LTTNG_ACTION_TYPE_SNAPSHOT_SESSION:
		is_tracer_executed = false;
		goto end;
	case LTTNG_ACTION_TYPE_INCREMENT_VALUE:
		is_tracer_executed = true;
		goto end;
	case LTTNG_ACTION_TYPE_GROUP:
	default:
		abort();
	}

end:
	return is_tracer_executed;
}

static
void lttng_actions_destructor(void *p)
{
	struct lttng_action *action = p;

	lttng_action_destroy(action);
}

int cmd_add_trigger(int argc, const char **argv)
{
	int ret;
	int my_argc = argc - 1;
	const char **my_argv = argv + 1;
	struct lttng_condition *condition = NULL;
	struct lttng_dynamic_pointer_array actions;
	struct argpar_state *argpar_state = NULL;
	struct argpar_item *argpar_item = NULL;
	struct lttng_action *action_list = NULL;
	struct lttng_action *action = NULL;
	struct lttng_trigger *trigger = NULL;
	char *error = NULL;
	char *name = NULL;
	int i;
	char *owner_uid = NULL;
	enum lttng_error_code ret_code;

	lttng_dynamic_pointer_array_init(&actions, lttng_actions_destructor);

	while (true) {
		enum argpar_state_parse_next_status status;
		const struct argpar_item_opt *item_opt;
		int ingested_args;

		argpar_state_destroy(argpar_state);
		argpar_state = argpar_state_create(my_argc, my_argv,
			add_trigger_options);
		if (!argpar_state) {
			ERR("Failed to create argpar state.");
			goto error;
		}

		ARGPAR_ITEM_DESTROY_AND_RESET(argpar_item);
		status = argpar_state_parse_next(argpar_state, &argpar_item, &error);
		if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR) {
			ERR("%s", error);
			goto error;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT) {
			ERR("%s", error);
			goto error;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_END) {
			break;
		}

		assert(status == ARGPAR_STATE_PARSE_NEXT_STATUS_OK);

		if (argpar_item->type == ARGPAR_ITEM_TYPE_NON_OPT) {
			const struct argpar_item_non_opt *item_non_opt =
					(const struct argpar_item_non_opt *)
							argpar_item;

			ERR("Unexpected argument `%s`.", item_non_opt->arg);
			goto error;
		}

		item_opt = (const struct argpar_item_opt *) argpar_item;

		ingested_args = argpar_state_get_ingested_orig_args(
				argpar_state);

		my_argc -= ingested_args;
		my_argv += ingested_args;

		switch (item_opt->descr->id) {
		case OPT_HELP:
			SHOW_HELP();
			ret = 0;
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options_argpar(stdout, add_trigger_options);
			ret = 0;
			goto end;
		case OPT_CONDITION:
		{
			if (condition) {
				ERR("A --condition was already given.");
				goto error;
			}

			condition = parse_condition(item_opt->arg, &my_argc, &my_argv);
			if (!condition) {
				/*
				 * An error message was already printed by
				 * parse_condition.
				 */
				goto error;
			}

			break;
		}
		case OPT_ACTION:
		{
			action = parse_action(item_opt->arg, &my_argc, &my_argv);
			if (!action) {
				/*
				 * An error message was already printed by
				 * parse_condition.
				 */
				goto error;
			}

			ret = lttng_dynamic_pointer_array_add_pointer(
					&actions, action);
			if (ret) {
				ERR("Failed to add pointer to pointer array.");
				goto error;
			}

			/* Ownership of the action was transferred to the group. */
			action = NULL;

			break;
		}
		case OPT_NAME:
		{
			if (!assign_string(&name, item_opt->arg, "--name")) {
				goto error;
			}

			break;
		}
		case OPT_OWNER_UID:
		{
			if (!assign_string(&owner_uid, item_opt->arg,
					"--owner-uid")) {
				goto error;
			}

			break;
		}
		default:
			abort();
		}
	}

	if (!condition) {
		ERR("Missing --condition.");
		goto error;
	}

	if (lttng_dynamic_pointer_array_get_count(&actions) == 0) {
		ERR("Need at least one --action.");
		goto error;
	}

	action_list = lttng_action_list_create();
	if (!action_list) {
		goto error;
	}

	for (i = 0; i < lttng_dynamic_pointer_array_get_count(&actions); i++) {
		enum lttng_action_status status;

		action = lttng_dynamic_pointer_array_steal_pointer(&actions, i);
		if (action_is_tracer_executed(action)) {
			if (fire_every_str || fire_once_after_str) {
				/*
				 * Firing policy with tracer-executed actions
				 * (`incr-value`) is not supported at the
				 * moment. It's not clear how the tracers will
				 * handle the different policies efficiently.
				 */
				ERR("Can't use --fire-once-after or --fire-every with tracer executed action (incr-value)");
				goto error;
			}
		}

		status = lttng_action_list_add_action(action_list, action);
		if (status != LTTNG_ACTION_STATUS_OK) {
			goto error;
		}

		/*
		 * The `lttng_action_list_add_action()` takes a reference to
		 * the action. We can destroy ours.
		 */
		lttng_action_destroy(action);
		action = NULL;
	}

	trigger = lttng_trigger_create(condition, action_list);
	if (!trigger) {
		goto error;
	}

	if (owner_uid) {
		enum lttng_trigger_status trigger_status;
		char *end;
		long long uid;

		errno = 0;
		uid = strtol(owner_uid, &end, 10);
		if (end == owner_uid || *end != '\0' || errno != 0) {
			ERR("Failed to parse `%s` as a user id.", owner_uid);
			goto error;
		}

		trigger_status = lttng_trigger_set_owner_uid(trigger, uid);
		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			ERR("Failed to set trigger's user identity.");
			goto error;
		}
	}

	if (name) {
		ret_code = lttng_register_trigger_with_name(trigger, name);
	} else {
		ret_code = lttng_register_trigger_with_automatic_name(trigger);
	}

	if (ret_code != LTTNG_OK) {
		ERR("Failed to register trigger: %s.",
				lttng_strerror(-ret_code));
		goto error;
	}

	MSG("Trigger registered successfully.");
	ret = 0;

	goto end;

error:
	ret = 1;

end:
	argpar_state_destroy(argpar_state);
	argpar_item_destroy(argpar_item);
	lttng_dynamic_pointer_array_reset(&actions);
	lttng_condition_destroy(condition);
	lttng_action_destroy(action_list);
	lttng_action_destroy(action);
	lttng_trigger_destroy(trigger);
	free(error);
	free(name);
	free(owner_uid);
	return ret;
}
