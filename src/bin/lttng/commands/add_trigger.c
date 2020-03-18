#include <stdio.h>

#include "../command.h"
#include "../uprobe.h"

#include "common/argpar/argpar.h"
#include "common/dynamic-array.h"
#include "common/string-utils/string-utils.h"
#include "common/utils.h"
#include "lttng/condition/event-rule.h"
#include "lttng/event-internal.h"
#include "lttng/event-expr.h"
#include <lttng/event-rule/event-rule-internal.h>
#include "lttng/event-rule/kprobe.h"
#include "lttng/event-rule/syscall.h"
#include <lttng/event-rule/tracepoint.h>
#include "lttng/event-rule/uprobe.h"
#include "common/filter/filter-ast.h"
#include "common/filter/filter-ir.h"

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
	OPT_FIRE_ONCE_AFTER,
	OPT_FIRE_EVERY,

	OPT_ALL,
	OPT_FILTER,
	OPT_EXCLUDE,
	OPT_LOGLEVEL,
	OPT_LOGLEVEL_ONLY,

	OPT_USERSPACE,
	OPT_KERNEL,
	OPT_LOG4J,
	OPT_JUL,
	OPT_PYTHON,

	OPT_FUNCTION,
	OPT_PROBE,
	OPT_USERSPACE_PROBE,
	OPT_SYSCALL,
	OPT_TRACEPOINT,

	OPT_NAME,
	OPT_MAX_SIZE,
	OPT_DATA_URL,
	OPT_CTRL_URL,

	OPT_CAPTURE,
};

static const struct argpar_opt_descr event_rule_opt_descrs[] = {
	{ OPT_ALL, 'a', "all", false },
	{ OPT_FILTER, 'f', "filter", true },
	{ OPT_EXCLUDE, 'x', "exclude", true },
	{ OPT_LOGLEVEL, '\0', "loglevel", true },
	{ OPT_LOGLEVEL_ONLY, '\0', "loglevel-only", true },

	/* Domains */
	{ OPT_USERSPACE, 'u', "userspace", false },
	{ OPT_KERNEL, 'k', "kernel", false },
	{ OPT_LOG4J, 'l', "log4j", false },
	{ OPT_JUL, 'j', "jul", false },
	{ OPT_PYTHON, 'p', "python", false },

	/* Event rule types */
	{ OPT_FUNCTION, '\0', "function", true },
	{ OPT_PROBE, '\0', "probe", true },
	{ OPT_USERSPACE_PROBE, '\0', "userspace-probe", true },
	{ OPT_SYSCALL, '\0', "syscall" },
	{ OPT_TRACEPOINT, '\0', "tracepoint" },

	ARGPAR_OPT_DESCR_SENTINEL
};

static
bool assign_domain_type(enum lttng_domain_type *dest,
		enum lttng_domain_type src)
{
	bool ret;

	if (*dest == LTTNG_DOMAIN_NONE || *dest == src) {
		*dest = src;
		ret = true;
	} else {
		ERR("Multiple domains specified.");
		ret = false;
	}

	return ret;
}

static
bool assign_event_rule_type(enum lttng_event_rule_type *dest,
		enum lttng_event_rule_type src)
{
	bool ret;

	if (*dest == LTTNG_EVENT_RULE_TYPE_UNKNOWN || *dest == src) {
		*dest = src;
		ret = true;
	} else {
		ERR("Multiple event type not supported.");
		ret = false;
	}

	return ret;
}

static
bool assign_string(char **dest, const char *src, const char *opt_name)
{
	bool ret;

	if (*dest) {
		ERR(
			"Duplicate %s given.", opt_name);
		goto error;
	}

	*dest = strdup(src);
	if (!*dest) {
		ERR("Failed to allocate %s string.", opt_name);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

/* This is defined in enable_events.c. */
LTTNG_HIDDEN
int create_exclusion_list_and_validate(const char *event_name,
		const char *exclusions_arg,
		char ***exclusion_list);

/*
 * Parse `str` as a log level in domain `domain_type`.  Return -1 if the string
 * is not recognized as a valid log level.
 */
static
int parse_loglevel_string(const char *str, enum lttng_domain_type domain_type)
{

	switch (domain_type) {
	case LTTNG_DOMAIN_UST:
		return loglevel_str_to_value(str);

	case LTTNG_DOMAIN_LOG4J:
		return loglevel_log4j_str_to_value(str);

	case LTTNG_DOMAIN_JUL:
		return loglevel_jul_str_to_value(str);

	case LTTNG_DOMAIN_PYTHON:
		return loglevel_python_str_to_value(str);

	default:
		/* Invalid domain type. */
		abort();
	}
}

static
struct lttng_event_rule *parse_event_rule(int *argc, const char ***argv)
{
	struct lttng_event_rule *er = NULL;
	enum lttng_domain_type domain_type = LTTNG_DOMAIN_NONE;
	enum lttng_event_rule_type event_rule_type = LTTNG_EVENT_RULE_TYPE_UNKNOWN;
	struct argpar_state *state;
	struct argpar_item *item = NULL;
	char *error = NULL;
	int consumed_args = -1;
	struct lttng_userspace_probe_location *userspace_probe_location = NULL;

	/* Was the -a/--all flag provided? */
	bool all_events = false;

	/* Tracepoint name (non-option argument) */
	const char *tracepoint_name = NULL;

	/* Holds the argument of --probe / --userspace-probe. */
	char *source = NULL;

	/* Filter */
	char *filter = NULL;

	/* Exclude */
	char *exclude = NULL;
	char **exclusion_list = NULL;

	/* Log level */
	char *loglevel_str = NULL;
	bool loglevel_only = false;

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
			struct argpar_item_opt *item_opt =
				(struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			/* Domains */
			case OPT_USERSPACE:
				if (!assign_domain_type(&domain_type, LTTNG_DOMAIN_UST)) {
					goto error;
				}
				break;

			case OPT_KERNEL:
				if (!assign_domain_type(&domain_type, LTTNG_DOMAIN_KERNEL)) {
					goto error;
				}
				break;

			case OPT_LOG4J:
				if (!assign_domain_type(&domain_type, LTTNG_DOMAIN_LOG4J)) {
					goto error;
				}
				break;

			case OPT_JUL:
				if (!assign_domain_type(&domain_type, LTTNG_DOMAIN_JUL)) {
					goto error;
				}
				break;

			case OPT_PYTHON:
				if (!assign_domain_type(&domain_type, LTTNG_DOMAIN_PYTHON)) {
					goto error;
				}
				break;

			/* Event rule types */
			case OPT_FUNCTION:
				if (!assign_event_rule_type(&event_rule_type,
						LTTNG_EVENT_RULE_TYPE_KRETPROBE)) {
					goto error;
				}
				break;

			case OPT_PROBE:
				if (!assign_event_rule_type(&event_rule_type,
						LTTNG_EVENT_RULE_TYPE_KPROBE)) {
					goto error;
				}

				if (!assign_string(&source, item_opt->arg, "source")) {
					goto error;
				}

				break;

			case OPT_USERSPACE_PROBE:
				if (!assign_event_rule_type(&event_rule_type,
						LTTNG_EVENT_RULE_TYPE_UPROBE)) {
					goto error;
				}

				if (!assign_string(&source, item_opt->arg, "source")) {
						goto error;
				}
				break;

			case OPT_SYSCALL:
				if (!assign_event_rule_type(&event_rule_type,
						LTTNG_EVENT_RULE_TYPE_SYSCALL)) {
					goto error;
				}
				break;

			case OPT_TRACEPOINT:
				if (!assign_event_rule_type(&event_rule_type,
						LTTNG_EVENT_RULE_TYPE_TRACEPOINT)) {
					goto error;
				}
				break;

			case OPT_ALL:
				all_events = true;
				break;

			case OPT_FILTER:
				if (!assign_string(&filter, item_opt->arg, "--filter/-f")) {
					goto error;
				}
				break;

			case OPT_EXCLUDE:
				if (!assign_string(&exclude, item_opt->arg, "--exclude/-x")) {
					goto error;
				}
				break;

			case OPT_LOGLEVEL:
			case OPT_LOGLEVEL_ONLY:
				if (!assign_string(&loglevel_str, item_opt->arg, "--loglevel/--loglevel-only")) {
					goto error;
				}

				loglevel_only = item_opt->descr->id == OPT_LOGLEVEL_ONLY;
				break;

			default:
				abort();
			}
		} else {
			struct argpar_item_non_opt *item_non_opt =
				(struct argpar_item_non_opt *) item;

			/*
			 * Don't accept two non-option arguments/tracepoint
			 * names.
			 */
			if (tracepoint_name) {
				ERR(
					"Unexpected argument: %s",
					item_non_opt->arg);
				goto error;
			}

			tracepoint_name = item_non_opt->arg;
		}
	}

	if (event_rule_type == LTTNG_EVENT_RULE_TYPE_UNKNOWN) {
		event_rule_type = LTTNG_EVENT_RULE_TYPE_TRACEPOINT;
	}

	/*
	 * Option -a is applicable to event rules of type tracepoint and
	 * syscall, and it is equivalent to using "*" as the tracepoint name.
	 */
	if (all_events) {
		switch (event_rule_type) {
		case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
		case LTTNG_EVENT_RULE_TYPE_SYSCALL:
			break;
		default:
			ERR("Can't use -a/--all with event rule of type %s.",
				lttng_event_rule_type_str(event_rule_type));
			goto error;
		}

		if (tracepoint_name) {
			ERR("Can't provide a tracepoint name with -a/--all.");
			goto error;
		}

		/* In which case, it's equivalent to tracepoint name "*". */
		tracepoint_name = "*";
	}

	/*
	 * A tracepoint name (or -a, for the event rule types that accept it)
	 * is required.
	 */
	if (!tracepoint_name) {
		ERR("Need to provide either a tracepoint name or -a/--all.");
		goto error;
	}

	/*
	 * We don't support multiple tracepoint names for now.
	 */
	if (strchr(tracepoint_name, ',')) {
		ERR("multiple tracepoint names are not supported at the moment.");
		goto error;
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
		ERR("Please specify a domain (-k/-u/-j).");
		goto error;
	}

	/* Validate event rule type against domain. */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_KPROBE:
	case LTTNG_EVENT_RULE_TYPE_KRETPROBE:
	case LTTNG_EVENT_RULE_TYPE_UPROBE:
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
		if (domain_type != LTTNG_DOMAIN_KERNEL) {
			ERR("Event type not available for user-space tracing");
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
			ERR("Filter expressions are not supported for %s events",
					lttng_event_rule_type_str(event_rule_type));
			goto error;
		}
	}

	/* If --exclude/-x was passed, split it into an exclusion list. */
	if (exclude) {
		if (domain_type != LTTNG_DOMAIN_UST) {
			ERR("Event name exclusions are not yet implemented for %s events",
						get_domain_str(domain_type));
			goto error;
		}


		if (create_exclusion_list_and_validate(tracepoint_name, exclude,
				&exclusion_list) != 0) {
			ERR("Failed to create exclusion list.");
			goto error;
		}
	}

	if (loglevel_str && event_rule_type != LTTNG_EVENT_RULE_TYPE_TRACEPOINT) {
		ERR("Log levels are only application to tracepoint event rules.");
		goto error;
	}

	/* Finally, create the event rule object. */
	switch (event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
	{
		enum lttng_event_rule_status event_rule_status;

		er = lttng_event_rule_tracepoint_create(domain_type);
		if (!er) {
			ERR("Failed to create tracepoint event rule.");
			goto error;
		}

		/* Set pattern. */
		event_rule_status =
			lttng_event_rule_tracepoint_set_pattern(er, tracepoint_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set tracepoint pattern.");
			goto error;
		}

		/* Set filter. */
		if (filter) {
			event_rule_status =
				lttng_event_rule_tracepoint_set_filter(
					er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set tracepoint filter expression.");
				goto error;
			}
		}

		/* Set exclusion list. */
		if (exclusion_list) {
			int n;

			/* Count number of items in exclusion list. */
			for (n = 0; exclusion_list[n]; n++);

			event_rule_status =
				lttng_event_rule_tracepoint_set_exclusions(er,
					n, (const char **) exclusion_list);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set tracepoint exclusion list.");
				goto error;
			}
		}

		if (loglevel_str) {
			int loglevel;

			if (domain_type == LTTNG_DOMAIN_KERNEL) {
				ERR("Log levels are not supported by the kernel tracer.");
				goto error;
			}

			loglevel = parse_loglevel_string(
				loglevel_str, domain_type);
			if (loglevel < 0) {
				ERR("Failed to parse `%s` as a log level.", loglevel_str);
				goto error;
			}

			if (loglevel_only) {
				event_rule_status =
					lttng_event_rule_tracepoint_set_loglevel(
						er, loglevel);
			} else {
				event_rule_status =
					lttng_event_rule_tracepoint_set_loglevel_range(
						er, loglevel);
			}

			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set log level.");
				goto error;
			}
		}

		break;
	}

	case LTTNG_EVENT_RULE_TYPE_KPROBE:
	{
		enum lttng_event_rule_status event_rule_status;

		er = lttng_event_rule_kprobe_create();
		if (!er) {
			ERR("Failed to create kprobe event rule.");
			goto error;
		}

		event_rule_status = lttng_event_rule_kprobe_set_name(er, tracepoint_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set kprobe event rule's name.");
			goto error;
		}

		assert(source);
		event_rule_status = lttng_event_rule_kprobe_set_source(er, source);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set kprobe event rule's source.");
			goto error;
		}

		break;
	}

	case LTTNG_EVENT_RULE_TYPE_UPROBE:
	{
		int ret;
		enum lttng_event_rule_status event_rule_status;

		ret = parse_userspace_probe_opts(source, &userspace_probe_location);
		if (ret) {
			ERR("Failed to parse userspace probe location.");
			goto error;
		}

		er = lttng_event_rule_uprobe_create();
		if (!er) {
			ERR("Failed to create userspace probe event rule.");
			goto error;
		}

		event_rule_status = lttng_event_rule_uprobe_set_location(er, userspace_probe_location);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set userspace probe event rule's location.");
			goto error;
		}

		event_rule_status = lttng_event_rule_uprobe_set_name(er, tracepoint_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set userspace probe event rule's name.");
			goto error;
		}

		break;
	}

	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
	{
		enum lttng_event_rule_status event_rule_status;

		er = lttng_event_rule_syscall_create();
		if (!er) {
			ERR("Failed to create syscall event rule.");
			goto error;
		}

		event_rule_status = lttng_event_rule_syscall_set_pattern(er, tracepoint_name);
		if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
			ERR("Failed to set syscall event rule's pattern.");
			goto error;
		}

		if (filter) {
			event_rule_status = lttng_event_rule_syscall_set_filter(
					er, filter);
			if (event_rule_status != LTTNG_EVENT_RULE_STATUS_OK) {
				ERR("Failed to set syscall event rule's filter expression.");
				goto error;
			}
		}

		break;
	}

	default:
		ERR("%s: I don't support event rules of type `%s` at the moment.", __func__,
			lttng_event_rule_type_str(event_rule_type));
		goto error;
	}

	goto end;

error:
	lttng_event_rule_destroy(er);
	er = NULL;

end:
	argpar_item_destroy(item);
	free(error);
	argpar_state_destroy(state);
	free(filter);
	free(exclude);
	free(loglevel_str);
	strutils_free_null_terminated_array_of_strings(exclusion_list);
	lttng_userspace_probe_location_destroy(userspace_probe_location);
	return er;
}

static
struct lttng_condition *handle_condition_event(int *argc, const char ***argv)
{
	struct lttng_event_rule *er;
	struct lttng_condition *c;

	er = parse_event_rule(argc, argv);
	if (!er) {
		c = NULL;
		goto end;
	}

	c = lttng_condition_event_rule_create(er);
	if (!c) {
		goto end;
	}

end:
	return c;
}

static
struct lttng_condition *handle_condition_session_consumed_size(int *argc, const char ***argv)
{
	struct lttng_condition *cond = NULL;
	struct argpar_state *state = NULL;
	struct argpar_item *item = NULL;
	const char *threshold_arg = NULL;
	const char *session_name_arg = NULL;
	uint64_t threshold;
	char *error = NULL;
	enum lttng_condition_status condition_status;

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
			struct argpar_item_opt *item_opt =
				(struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			default:
				abort();
			}
		} else {
			struct argpar_item_non_opt *item_non_opt;

			assert(item->type == ARGPAR_ITEM_TYPE_NON_OPT);

			item_non_opt = (struct argpar_item_non_opt *) item;

			switch (item_non_opt->non_opt_index) {
			case 0:
				session_name_arg = item_non_opt->arg;
				break;
			case 1:
				threshold_arg = item_non_opt->arg;
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
		ERR("Missing session name argument.");
		goto error;
	}

	if (!threshold_arg) {
		ERR("Missing threshold argument.");
		goto error;
	}

	if (utils_parse_size_suffix(threshold_arg, &threshold) != 0) {
		ERR("Failed to parse `%s` as a size.", threshold_arg);
		goto error;
	}

	cond = lttng_condition_session_consumed_size_create();
	if (!cond) {
		ERR("Failed to allocate a session consumed size condition.");
		goto error;
	}

	condition_status = lttng_condition_session_consumed_size_set_session_name(
		cond, session_name_arg);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set session consumed size condition session name.");
		goto error;
	}


	condition_status = lttng_condition_session_consumed_size_set_threshold(
		cond, threshold);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set session consumed size condition threshold.");
		goto error;
	}

	goto end;

error:
	lttng_condition_destroy(cond);
	cond = NULL;

end:
	argpar_state_destroy(state);
	argpar_item_destroy(item);
	free(error);
	return cond;
}

static
struct lttng_condition *handle_condition_buffer_usage_high(int *argc, const char ***argv)
{
	struct lttng_condition *cond = NULL;
	struct argpar_state *state = NULL;
	struct argpar_item *item = NULL;
	const char *threshold_arg = NULL;
	const char *session_name_arg = NULL;
	uint64_t threshold;
	char *error = NULL;
	enum lttng_condition_status condition_status;

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
			struct argpar_item_opt *item_opt =
				(struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			default:
				abort();
			}
		} else {
			struct argpar_item_non_opt *item_non_opt;

			assert(item->type == ARGPAR_ITEM_TYPE_NON_OPT);

			item_non_opt = (struct argpar_item_non_opt *) item;

			switch (item_non_opt->non_opt_index) {
			case 0:
				session_name_arg = item_non_opt->arg;
				break;
			case 1:
				threshold_arg = item_non_opt->arg;
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
		ERR("Missing session name argument.");
		goto error;
	}

	if (!threshold_arg) {
		ERR("Missing threshold argument.");
		goto error;
	}

	if (utils_parse_size_suffix(threshold_arg, &threshold) != 0) {
		ERR("Failed to parse `%s` as a size.", threshold_arg);
		goto error;
	}

	cond = lttng_condition_session_consumed_size_create();
	if (!cond) {
		ERR("Failed to allocate a session consumed size condition.");
		goto error;
	}

	condition_status = lttng_condition_session_consumed_size_set_session_name(
		cond, session_name_arg);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set session consumed size condition session name.");
		goto error;
	}

	condition_status = lttng_condition_session_consumed_size_set_threshold(
		cond, threshold);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to set session consumed size condition threshold.");
		goto error;
	}

	goto end;

error:
	lttng_condition_destroy(cond);
	cond = NULL;

end:
	argpar_state_destroy(state);
	argpar_item_destroy(item);
	free(error);
	return cond;
}

static
struct lttng_condition *handle_condition_buffer_usage_low(int *argc, const char ***argv)
{
	return NULL;
}

static
struct lttng_condition *handle_condition_session_rotation_ongoing(int *argc, const char ***argv)
{
	return NULL;
}

static
struct lttng_condition *handle_condition_session_rotation_completed(int *argc, const char ***argv)
{
	return NULL;
}

struct condition_descr {
	const char *name;
	struct lttng_condition *(*handler) (int *argc, const char ***argv);
};

static const
struct condition_descr condition_descrs[] = {
	{ "on-event", handle_condition_event },
	{ "on-session-consumed-size", handle_condition_session_consumed_size },
	{ "on-buffer-usage-high", handle_condition_buffer_usage_high },
	{ "on-buffer-usage-low", handle_condition_buffer_usage_low },
	{ "on-session-rotation-ongoing", handle_condition_session_rotation_ongoing },
	{ "on-session-rotation-completed", handle_condition_session_rotation_completed },
};

static
struct lttng_condition *parse_condition(int *argc, const char ***argv)
{
	int i;
	struct lttng_condition *cond;
	const char *condition_name;
	const struct condition_descr *descr = NULL;

	if (*argc == 0) {
		ERR("Missing condition name.");
		goto error;
	}

	condition_name = (*argv)[0];

	(*argc)--;
	(*argv)++;

	for (i = 0; i < ARRAY_SIZE(condition_descrs); i++) {
		if (strcmp(condition_name, condition_descrs[i].name) == 0) {
			descr = &condition_descrs[i];
			break;
		}
	}

	if (!descr) {
		ERR("Unknown condition name: %s", condition_name);
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

static
struct lttng_event_expr *ir_op_load_expr_to_event_expr(
		struct ir_load_expression *load_exp)
{
	struct ir_load_expression_op *load_expr_op = load_exp->child;
	struct lttng_event_expr *event_expr = NULL;
	char *provider_name = NULL;

	switch (load_expr_op->type) {
	case IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT:
	{
		const char *field_name;

		load_expr_op = load_expr_op->next;
		assert(load_expr_op);
		assert(load_expr_op->type == IR_LOAD_EXPRESSION_GET_SYMBOL);
		field_name = load_expr_op->u.symbol;
		assert(field_name);

		event_expr = lttng_event_expr_event_payload_field_create(field_name);
		if (!event_expr) {
			fprintf(stderr, "Failed to create payload field event expression.\n");
			goto error;
		}

		break;
	}

	case IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT:
	{
		const char *field_name;

		load_expr_op = load_expr_op->next;
		assert(load_expr_op);
		assert(load_expr_op->type == IR_LOAD_EXPRESSION_GET_SYMBOL);
		field_name = load_expr_op->u.symbol;
		assert(field_name);

		event_expr = lttng_event_expr_channel_context_field_create(field_name);
		if (!event_expr) {
			fprintf(stderr, "Failed to create channel context field event expression.\n");
			goto error;
		}

		break;
	}

	case IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT:
	{
		const char *field_name;
		const char *colon;
		const char *type_name;

		load_expr_op = load_expr_op->next;
		assert(load_expr_op);
		assert(load_expr_op->type == IR_LOAD_EXPRESSION_GET_SYMBOL);
		field_name = load_expr_op->u.symbol;
		assert(field_name);

		/*
		 * The field name needs to be of the form PROVIDER:TYPE.  We
		 * split it here.
		 */
		colon = strchr(field_name, ':');
		if (!colon) {
			fprintf(stderr, "Invalid app-specific context field name: missing colon in `%s`.\n",
				field_name);
			goto error;
		}

		type_name = colon + 1;
		if (*type_name == '\0') {
			fprintf(stderr,
				"Invalid app-specific context field name: missing type name after colon in `%s`.\n",
				field_name);
			goto error;
		}

		provider_name = strndup(field_name, colon - field_name);
		if (!provider_name) {
			fprintf(stderr, "Failed to allocate string.\n");
			goto error;
		}

		event_expr = lttng_event_expr_app_specific_context_field_create(
			provider_name, type_name);
		if (!event_expr) {
			fprintf(stderr,
				"Failed to create app-specific context field event expression.\n");
			goto error;
		}

		break;
	}

	default:
		fprintf(stderr, "%s: unexpected load expr type %d.\n",
			__func__, load_expr_op->type);
		abort();
	}

	load_expr_op = load_expr_op->next;

	/* There may be a single array index after that.  */
	if (load_expr_op->type == IR_LOAD_EXPRESSION_GET_INDEX) {
		uint64_t index = load_expr_op->u.index;
		struct lttng_event_expr *index_event_expr;

		index_event_expr = lttng_event_expr_array_field_element_create(event_expr, index);
		if (!index_event_expr) {
			fprintf(stderr, "Failed to create array field element event expression.\n");
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
		fprintf(stderr, "Capturing subfields is not supported.\n");
		goto error;

	default:
		fprintf(stderr, "%s: unexpected load expression operator %s.\n",
			__func__, ir_load_expression_type_str(load_expr_op->type));
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
struct lttng_event_expr *ir_op_load_to_event_expr(struct ir_op *ir)
{
	struct lttng_event_expr *event_expr = NULL;

	assert(ir->op == IR_OP_LOAD);

	switch (ir->data_type) {
	case IR_DATA_EXPRESSION:
	{
		struct ir_load_expression *ir_load_expr = ir->u.load.u.expression;
		event_expr = ir_op_load_expr_to_event_expr(ir_load_expr);
		break;
	}

	default:
		fprintf(stderr, "%s: unexpected data type: %s.\n", __func__,
			ir_data_type_str(ir->data_type));
		abort();
	}

	return event_expr;
}

static
struct lttng_event_expr *ir_op_root_to_event_expr(struct ir_op *ir)
{
	struct lttng_event_expr *event_expr = NULL;

	assert(ir->op == IR_OP_ROOT);
	ir = ir->u.root.child;

	switch (ir->op) {
	case IR_OP_LOAD:
		event_expr = ir_op_load_to_event_expr(ir);
		break;

	case IR_OP_BINARY:
		fprintf(stderr, "Binary operators are not allowed in capture expressions.\n");
		break;

	case IR_OP_UNARY:
		fprintf(stderr, "Unary operators are not allowed in capture expressions.\n");
		break;

	case IR_OP_LOGICAL:
		fprintf(stderr, "Logical operators are not allowed in capture expressions.\n");
		break;

	default:
		fprintf(stderr, "%s: unexpected IR op type: %s.\n", __func__,
			ir_op_type_str(ir->op));
		abort();
	}

	return event_expr;
}

static
const struct argpar_opt_descr notify_action_opt_descrs[] = {
	{ OPT_CAPTURE, '\0', "capture", true },
	ARGPAR_OPT_DESCR_SENTINEL
};

static
struct lttng_action *handle_action_notify(int *argc, const char ***argv)
{
	struct lttng_action *action = NULL;
	struct argpar_state *argpar_state = NULL;
	struct argpar_item *argpar_item = NULL;
	char *error = NULL;
	struct filter_parser_ctx *parser_ctx = NULL;
	struct lttng_event_expr *event_expr = NULL;

	action = lttng_action_notify_create();

	argpar_state = argpar_state_create(*argc, *argv, notify_action_opt_descrs);
	if (!argpar_state) {
		fprintf(stderr, "Failed to allocate an argpar state.\n");
		goto error;
	}

	while (true) {
		enum argpar_state_parse_next_status status;
		struct argpar_item_opt *item_opt;

		ARGPAR_ITEM_DESTROY_AND_RESET(argpar_item);
		status = argpar_state_parse_next(argpar_state, &argpar_item, &error);
		if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR) {
			fprintf(stderr, "Error: %s\n", error);
			goto error;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_ERROR_UNKNOWN_OPT) {
			/* Just stop parsing here. */
			break;
		} else if (status == ARGPAR_STATE_PARSE_NEXT_STATUS_END) {
			break;
		}

		assert(status == ARGPAR_STATE_PARSE_NEXT_STATUS_OK);

		if (argpar_item->type == ARGPAR_ITEM_TYPE_NON_OPT) {
			struct argpar_item_non_opt *item_non_opt =
				(struct argpar_item_non_opt *) argpar_item;

			ERR("Unexpected argument `%s`.", item_non_opt->arg);
			goto error;
		}

		assert(argpar_item->type == ARGPAR_ITEM_TYPE_OPT);

		item_opt = (struct argpar_item_opt *) argpar_item;

		switch (item_opt->descr->id) {
		case OPT_CAPTURE:
		{
			const char *capture_str = item_opt->arg;
			int ret;
			enum lttng_action_status action_status;

			ret = filter_parser_ctx_create_from_filter_expression(
				capture_str, &parser_ctx);
			if (ret) {
				fprintf(stderr, "Failed to parse capture expression `%s`.\n", capture_str);
				goto error;
			}

			event_expr = ir_op_root_to_event_expr(parser_ctx->ir_root);
			if (!event_expr) {
				/* ir_op_root_to_event_expr has printed an error message. */
				goto error;
			}

			action_status = lttng_action_notify_append_capture_descriptor(
				action, event_expr);
			if (action_status) {
				fprintf(stderr, "Failed to append capture descriptor to notify action.\n");
				goto error;
			}

			/* The ownership of event expression was transferred to the action. */
			event_expr = NULL;

			break;
		}
		default:
			abort();
		}
	}

	*argc -= argpar_state_get_ingested_orig_args(argpar_state);
	*argv += argpar_state_get_ingested_orig_args(argpar_state);

	goto end;

error:
	lttng_action_destroy(action);
	action = NULL;

end:
	lttng_event_expr_destroy(event_expr);
	if (parser_ctx) {
		filter_parser_ctx_free(parser_ctx);
	}
	argpar_item_destroy(argpar_item);
	argpar_state_destroy(argpar_state);
	free(error);

	return action;
}

static const struct argpar_opt_descr no_opt_descrs[] = {
	ARGPAR_OPT_DESCR_SENTINEL
};

/*
 * Generic handler for a kind of action that takes a session name as its sole
 * argument.
 */

static
struct lttng_action *handle_action_simple_session(
		int *argc, const char ***argv,
		struct lttng_action *(*create_action_cb)(void),
		enum lttng_action_status (*set_session_name_cb)(struct lttng_action *, const char *),
		const char *action_name)
{
	struct lttng_action *action = NULL;
	struct argpar_state *state = NULL;
	struct argpar_item *item = NULL;
	const char *session_name_arg = NULL;
	char *error = NULL;
	enum lttng_action_status action_status;

	state = argpar_state_create(*argc, *argv, no_opt_descrs);
	if (!state) {
		ERR("Failed to allocate an argpar state.");
		goto error;
	}

	while (true) {
		enum argpar_state_parse_next_status status;
		struct argpar_item_non_opt *item_non_opt;

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
		assert(item->type == ARGPAR_ITEM_TYPE_NON_OPT);

		item_non_opt = (struct argpar_item_non_opt *) item;

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

	*argc -= argpar_state_get_ingested_orig_args(state);
	*argv += argpar_state_get_ingested_orig_args(state);

	if (!session_name_arg) {
		ERR("Missing session name.");
		goto error;
	}

	action = create_action_cb();
	if (!action) {
		ERR(
			"Failed to allocate %s session action.", action_name);
		goto error;
	}

	action_status = set_session_name_cb(action, session_name_arg);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR(
			"Failed to set action %s session's session name.",
			action_name);
		goto error;
	}

	goto end;

error:
	lttng_action_destroy(action);
	action = NULL;

end:
	return action;
}

static
struct lttng_action *handle_action_start_session(int *argc,
		const char ***argv)
{
	return handle_action_simple_session(argc, argv,
		lttng_action_start_session_create,
		lttng_action_start_session_set_session_name,
		"start");
}

static
struct lttng_action *handle_action_stop_session(int *argc,
		const char ***argv)
{
	return handle_action_simple_session(argc, argv,
		lttng_action_stop_session_create,
		lttng_action_stop_session_set_session_name,
		"stop");
}

static
struct lttng_action *handle_action_rotate_session(int *argc,
		const char ***argv)
{
	return handle_action_simple_session(argc, argv,
		lttng_action_rotate_session_create,
		lttng_action_rotate_session_set_session_name,
		"rotate");
}

static const struct argpar_opt_descr snapshot_action_opt_descrs[] = {
	{ OPT_NAME, 'n', "name", true },
	{ OPT_MAX_SIZE, 'm', "max-size", true },
	{ OPT_CTRL_URL, '\0', "ctrl-url", true },
	{ OPT_DATA_URL, '\0', "data-url", true },
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
	const char *url_arg = NULL;
	char *error = NULL;
	enum lttng_action_status action_status;
	struct lttng_snapshot_output *snapshot_output = NULL;
	int ret;

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
			struct argpar_item_opt *item_opt =
				(struct argpar_item_opt *) item;

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

			default:
				abort();
			}
		} else {
			struct argpar_item_non_opt *item_non_opt;

			assert(item->type == ARGPAR_ITEM_TYPE_NON_OPT);

			item_non_opt = (struct argpar_item_non_opt *) item;

			switch (item_non_opt->non_opt_index) {
			case 0:
				session_name_arg = item_non_opt->arg;
				break;

			// FIXME: the use of a non-option argument for this is to
			// follow the syntax of `lttng snapshot record`.  But otherwise,
			// I think an option argument would be best.
			case 1:
				url_arg = item_non_opt->arg;
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

	/* --ctrl-url/--data-url and the non-option URL are mutually exclusive. */
	if (ctrl_url_arg && url_arg) {
		ERR("Both --ctrl-url/--data-url and the non-option URL argument "
				"can't be used together.");
		goto error;
	}

	/*
	 * Did the user specify an option that implies using a
	 * custom/unregistered output?
	 */
	if (url_arg || ctrl_url_arg) {
		snapshot_output = lttng_snapshot_output_create();
		if (!snapshot_output) {
			ERR("Failed to allocate a snapshot output.");
			goto error;
		}
	}

	action = lttng_action_snapshot_session_create();
	if (!action) {
		ERR(
			"Failed to allocate snapshot session action.");
		goto error;
	}

	action_status = lttng_action_snapshot_session_set_session_name(
		action, session_name_arg);
	if (action_status != LTTNG_ACTION_STATUS_OK) {
		ERR(
			"Failed to set action snapshot session's session name.");
		goto error;
	}

	if (snapshot_name_arg) {
		if (!snapshot_output) {
			ERR("Can't provide a snapshot output name without a snapshot output destination.");
			goto error;
		}

		ret = lttng_snapshot_output_set_name(snapshot_name_arg, snapshot_output);
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
			ERR("Failed to set snapshot output's max size.");
			goto error;
		}
	}

	if (url_arg) {
		/* One argument form, either net:// / net6:// or a local file path. */

		if (strncmp(url_arg, "net://", strlen("net://")) == 0 ||
				strncmp(url_arg, "net6://", strlen("net6://")) == 0) {
			ret = lttng_snapshot_output_set_network_url(
				url_arg, snapshot_output);
			if (ret != 0) {
				ERR("Failed to parse %s as a network URL.", url_arg);
				goto error;
			}
		} else {
			ret = lttng_snapshot_output_set_local_path(
				url_arg, snapshot_output);
			if (ret != 0) {
				ERR("Failed to parse %s as a local path.", url_arg);
				goto error;
			}
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

	goto end;

error:
	lttng_action_destroy(action);
	action = NULL;

end:
	free(snapshot_name_arg);
	free(ctrl_url_arg);
	free(data_url_arg);
	free(snapshot_output);
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
};

static
struct lttng_action *parse_action(int *argc, const char ***argv)
{
	int i;
	struct lttng_action *action;
	const char *action_name;
	const struct action_descr *descr = NULL;

	if (*argc == 0) {
		ERR("Missing action name.");
		goto error;
	}

	action_name = (*argv)[0];

	(*argc)--;
	(*argv)++;

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
	{ OPT_CONDITION, '\0', "condition", false },
	{ OPT_ACTION, '\0', "action", false },
	{ OPT_ID, '\0', "id", true },
	{ OPT_FIRE_ONCE_AFTER, '\0', "fire-once-after", true },
	{ OPT_FIRE_EVERY, '\0', "fire-every", true },
	ARGPAR_OPT_DESCR_SENTINEL,
};

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
	struct lttng_action *action_group = NULL;
	struct lttng_action *action = NULL;
	struct lttng_trigger *trigger = NULL;
	char *error = NULL;
	char *id = NULL;
	int i;
	char *fire_once_after_str = NULL;
	char *fire_every_str = NULL;

	lttng_dynamic_pointer_array_init(&actions, lttng_actions_destructor);

	while (true) {
		enum argpar_state_parse_next_status status;
		struct argpar_item_opt *item_opt;
		int ingested_args;

		argpar_state_destroy(argpar_state);
		argpar_state = argpar_state_create(my_argc, my_argv,
			add_trigger_options);
		if (!argpar_state) {
			ERR("Failed to create argpar state.");
			goto error;
		}

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
			struct argpar_item_non_opt *item_non_opt =
				(struct argpar_item_non_opt *) argpar_item;

			ERR("Unexpected argument `%s`.",
				item_non_opt->arg);
			goto error;
		}

		item_opt = (struct argpar_item_opt *) argpar_item;

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

			condition = parse_condition(&my_argc, &my_argv);
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
			action = parse_action(&my_argc, &my_argv);
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

		case OPT_ID:
		{
			if (!assign_string(&id, item_opt->arg, "--id")) {
				goto error;
			}

			break;
		}

		case OPT_FIRE_ONCE_AFTER:
		{
			if (!assign_string(&fire_once_after_str, item_opt->arg,
					"--fire-once-after")) {
				goto error;
			}
			break;
		}

		case OPT_FIRE_EVERY:
		{
			if (!assign_string(&fire_every_str, item_opt->arg,
					"--fire-every")) {
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

	if (fire_every_str && fire_once_after_str) {
		ERR("Can't specify both --fire-once-after and --fire-every.");
		goto error;
	}

	action_group = lttng_action_group_create();
	if (!action_group) {
		goto error;
	}

	for (i = 0; i < lttng_dynamic_pointer_array_get_count(&actions); i++) {
		enum lttng_action_status status;

		action = lttng_dynamic_pointer_array_steal_pointer(&actions, i);

		status = lttng_action_group_add_action(
			action_group, action);
		if (status != LTTNG_ACTION_STATUS_OK) {
			goto error;
		}

		/* Ownership of the action was transferred to the group. */
		action = NULL;
	}


	trigger = lttng_trigger_create(condition, action_group);
	if (!trigger) {
		goto error;
	}

	/*
	 * Ownership of the condition and action group was transferred to the
	 * trigger.
	 */
	condition = NULL;
	action_group = NULL;

	if (id) {
		enum lttng_trigger_status trigger_status =
			lttng_trigger_set_name(trigger, id);
		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			ERR("Failed to set trigger id.");
			goto error;
		}
	}

	if (fire_once_after_str) {
		unsigned long long threshold;
		enum lttng_trigger_status trigger_status;

		if (utils_parse_unsigned_long_long(fire_once_after_str, &threshold) != 0) {
			ERR("Failed to parse `%s` as an integer.", fire_once_after_str);
			goto error;
		}

		trigger_status = lttng_trigger_set_firing_policy(trigger,
			LTTNG_TRIGGER_FIRE_ONCE_AFTER_N, threshold);
		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			ERR("Failed to set trigger's firing policy.");
			goto error;
		}
	}

	if (fire_every_str) {
		unsigned long long threshold;
		enum lttng_trigger_status trigger_status;

		if (utils_parse_unsigned_long_long(fire_every_str, &threshold) != 0) {
			ERR("Failed to parse `%s` as an integer.", fire_every_str);
			goto error;
		}

		trigger_status = lttng_trigger_set_firing_policy(trigger,
			LTTNG_TRIGGER_FIRE_EVERY_N, threshold);
		if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
			ERR("Failed to set trigger's firing policy.");
			goto error;
		}
	}

	ret = lttng_register_trigger(trigger);
	if (ret) {
		ERR("Failed to register trigger: %s.",
			lttng_strerror(ret));
		goto error;
	}

	MSG("Trigger registered successfully.");

	goto end;

error:
	ret = 1;

end:
	argpar_state_destroy(argpar_state);
	lttng_dynamic_pointer_array_reset(&actions);
	lttng_condition_destroy(condition);
	lttng_action_destroy(action_group);
	lttng_trigger_destroy(trigger);
	free(id);
	free(fire_once_after_str);
	free(fire_every_str);
	// TODO: check what else to free

	return ret;
}
