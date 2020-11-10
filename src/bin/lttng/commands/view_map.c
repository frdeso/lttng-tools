/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "../command.h"

#include "common/argpar/argpar.h"

enum {
	OPT_HELP,
	OPT_SESSION,
	OPT_LIST_OPTIONS,
};

static const
struct argpar_opt_descr view_map_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_SESSION, 's', "session", true },
	{ OPT_LIST_OPTIONS, '\0', "list-options", false },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static
bool assign_string(char **dest, const char *src, const char *opt_name)
{
	bool ret;

	if (*dest) {
		ERR("Duplicate %s given.", opt_name);
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

static
int view_map(const char *session, const char *map)
{

	return CMD_SUCCESS;
}

int cmd_view_map(int argc, const char **argv)
{
	int ret, i;
	struct argpar_parse_ret argpar_parse_ret = { 0 };
	const char *opt_map_name = NULL;;
	char *opt_session_name = NULL, *session_name = NULL;

	argpar_parse_ret = argpar_parse(argc - 1, argv + 1,
		view_map_options, true);
	if (!argpar_parse_ret.items) {
		ERR("%s", argpar_parse_ret.error);
		goto error;
	}

	for (i = 0; i < argpar_parse_ret.items->n_items; i++) {
		struct argpar_item *item = argpar_parse_ret.items->items[i];

		if (item->type == ARGPAR_ITEM_TYPE_OPT) {
			struct argpar_item_opt *item_opt =
				(struct argpar_item_opt *) item;

			switch (item_opt->descr->id) {
			case OPT_HELP:
				SHOW_HELP();
				ret = CMD_SUCCESS;
				goto end;
			case OPT_SESSION:
				if (!assign_string(&opt_session_name, item_opt->arg,
						"-s/--session")) {
					goto error;
				}
				break;
			case OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout,
					view_map_options);
				ret = CMD_SUCCESS;
				goto end;

			default:
				abort();
			}

		} else {
			struct argpar_item_non_opt *item_non_opt =
				(struct argpar_item_non_opt *) item;

			if (opt_map_name) {
				ERR("Unexpected argument: %s", item_non_opt->arg);
				goto error;
			}
			opt_map_name = item_non_opt->arg;
		}
	}

	//FIXME print current based on lttngrc if not provided?
	if (!opt_map_name) {
		ERR("Missing map name");
		goto error;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			goto error;
		}
	} else {
		session_name = opt_session_name;
	}

	ret = view_map(session_name, opt_map_name);

	ret = CMD_SUCCESS;
	goto end;
error:
	ret = CMD_ERROR;

end:
	argpar_parse_ret_fini(&argpar_parse_ret);
	return ret;
}
