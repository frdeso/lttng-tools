/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _TRIGGER_ERROR_ACCOUNTING_H
#define _TRIGGER_ERROR_ACCOUNTING_H

#include <stdint.h>

#include "ust-app.h"

enum trigger_error_accounting_status {
	TRIGGER_ERROR_ACCOUNTING_STATUS_OK,
	TRIGGER_ERROR_ACCOUNTING_STATUS_ERR,
	TRIGGER_ERROR_ACCOUNTING_STATUS_NOT_FOUND,
	TRIGGER_ERROR_ACCOUNTING_STATUS_NOMEM,
	TRIGGER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE,
	TRIGGER_ERROR_ACCOUNTING_STATUS_APP_DEAD,
};

void trigger_error_accounting_init(uint64_t nb_bucket);

enum trigger_error_accounting_status trigger_error_accounting_register_kernel(
		int kernel_trigger_group_fd);

#ifdef HAVE_LIBLTTNG_UST_CTL
enum trigger_error_accounting_status trigger_error_accounting_register_app(
		struct ust_app *app);
#else /* HAVE_LIBLTTNG_UST_CTL */
static inline
enum trigger_error_accounting_status trigger_error_accounting_register_app(
		struct ust_app *app)
{
	return TRIGGER_ERROR_ACCOUNTING_STATUS_OK;
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

enum trigger_error_accounting_status trigger_error_accounting_register_trigger(
		const struct lttng_trigger *trigger,
		uint64_t *error_counter_index);

enum trigger_error_accounting_status trigger_error_accounting_get_count(
		const struct lttng_trigger *trigger, uint64_t *count);

void trigger_error_accounting_unregister_trigger(
		const struct lttng_trigger *trigger);

void trigger_error_accounting_fini(void);

#endif /* _TRIGGER_ERROR_ACCOUNTING_H */
