/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER incr_value_ex

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tracepoint-incr-value-example.h"

#if !defined(_TRACEPOINT_TRIGGER_EXAMPLE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TRIGGER_EXAMPLE_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(incr_value_ex, event1,
	TP_ARGS(int, iteration),
	TP_FIELDS(
		ctf_integer(uint64_t, iteration, iteration)
	)
)

TRACEPOINT_EVENT(incr_value_ex, event2,
	TP_ARGS(int, iteration),
	TP_FIELDS(
		ctf_integer(uint64_t, iteration, iteration)
	)
)

TRACEPOINT_EVENT(incr_value_ex, event3,
	TP_ARGS(int, iteration),
	TP_FIELDS(
		ctf_integer(uint64_t, iteration, iteration)
	)
)

#endif /* _TRACEPOINT_TRIGGER_EXAMPLE_H */

#include <lttng/tracepoint-event.h>
