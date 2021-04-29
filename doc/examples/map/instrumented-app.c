/*
 * Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include "tracepoint-incr-value-example.h"

#include <lttng/tracepoint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	uint64_t i;

	for (i = 0; i < UINT64_MAX; i++) {
		char time_str[64];
		struct timeval tv;
		time_t the_time;

		gettimeofday(&tv, NULL);
		the_time = tv.tv_sec;

		strftime(time_str, sizeof(time_str), "[%m-%d-%Y] %T",
				localtime(&the_time));
		printf("%s.%ld - Tracing event \"trigger_example:my_event1\"\n",
				time_str, tv.tv_usec);

		tracepoint(incr_value_ex, event1, i);
		if (i % 2 == 0) {
			tracepoint(incr_value_ex, event2, i);
		}

		if (i % 3 == 0) {
			tracepoint(incr_value_ex, event3, i);
		}

		sleep(1);
	}
	return 0;
}
