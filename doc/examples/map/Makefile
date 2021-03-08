#
# Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
#
# SPDX-License-Identifier: MIT


LOCAL_CPPFLAGS += -I. -g -O0
LIBS_INSTRUMENTED_APP = -ldl -llttng-ust
LIBS_QUERY_EXAMPLE = -llttng-ctl
AM_V_P := :

all: instrumented-app query-example

tracepoint-incr-value-example.o: tracepoint-incr-value-example.c tracepoint-incr-value-example.h
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

instrumented-app.o: instrumented-app.c
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

instrumented-app: instrumented-app.o tracepoint-incr-value-example.o
	@if $(AM_V_P); then set -x; else echo "  CCLD     $@"; fi; \
		$(CC) -o $@ $(LDFLAGS) $(CPPFLAGS) $(AM_LDFLAGS) $(AM_CFLAGS) \
		$(CFLAGS) instrumented-app.o tracepoint-incr-value-example.o $(LIBS_INSTRUMENTED_APP)

query-example: query-example.c
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -o $@ $< $(LIBS_QUERY_EXAMPLE)

.PHONY: clean
clean:
	rm -f *.o *.a instrumented-app query-example
