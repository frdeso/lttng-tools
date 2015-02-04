AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src \
			  -DINSTALL_BIN_PATH=\""$(bindir)"\"

bin_PROGRAMS = lttng-ptrace

lttng_ptrace_SOURCES = lttng-ptrace.c

lttng_ptrace_LDADD = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
			$(top_builddir)/src/common/libcommon.la \
			$(top_builddir)/src/common/config/libconfig.la
