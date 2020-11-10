# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests -I$(srcdir)

noinst_SCRIPTS = \
	map_base_test.sh \
	test_map_kernel

EXTRA_DIST = \
	map_base_test.sh \
	test_map_kernel

if HAVE_LIBLTTNG_UST_CTL
EXTRA_DIST += test_map_ust
noinst_SCRIPTS += test_map_ust
endif

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
