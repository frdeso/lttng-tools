# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = tools kernel ust

LOG_DRIVER_FLAGS = --merge --post-script $(top_srcdir)/tests/utils/warn_processes.sh
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = tools/notification/test_notification_notifier_discarded_count
