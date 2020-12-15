# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = tools kernel ust

LOG_DRIVER_FLAGS = --merge --post-script $(top_srcdir)/tests/utils/warn_processes.sh
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = tools/notification/test_notification_ust_error \
     tools/notification/test_notification_ust_buffer_usage \
     tools/notification/test_notification_ust_capture \
     tools/notification/test_notification_ust_event_rule_condition_exclusion \
     tools/notification/test_notification_kernel_error \
     tools/notification/test_notification_kernel_buffer_usage \
     tools/notification/test_notification_kernel_capture \
     tools/notification/test_notification_kernel_instrumentation \
     tools/notification/test_notification_kernel_syscall \
     tools/notification/test_notification_notifier_discarded_count \
     tools/notification/test_notification_kernel_userspace_probe \
     tools/notification/test_notification_multi_app
