/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef NOTIFICATION_THREAD_COMMANDS_H
#define NOTIFICATION_THREAD_COMMANDS_H

#include <lttng/domain.h>
#include <lttng/lttng-error.h>
#include <urcu/rculfhash.h>
#include "notification-thread.h"
#include "notification-thread-internal.h"
#include "notification-thread-events.h"
#include <common/waiter.h>
#include <stdbool.h>

struct notification_thread_data;
struct lttng_trigger;

enum notification_thread_command_type {
	NOTIFICATION_COMMAND_TYPE_REGISTER_TRIGGER,
	NOTIFICATION_COMMAND_TYPE_UNREGISTER_TRIGGER,
	NOTIFICATION_COMMAND_TYPE_ADD_CHANNEL,
	NOTIFICATION_COMMAND_TYPE_REMOVE_CHANNEL,
	NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_ONGOING,
	NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_COMPLETED,
	NOTIFICATION_COMMAND_TYPE_ADD_TRACER_EVENT_SOURCE,
	NOTIFICATION_COMMAND_TYPE_REMOVE_TRACER_EVENT_SOURCE,
	NOTIFICATION_COMMAND_TYPE_LIST_TRIGGERS,
	NOTIFICATION_COMMAND_TYPE_QUIT,
	NOTIFICATION_COMMAND_TYPE_CLIENT_COMMUNICATION_UPDATE,
};

struct notification_thread_command {
	struct cds_list_head cmd_list_node;

	enum notification_thread_command_type type;
	union {
		/* Register/Unregister trigger. */
		struct lttng_trigger *trigger;
		/* Add channel. */
		struct {
			struct {
				const char *name;
				uid_t uid;
				gid_t gid;
			} session;
			struct {
				const char *name;
				enum lttng_domain_type domain;
				uint64_t key;
				uint64_t capacity;
			} channel;
		} add_channel;
		/* Remove channel. */
		struct {
			uint64_t key;
			enum lttng_domain_type domain;
		} remove_channel;
		struct {
			const char *session_name;
			uid_t uid;
			gid_t gid;
			uint64_t trace_archive_chunk_id;
			struct lttng_trace_archive_location *location;
		} session_rotation;
		/* Add/Remove tracer event source fd */
		struct {
			int tracer_event_source_fd;
			enum lttng_domain_type domain;
		} tracer_event_source;
		/* List triggers. */
		struct {
			/* Credentials of the requesting user. */
			uid_t uid;
		} list_triggers;
		/* Client communication update. */
		struct {
			notification_client_id id;
			enum client_transmission_status status;
		} client_communication_update;

	} parameters;

	union {
		struct {
			struct lttng_triggers *triggers;
		} list_triggers;
	} reply;
	/* lttng_waiter on which to wait for command reply (optional). */
	struct lttng_waiter reply_waiter;
	enum lttng_error_code reply_code;
	bool is_async;
};

enum lttng_error_code notification_thread_command_register_trigger(
		struct notification_thread_handle *handle,
		struct lttng_trigger *trigger);

enum lttng_error_code notification_thread_command_unregister_trigger(
		struct notification_thread_handle *handle,
		struct lttng_trigger *trigger);

enum lttng_error_code notification_thread_command_add_channel(
		struct notification_thread_handle *handle,
		char *session_name, uid_t session_uid, gid_t session_gid,
		char *channel_name, uint64_t key,
		enum lttng_domain_type domain, uint64_t capacity);

enum lttng_error_code notification_thread_command_remove_channel(
		struct notification_thread_handle *handle,
		uint64_t key, enum lttng_domain_type domain);

enum lttng_error_code notification_thread_command_session_rotation_ongoing(
		struct notification_thread_handle *handle,
		const char *session_name, uid_t session_uid, gid_t session_gid,
		uint64_t trace_archive_chunk_id);

/* Ownership of location is transferred. */
enum lttng_error_code notification_thread_command_session_rotation_completed(
		struct notification_thread_handle *handle,
		const char *session_name, uid_t session_uid, gid_t session_gid,
		uint64_t trace_archive_chunk_id,
		struct lttng_trace_archive_location *location);

/*
 * Return the set of triggers visible to a given client.
 *
 * The trigger objects contained in the set are the actual trigger instances
 * used by the notification subsystem (i.e. not a copy). Given that the command
 * is only used to serialize the triggers, this is fine: the properties that
 * are serialized are immutable over the lifetime of the triggers.
 *
 * Moreover, the lifetime of the trigger instances is protected through
 * reference counting (references are held by the trigger set).
 *
 * The caller has the exclusive ownership of the returned trigger set.
 */
enum lttng_error_code notification_thread_command_list_triggers(
		struct notification_thread_handle *handle,
		uid_t client_uid,
		struct lttng_triggers **triggers);

enum lttng_error_code notification_thread_command_add_tracer_event_source(
		struct notification_thread_handle *handle,
		int fd,
		enum lttng_domain_type domain
		);

enum lttng_error_code notification_thread_command_remove_tracer_event_source(
		struct notification_thread_handle *handle,
		int trigger_event_application_pipe);

void notification_thread_command_quit(
		struct notification_thread_handle *handle);

#endif /* NOTIFICATION_THREAD_COMMANDS_H */
