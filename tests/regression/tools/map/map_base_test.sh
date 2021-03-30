#!/bin/bash
#
# Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only

CURDIR=$(dirname "$0")/
TESTDIR=$CURDIR/../../..

TMPDIR=$(mktemp -d)

SH_TAP=1

# shellcheck source=../../../utils/utils.sh
source "$TESTDIR/utils/utils.sh"

FULL_LTTNG_BIN="${TESTDIR}/../src/bin/lttng/${LTTNG_BIN}"

function view_map_ok() {
	local map_name="$1"
	local key="$2"
	local expected_value="$3"
	local extracted_value
	local temp_view_output

	temp_view_output=$(mktemp -t map_view_output.XXXXXX)

	"$FULL_LTTNG_BIN" view-map "$map_name" --key="$key" > "$temp_view_output"
	ok $? "Map '$map_name' viewed succesfully"

	grep -q " $key " "$temp_view_output"
	ok $? "Key '$key' found in view-map output"

	# Get value
	# TODO: this is based on the text output, ideally when mi is availabe we
	# who should use it to parse the value!
	# Sample output
	# | key | 5|
	# Keep white space surrounding the key so to avoid grepping a substring
	# in a larger key.
	extracted_value=$(grep " $key " "$temp_view_output" | tr -d " " | cut -d "|" -f3)
	# Necessary since the returned value can be non existent
	extracted_value=${extracted_value:-"-1"}

	is "$extracted_value" "$expected_value" "Key value is $expected_value as expected"

	rm -f "$temp_view_output"
}

function test_map_view_empty()
{
	local domain="$1"
	local bitness="$2"
	local buf_option="$3"

	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"

	diag "Map view empty: $domain bitness $bitness $buf_option"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	"$FULL_LTTNG_BIN" view-map "$MAP_NAME" > /dev/null
	ok $? "Map enabled viewed succesfully"

	"$FULL_LTTNG_BIN" disable-map "$domain" "$MAP_NAME" > /dev/null
	ok $? "Map disabled succesfully"

	"$FULL_LTTNG_BIN" view-map "$MAP_NAME" > /dev/null
	ok $? "Map disabled viewed succesfully"

	destroy_lttng_session_ok "$SESSION_NAME"
}

function test_map_formated_keys()
{
	local domain="$1"
	local event_name="$2"
	local key_format="$3"
	local expected_key="$4"
	local test_app="$5"

	local bitness="32"
	# buf option left empty for use with both UST and kernel domain.
	local buf_option=""
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"

	diag "Map with $domain formated key. event-name: \"$event_name\", key format: \"$key_format\", expecting: \"$expected_key\""

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$key_format"

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$expected_key" "$NR_ITER"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_n_triggers_n_keys()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""

	local number_of_trigger=5

	diag "Map $domain with $number_of_trigger triggers with all different keys"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	for i in $(seq 1 $number_of_trigger); do
		cur_trigger_name="${TRIGGER_NAME}${i}"
		lttng_add_trigger_ok "$cur_trigger_name" \
			--condition \
				on-event "$domain" "$event_name" \
			--action \
				incr-value --session "$SESSION_NAME" \
				--map "$MAP_NAME" \
				--key "${KEY}${i}"
	done

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	for i in $(seq 1 $number_of_trigger); do
		view_map_ok "$MAP_NAME" "$KEY${i}" "$NR_ITER"
	done

	for i in $(seq 1 $number_of_trigger); do
		lttng_remove_trigger_ok "$TRIGGER_NAME${i}"
	done

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_n_triggers_1_key()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""

	local number_of_trigger=5

	diag "Map $domain with $number_of_trigger triggers all with the same key"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	for i in $(seq 1 $number_of_trigger); do
		cur_trigger_name="${TRIGGER_NAME}${i}"
		lttng_add_trigger_ok "$cur_trigger_name" \
			--condition \
				on-event "$domain" "$event_name" \
			--action \
				incr-value --session "$SESSION_NAME" \
				--map "$MAP_NAME" \
				--key "${KEY}"
	done

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "$((NR_ITER * number_of_trigger))"

	for i in $(seq 1 $number_of_trigger); do
		lttng_remove_trigger_ok "$TRIGGER_NAME${i}"
	done

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_n_triggers_1_key_coalesced()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""

	local number_of_trigger=5

	diag "Map $domain with $number_of_trigger triggers all with the same key"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option" "--coalesce-hits"

	for i in $(seq 1 $number_of_trigger); do
		cur_trigger_name="${TRIGGER_NAME}${i}"
		lttng_add_trigger_ok "$cur_trigger_name" \
			--condition \
				on-event "$domain" "$event_name" \
			--action \
				incr-value --session "$SESSION_NAME" \
				--map "$MAP_NAME" \
				--key "${KEY}"
	done

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	# With the `coalesce-hits` map option two enablers on the same event
	# with the same key will only increment the counter once.
	view_map_ok "$MAP_NAME" "$KEY" "$((NR_ITER))"

	for i in $(seq 1 $number_of_trigger); do
		lttng_remove_trigger_ok "$TRIGGER_NAME${i}"
	done

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_disable_enable()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""

	diag "Map $domain disable-enable --bitness $bitness"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY"

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "$NR_ITER"

	"$FULL_LTTNG_BIN" disable-map "$domain" -s "$SESSION_NAME" "$MAP_NAME" > /dev/null
	ok $? "Map disabled succesfully"

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	# The values in the map should not have changed since the map is
	# disabled.
	view_map_ok "$MAP_NAME" "$KEY" "$NR_ITER"

	"$FULL_LTTNG_BIN" enable-map "$domain" -s "$SESSION_NAME" "$MAP_NAME" > /dev/null
	ok $? "Map enabled succesfully"

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "$((NR_ITER * 2))"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_add_remove_add_trigger()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""

	diag "Map $domain add-remove-add the same trigger"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY"

	start_lttng_tracing_ok $SESSION_NAME

	"$test_app"

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "$NR_ITER"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	start_lttng_tracing_ok $SESSION_NAME

	"$test_app"

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "$NR_ITER"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY"

	start_lttng_tracing_ok $SESSION_NAME

	"$test_app"

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "$((NR_ITER * 2))"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_creation_after_trigger()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""

	diag "Map $domain creation after trigger creation"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	start_lttng_tracing_ok $SESSION_NAME

	"$test_app"

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "$NR_ITER"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_remove_trigger_before_stop()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""

	diag "Map remove trigger before stop"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY"

	start_lttng_tracing_ok $SESSION_NAME

	"$test_app"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	view_map_ok "$MAP_NAME" "$KEY" "$NR_ITER"

	stop_lttng_tracing_ok $SESSION_NAME

	# Confirm that the map content is unchanged after a stop.
	view_map_ok "$MAP_NAME" "$KEY" "$NR_ITER"

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_two_incr_value_two_keys()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY1="romados"
	local KEY2="pitarifique"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""

	diag "Map remove trigger before stop"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY1" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY2"

	start_lttng_tracing_ok $SESSION_NAME

	"$test_app"


	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY1" "$NR_ITER"
	view_map_ok "$MAP_NAME" "$KEY2" "$NR_ITER"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_filter()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local event_name="$2"
	local filter_field="$3"
	local test_app="$4"
	local buf_option=""
	local bitness="32"

	diag "Map $domain filtering $event_name filter: \"$filter_field == 0\""

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" --filter "$filter_field==0"\
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY"

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "1"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	destroy_lttng_session_ok $SESSION_NAME
}

function test_map_clear()
{
	local MAP_NAME="my_map_name"
	local SESSION_NAME="my_session_name"
	local TRIGGER_NAME="my_trigger_name"
	local KEY="foo"
	local domain="$1"
	local bitness="$2"
	local event_name="$3"
	local test_app="$4"
	local buf_option=""
	local bitness="32"

	diag "Map $domain clear"

	create_lttng_session_ok "$SESSION_NAME"

	lttng_add_map_ok "$MAP_NAME" "$SESSION_NAME" "$domain" "$bitness" "$buf_option"

	lttng_add_trigger_ok "$TRIGGER_NAME" \
		--condition \
			on-event "$domain" "$event_name" \
		--action \
			incr-value --session "$SESSION_NAME" --map "$MAP_NAME" --key "$KEY"

	start_lttng_tracing_ok $SESSION_NAME

	$test_app

	stop_lttng_tracing_ok $SESSION_NAME

	view_map_ok "$MAP_NAME" "$KEY" "$NR_ITER"

	lttng_clear_session_ok "$SESSION_NAME"

	view_map_ok "$MAP_NAME" "$KEY" "0"

	lttng_remove_trigger_ok "$TRIGGER_NAME"

	destroy_lttng_session_ok $SESSION_NAME
}
