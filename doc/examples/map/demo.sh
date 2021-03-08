#!/bin/bash
#
# Copyright (C) 2021 Francis Deslauriers <francis.deslauriers@efficios.com>
#
# SPDX-License-Identifier: MIT

SESSION_NAME="incr_value_ex_sess"
MAP_NAME="incr_value_ex_map"
TRIGGER_NAME="incr_value_ex_trigger"

lttng list > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Could not connect to session daemon, are you sure it is running?"
    exit 1
fi

echo "1. Creating a session"
lttng create $SESSION_NAME
echo ""

echo "2. Creating a UST map with default configuration"
lttng add-map --userspace $MAP_NAME
lttng list $SESSION_NAME --map=$MAP_NAME
echo ""

echo "3. Registering a incr-value trigger named \"$TRIGGER_NAME\" for user-space events"
echo "   The \"$TRIGGER_NAME\" trigger has 2 distinct \`incr-value\` actions."
lttng add-trigger --id $TRIGGER_NAME \
	--condition on-event -u "incr_value_ex:*" \
	--action incr-value --session $SESSION_NAME --map $MAP_NAME --key 'Total number of events' \
	--action incr-value --session $SESSION_NAME --map $MAP_NAME --key '${PROVIDER_NAME} -> ${EVENT_NAME}'
lttng list-triggers
echo ""


echo "4. Start the tracing and run the application for 10 seconds"
lttng start
timeout 10 ./instrumented-app > /dev/null
echo ""

echo "5. Stop tracing"
lttng stop
echo ""

echo "6. View the $MAP_NAME map"
lttng view-map $MAP_NAME
echo ""

echo "7. View only on key of the $MAP_NAME map"
lttng view-map $MAP_NAME --key "incr_value_ex -> event1"
echo ""


echo "8. Query a specific value using the C API"
./query-example $SESSION_NAME $MAP_NAME "Total number of events"
echo ""

lttng destroy -a
lttng remove-trigger $TRIGGER_NAME
