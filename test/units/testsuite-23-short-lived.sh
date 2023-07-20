#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

if [ -f /tmp/testsuite-23.counter ] ; then
    read -r counter < /tmp/testsuite-23.counter
    counter=$((counter + 1))
else
    counter=0
fi

echo "$counter" >/tmp/testsuite-23.counter

if [ "$counter" -eq 5 ] ; then
    systemctl kill --kill-whom=main -sUSR1 testsuite-23.service
fi

exec sleep 1.5
