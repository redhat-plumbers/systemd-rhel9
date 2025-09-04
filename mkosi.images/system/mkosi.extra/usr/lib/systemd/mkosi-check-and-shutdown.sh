#!/bin/bash -eux
# SPDX-License-Identifier: LGPL-2.1-or-later

rm -f /testok

systemctl --failed --no-legend | tee /failed-services

# Check that secure boot keys were properly enrolled.
if ! systemd-detect-virt --container; then
    hexdump -C /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c
    hexdump -C /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c

    diff --text /sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c <(printf '\6\0\0\0\0')
    diff --text /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c <(printf '\6\0\0\0\1')

    if command -v pesign &>/dev/null; then
        cat /proc/cmdline
        grep -q this_should_be_here /proc/cmdline
        (! grep -q this_should_not_be_here /proc/cmdline)
    fi
fi

# Exit with non-zero EC if the /failed-services file is not empty (we have -e set)
[[ ! -s /failed-services ]]
touch /testok
