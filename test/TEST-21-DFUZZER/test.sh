#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Fuzz our D-Bus interfaces with dfuzzer"
TEST_NO_NSPAWN=1
TEST_SUPPORTING_SERVICES_SHOULD_BE_MASKED=0
QEMU_TIMEOUT="${QEMU_TIMEOUT:-1800}"
IMAGE_NAME=dfuzzer
TEST_FORCE_NEWIMAGE=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

command -v dfuzzer >/dev/null || exit 0

if ! get_bool "$IS_BUILT_WITH_ASAN"; then
    echo "systemd is built without ASan, skipping..."
    exit 0
fi

test_append_files() {
    local workspace="${1:?}"

    image_install dfuzzer /etc/dfuzzer.conf

    # Enable all systemd-related services, including the D-Bus ones
    "$SYSTEMCTL" --root="${workspace:?}" preset-all
}

do_test "$@"
