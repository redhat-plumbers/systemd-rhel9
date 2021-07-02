#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Job-related tests"
TEST_NO_QEMU=1
IMAGE_NAME="default"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
