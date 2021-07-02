#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="Test ExecReload= (PR #13098)"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
