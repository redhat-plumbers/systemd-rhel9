#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test that ExecStopPost= is always run"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
