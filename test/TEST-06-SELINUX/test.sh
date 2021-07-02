#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="SELinux tests"
IMAGE_NAME="selinux"
TEST_NO_NSPAWN=1

# Requirements:
# Fedora 23
# selinux-policy-targeted
# selinux-policy-devel

# Check if selinux-policy-devel is installed, and if it isn't bail out early instead of failing
test -f /usr/share/selinux/devel/include/system/systemd.if || exit 0

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

SETUP_SELINUX=yes
KERNEL_APPEND="${KERNEL_APPEND:=} selinux=1 security=selinux"

test_append_files() {
    (
        local workspace="${1:?}"
        local policy_headers_dir=/usr/share/selinux/devel
        local modules_dir=/var/lib/selinux

        setup_selinux
        # Make sure we never expand this to "/..."
        rm -rf "${workspace:?}/$modules_dir"

        if ! cp -ar "$modules_dir" "$workspace/$modules_dir"; then
            dfatal "Failed to copy $modules_dir"
            exit 1
        fi

        rm -rf "${workspace:?}/$policy_headers_dir"
        inst_dir /usr/share/selinux

        if ! cp -ar "$policy_headers_dir" "$workspace/$policy_headers_dir"; then
            dfatal "Failed to copy $policy_headers_dir"
            exit 1
        fi

        mkdir "$workspace/systemd-test-module"
        cp systemd_test.te "$workspace/systemd-test-module"
        cp systemd_test.if "$workspace/systemd-test-module"
        cp systemd_test.fc "$workspace/systemd-test-module"
        dracut_install -o sesearch
        dracut_install runcon
        dracut_install checkmodule semodule semodule_package m4 make load_policy sefcontext_compile
        dracut_install -o /usr/libexec/selinux/hll/pp # Fedora/RHEL/...
        dracut_install -o /usr/lib/selinux/hll/pp     # Debian/Ubuntu/...
    )
}

do_test "$@"
