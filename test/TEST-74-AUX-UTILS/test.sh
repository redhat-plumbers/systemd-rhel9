#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Tests for auxiliary utilities"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

# Make sure vsock is available in the VM
CID=$((RANDOM + 3))
QEMU_OPTIONS+=" -device vhost-vsock-pci,guest-cid=$CID"

test_create_image() {
    create_empty_image_rootdir

    LOG_LEVEL=5

    setup_basic_environment
    mask_supporting_services

    generate_module_dependencies

    inst_binary socat
    inst_binary ssh
    inst_binary sshd
    inst_binary ssh-keygen
    inst_binary usermod
    instmods vmw_vsock_virtio_transport
    instmods vsock_loopback
    instmods vmw_vsock_vmci_transport
    generate_module_dependencies
}

do_test "$@"
