#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

# Test start & stop operations without daemon-reload

at_exit() {
    set +e

    rm -f /run/systemd/system/testsuite-23-no-reload.target
    rm -f /run/systemd/system/testsuite-23-no-reload.service
    rm -f /run/systemd/system/testsuite-23-no-reload-2.service
    rm -f /run/systemd/system/testsuite-23-no-reload-3.service
    systemctl stop testsuite-23-no-reload.target
    systemctl stop testsuite-23-no-reload.service
    systemctl stop testsuite-23-no-reload-2.service
    systemctl stop testsuite-23-no-reload-3.service
}

trap at_exit EXIT

# Stop and remove, and try again to exercise https://github.com/systemd/systemd/issues/36031
systemctl stop testsuite-23-no-reload.service testsuite-23-no-reload.target
rm -f /run/systemd/system/testsuite-23-no-reload.service /run/systemd/system/testsuite-23-no-reload.target
systemctl daemon-reload

sleep 3.1

cat >/run/systemd/system/testsuite-23-no-reload.target <<EOF
[Unit]
Conflicts=shutdown.target
EOF

cat >/run/systemd/system/testsuite-23-no-reload.service <<EOF
[Unit]
Conflicts=testsuite-23-no-reload.target
Wants=testsuite-23-no-reload-2.service
Wants=testsuite-23-no-reload-3.service
[Service]
ExecStart=sleep infinity
EOF

systemctl daemon-reload

systemctl start testsuite-23-no-reload.service
(! systemctl is-active testsuite-23-no-reload.target )
systemctl is-active testsuite-23-no-reload.service
[[ "$(systemctl show --property LoadState --value testsuite-23-no-reload-2.service)" == not-found ]]
[[ "$(systemctl show --property LoadState --value testsuite-23-no-reload-3.service)" == not-found ]]

cat >/run/systemd/system/testsuite-23-no-reload-2.service <<EOF
[Unit]
Conflicts=testsuite-23-no-reload.target
[Service]
ExecStart=sleep infinity
EOF

# This service file is intentionally invalid (Type=exec without ExecStart=).
cat >/run/systemd/system/testsuite-23-no-reload-3.service <<EOF
[Unit]
Conflicts=testsuite-23-no-reload.target
[Service]
Type=exec
ExecStop=sleep infinity
EOF

systemctl start testsuite-23-no-reload.target
systemctl is-active testsuite-23-no-reload.target
(! systemctl is-active testsuite-23-no-reload.service )
(! systemctl is-active testsuite-23-no-reload-2.service )
(! systemctl is-active testsuite-23-no-reload-3.service )
[[ "$(systemctl show --property LoadState --value testsuite-23-no-reload-2.service)" == loaded ]]
[[ "$(systemctl show --property LoadState --value testsuite-23-no-reload-3.service)" == bad-setting ]]
[[ "$(systemctl show --property Conflicts --value testsuite-23-no-reload-2.service)" =~ testsuite-23-no-reload.target ]]
[[ "$(systemctl show --property Conflicts --value testsuite-23-no-reload-3.service)" =~ testsuite-23-no-reload.target ]]
