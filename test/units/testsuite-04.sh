#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Limit the maximum journal size
trap "journalctl --rotate --vacuum-size=16M" EXIT

# Rotation/flush test, see https://github.com/systemd/systemd/issues/19895
journalctl --relinquish-var
[[ "$(systemd-detect-virt -v)" == "qemu" ]] && ITERATIONS=10 || ITERATIONS=50
for ((i = 0; i < ITERATIONS; i++)); do
    dd if=/dev/urandom bs=1M count=1 | base64 | systemd-cat
done
journalctl --rotate
journalctl --flush
journalctl --sync

# Reset the ratelimit buckets for the subsequent tests below.
systemctl restart systemd-journald

# Test stdout stream

# Skip empty lines
ID=$(journalctl --new-id128 | sed -n 2p)
: >/expected
printf $'\n\n\n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
: >/expected
printf $'<5>\n<6>\n<7>\n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# Remove trailing spaces
ID=$(journalctl --new-id128 | sed -n 2p)
printf "Trailing spaces\n">/expected
printf $'<5>Trailing spaces \t \n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
printf "Trailing spaces\n">/expected
printf $'Trailing spaces \t \n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# Don't remove leading spaces
ID=$(journalctl --new-id128 | sed -n 2p)
printf $' \t Leading spaces\n'>/expected
printf $'<5> \t Leading spaces\n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
printf $' \t Leading spaces\n'>/expected
printf $' \t Leading spaces\n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# --output-fields restricts output
ID=$(journalctl --new-id128 | sed -n 2p)
printf $'foo' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o export --output-fields=MESSAGE,FOO --output-fields=PRIORITY,MESSAGE -t "$ID" >/output
[[ $(grep -c . /output) -eq 6 ]]
grep -q '^__CURSOR=' /output
grep -q '^MESSAGE=foo$' /output
grep -q '^PRIORITY=6$' /output
grep '^FOO=' /output && { echo 'unexpected success'; exit 1; }
grep '^SYSLOG_FACILITY=' /output && { echo 'unexpected success'; exit 1; }

# `-b all` negates earlier use of -b (-b and -m are otherwise exclusive)
journalctl -b -1 -b all -m >/dev/null

# -b always behaves like -b0
journalctl -q -b-1 -b0 | head -1 >/expected
journalctl -q -b-1 -b  | head -1 >/output
cmp /expected /output
# ... even when another option follows (both of these should fail due to -m)
{ journalctl -ball -b0 -m 2>&1 || :; } | head -1 >/expected
{ journalctl -ball -b  -m 2>&1 || :; } | head -1 >/output
cmp /expected /output

# https://github.com/systemd/systemd/issues/13708
ID=$(systemd-id128 new)
systemd-cat -t "$ID" bash -c 'echo parent; (echo child) & wait' &
PID=$!
wait $PID
journalctl --sync
# We can drop this grep when https://github.com/systemd/systemd/issues/13937
# has a fix.
journalctl -b -o export -t "$ID" --output-fields=_PID | grep '^_PID=' >/output
[[ $(grep -c . /output) -eq 2 ]]
grep -q "^_PID=$PID" /output
grep -vq "^_PID=$PID" /output

# https://github.com/systemd/systemd/issues/15654
ID=$(journalctl --new-id128 | sed -n 2p)
printf "This will\nusually fail\nand be truncated\n">/expected
systemd-cat -t "$ID" /bin/sh -c 'env echo -n "This will";echo;env echo -n "usually fail";echo;env echo -n "and be truncated";echo;'
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_TRANSPORT | grep -Pc "^stdout$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_LINE_BREAK | grep -Pc "^pid-change$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_PID | sort -u | grep -c "^.*$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=MESSAGE | grep -Pc "^(This will|usually fail|and be truncated)$") -eq 3 ]]

# test that LogLevelMax can also suppress logging about services, not only by services
systemctl start silent-success
journalctl --sync
[[ -z "$(journalctl -b -q -u silent-success.service)" ]]

# Exercise the matching machinery
SYSTEMD_LOG_LEVEL=debug journalctl -b -n 1 /dev/null /dev/zero /dev/null /dev/null /dev/null
journalctl -b -n 1 /bin/true /bin/false
journalctl -b -n 1 /bin/true + /bin/false
journalctl -b -n 1 -r --unit "systemd*"

systemd-run --user -M "testuser@.host" /bin/echo hello
journalctl --sync
journalctl -b -n 1 -r --user-unit "*"

(! journalctl -b /dev/lets-hope-this-doesnt-exist)
(! journalctl -b /dev/null /dev/zero /dev/this-also-shouldnt-exist)
(! journalctl -b --unit "this-unit-should-not-exist*")

# Facilities & priorities
journalctl --facility help
journalctl --facility kern -n 1
journalctl --facility syslog --priority 0..3 -n 1
journalctl --facility syslog --priority 3..0 -n 1
journalctl --facility user --priority 0..0 -n 1
journalctl --facility daemon --priority warning -n 1
journalctl --facility daemon --priority warning..info -n 1
journalctl --facility daemon --priority notice..crit -n 1
journalctl --facility daemon --priority 5..crit -n 1

(! journalctl --facility hopefully-an-unknown-facility)
(! journalctl --priority hello-world)
(! journalctl --priority 0..128)
(! journalctl --priority 0..systemd)

# Other options
journalctl --disk-usage
journalctl --dmesg -n 1
journalctl --fields
journalctl --list-boots
journalctl --update-catalog
journalctl --list-catalog

# Add new tests before here, the journald restarts below
# may make tests flappy.

# Don't lose streams on restart
systemctl start forever-print-hola
sleep 3
systemctl restart systemd-journald
sleep 3
systemctl stop forever-print-hola
[[ ! -f "/i-lose-my-logs" ]]

# https://github.com/systemd/systemd/issues/4408
rm -f /i-lose-my-logs
systemctl start forever-print-hola
sleep 3
systemctl kill --signal=SIGKILL systemd-journald
sleep 3
[[ ! -f "/i-lose-my-logs" ]]

set +o pipefail
# https://github.com/systemd/systemd/issues/15528
journalctl --follow --file=/var/log/journal/*/* | head -n1 | grep .
# https://github.com/systemd/systemd/issues/24565
journalctl --follow --merge | head -n1 | grep .
set -o pipefail

# https://github.com/systemd/systemd/issues/26746
rm -f /tmp/issue-26746-log /tmp/issue-26746-cursor
ID="$(systemd-id128 new)"
journalctl -t "$ID" --follow --cursor-file=/tmp/issue-26746-cursor | tee /tmp/issue-26746-log &
systemd-cat -t "$ID" /bin/sh -c 'echo hogehoge'
# shellcheck disable=SC2016
timeout 10 bash -c 'while ! [[ -f /tmp/issue-26746-log && "$(cat /tmp/issue-26746-log)" =~ hogehoge ]]; do sleep .5; done'
pkill -TERM journalctl
timeout 10 bash -c 'while ! test -f /tmp/issue-26746-cursor; do sleep .5; done'
CURSOR_FROM_FILE="$(cat /tmp/issue-26746-cursor)"
CURSOR_FROM_JOURNAL="$(journalctl -t "$ID" --output=export MESSAGE=hogehoge | sed -n -e '/__CURSOR=/ { s/__CURSOR=//; p }')"
test "$CURSOR_FROM_FILE" = "$CURSOR_FROM_JOURNAL"


# https://bugzilla.redhat.com/show_bug.cgi?id=2183546
mkdir /run/systemd/system/systemd-journald.service.d
MID=$(cat /etc/machine-id)
for c in "NONE" "XZ" "LZ4" "ZSTD"; do
    cat >/run/systemd/system/systemd-journald.service.d/compress.conf <<EOF
[Service]
Environment=SYSTEMD_JOURNAL_COMPRESS=${c}
EOF
    systemctl daemon-reload
    systemctl restart systemd-journald.service
    journalctl --rotate

    ID=$(systemd-id128 new)
    systemd-cat -t "$ID" /bin/bash -c "for ((i=0;i<100;i++)); do echo -n hoge with ${c}; done; echo"
    journalctl --sync
    timeout 10 bash -c "while ! SYSTEMD_LOG_LEVEL=debug journalctl --verify --quiet --file /var/log/journal/$MID/system.journal 2>&1 | grep -q -F 'compress=${c}'; do sleep .5; done"

    # $SYSTEMD_JOURNAL_COMPRESS= also works for journal-remote
    if [[ -x /usr/lib/systemd/systemd-journal-remote ]]; then
        for cc in "NONE" "XZ" "LZ4" "ZSTD"; do
            rm -f /tmp/foo.journal
            SYSTEMD_JOURNAL_COMPRESS="${cc}" /usr/lib/systemd/systemd-journal-remote --split-mode=none -o /tmp/foo.journal --getter="journalctl -b -o export -t $ID"
            SYSTEMD_LOG_LEVEL=debug journalctl --verify --quiet --file /tmp/foo.journal 2>&1 | grep -q -F "compress=${cc}"
            journalctl -t "$ID" -o cat --file /tmp/foo.journal | grep -q -F "hoge with ${c}"
        done
    fi
done
rm /run/systemd/system/systemd-journald.service.d/compress.conf
systemctl daemon-reload
systemctl restart systemd-journald.service
journalctl --rotate

# Check that using --after-cursor/--cursor-file= together with journal filters doesn't
# skip over entries matched by the filter
# See: https://github.com/systemd/systemd/issues/30288
UNIT_NAME="test-cursor-$RANDOM.service"
CURSOR_FILE="$(mktemp)"
# Generate some messages we can match against
journalctl --cursor-file="$CURSOR_FILE" -n1
systemd-run --unit="$UNIT_NAME" --wait --service-type=exec bash -xec "echo hello; echo world"
journalctl --sync
# --after-cursor= + --unit=
# The format of the "Starting ..." message depends on StatusUnitFormat=, so match only the beginning
# which should be enough in this case
[[ "$(journalctl -n 1 -p info -o cat --unit="$UNIT_NAME" --after-cursor="$(<"$CURSOR_FILE")" _PID=1 )" =~ ^Starting\  ]]
# There should be no such messages before the cursor
[[ -z "$(journalctl -n 1 -p info -o cat --unit="$UNIT_NAME" --after-cursor="$(<"$CURSOR_FILE")" --reverse)" ]]
# --cursor-file= + a journal filter
diff <(journalctl --cursor-file="$CURSOR_FILE" -p info -o cat _SYSTEMD_UNIT="$UNIT_NAME") - <<EOF
+ echo hello
hello
+ echo world
world
EOF
rm -f "$CURSOR_FILE"

# Check that --until works with --after-cursor and --lines/-n
# See: https://github.com/systemd/systemd/issues/31776
CURSOR_FILE="$(mktemp)"
journalctl -q -n 0 --cursor-file="$CURSOR_FILE"
TIMESTAMP="$(journalctl -q -n 1 --cursor="$(<"$CURSOR_FILE")" --output=short-unix | cut -d ' ' -f 1 | cut -d '.' -f 1)"
[[ -z "$(journalctl -q -n 10 --after-cursor="$(<"$CURSOR_FILE")" --until "@$((TIMESTAMP - 3))")" ]]
rm -f "$CURSOR_FILE"

touch /testok
