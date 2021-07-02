#!/bin/bash
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

test ! -f /run/udev/tags/added/c1:3
test ! -f /run/udev/tags/changed/c1:3
udevadm info /dev/null | grep -E 'E: (TAGS|CURRENT_TAGS)=.*:(added|changed):' && exit 1

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", TAG+="added"
ACTION=="change", SUBSYSTEM=="mem", KERNEL=="null", TAG+="changed"
EOF

udevadm control --reload
udevadm trigger -c add /dev/null

while   test ! -f /run/udev/tags/added/c1:3 ||
        test -f /run/udev/tags/changed/c1:3 ||
        ! udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*' ||
        ! udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:added:.*' ||
        udevadm info /dev/null | grep -q 'E: TAGS=.*:changed:.*' ||
        udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:changed:.*'
do
    sleep .5
done

udevadm control --reload
udevadm trigger -c change /dev/null

while   test ! -f /run/udev/tags/added/c1:3 ||
        test ! -f /run/udev/tags/changed/c1:3 ||
        ! udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*' ||
        udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:added:.*' ||
        ! udevadm info /dev/null | grep -q 'E: TAGS=.*:changed:.*' ||
        ! udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:changed:.*'
do
    sleep .5
done

udevadm control --reload
udevadm trigger -c add /dev/null

while   test ! -f /run/udev/tags/added/c1:3 ||
        test ! -f /run/udev/tags/changed/c1:3 ||
        ! udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*' ||
        ! udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:added:.*' ||
        ! udevadm info /dev/null | grep -q 'E: TAGS=.*:changed:.*' ||
        udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:changed:.*'
do
    sleep .5
done

exit 0
