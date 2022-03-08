#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -ex

export LC_CTYPE=C.UTF-8

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
clang_version="$($CC --version | sed -nr 's/.*version ([^ ]+?) .*/\1/p' | sed -r 's/-$//')"

SANITIZER=${SANITIZER:-address -fsanitize-address-use-after-scope}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER"

clang_lib="/usr/lib64/clang/${clang_version}/lib/linux"
[ -d "$clang_lib" ] || clang_lib="/usr/lib/clang/${clang_version}/lib/linux"

export CFLAGS=${CFLAGS:-$flags}
export CXXFLAGS=${CXXFLAGS:-$flags}
export LDFLAGS=${LDFLAGS:--L${clang_lib}}

export WORK=${WORK:-$(pwd)}
export OUT=${OUT:-$(pwd)/out}
mkdir -p "$OUT"

build="$WORK/build"
rm -rf "$build"
mkdir -p "$build"

if [ -z "$FUZZING_ENGINE" ]; then
    fuzzflag="llvm-fuzz=true"
else
    fuzzflag="oss-fuzz=true"

    apt-get update
    apt-get install -y gperf m4 gettext python3-pip \
        libcap-dev libmount-dev libkmod-dev \
        pkg-config wget python3-jinja2

    # gnu-efi is installed here to enable -Dgnu-efi behind which fuzz-bcd
    # is hidden. It isn't linked against efi. It doesn't
    # even include "efi.h" because "bcd.c" can work in "unit test" mode
    # where it isn't necessary.
    apt-get install -y gnu-efi zstd

    pip3 install -r .github/workflows/requirements.txt --require-hashes

    # https://github.com/google/oss-fuzz/issues/6868
    ORIG_PYTHONPATH=$(python3 -c 'import sys;print(":".join(sys.path[1:]))')
    export PYTHONPATH="$ORIG_PYTHONPATH:/usr/lib/python3/dist-packages/"

    if [[ "$SANITIZER" == undefined ]]; then
        UBSAN_FLAGS="-fsanitize=pointer-overflow -fno-sanitize-recover=pointer-overflow"
        CFLAGS="$CFLAGS $UBSAN_FLAGS"
        CXXFLAGS="$CXXFLAGS $UBSAN_FLAGS"
    fi
fi

if ! meson "$build" "-D$fuzzflag" -Db_lundef=false; then
    cat "$build/meson-logs/meson-log.txt"
    exit 1
fi

ninja -v -C "$build" fuzzers

# Compressed BCD files are kept in test/test-bcd so let's unpack them
# and put them all in the seed corpus.
bcd=$(mktemp -d)
for i in test/test-bcd/*.zst; do
     unzstd "$i" -o "$bcd/$(basename "${i%.zst}")";
done
zip -jqr "$OUT/fuzz-bcd_seed_corpus.zip" "$bcd"
rm -rf "$bcd"

# The seed corpus is a separate flat archive for each fuzzer,
# with a fixed name ${fuzzer}_seed_corpus.zip.
for d in "$(dirname "$0")/../test/fuzz/fuzz-"*; do
    zip -jqr "$OUT/$(basename "$d")_seed_corpus.zip" "$d"
done

# get fuzz-dns-packet corpus
df="$build/dns-fuzzing"
git clone --depth 1 https://github.com/CZ-NIC/dns-fuzzing "$df"
zip -jqr "$OUT/fuzz-dns-packet_seed_corpus.zip" "$df/packet"

install -Dt "$OUT/src/shared/" "$build"/src/shared/libsystemd-shared-*.so

wget -O "$OUT/fuzz-json.dict" https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/json.dict

find "$build" -maxdepth 1 -type f -executable -name "fuzz-*" -exec mv {} "$OUT" \;
find src -type f -name "fuzz-*.dict" -exec cp {} "$OUT" \;
cp src/fuzz/*.options "$OUT"
