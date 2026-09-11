#!/bin/bash
# @@@LICENSE
#
# Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# LICENSE@@@
#
# Runs the libpalmsocket test harness against multiple OpenSSL
# versions.
#
# Usage:
#   ./run_matrix.sh [prefix ...]
#
# With no arguments, runs against the system OpenSSL only (plus an
# AddressSanitizer pass).  Each additional argument is an OpenSSL
# install prefix (from "./Configure ... shared --prefix=X && make &&
# make install_sw") to build and test against as well, e.g. 0.9.8,
# 1.0.2 and 1.1.1 trees.
#
# webOS dependencies (PmLogLib header + stub, PmStateMachineEngine)
# are bootstrapped into deps-build/ automatically from the
# webOS-ports github repos when not already present.

set -u -o pipefail
cd "$(dirname "$0")"

DEPS=deps-build

bootstrap_deps() {
    [ -f "$DEPS/lib/libPmStateMachineEngine.so" ] && \
        [ -f "$DEPS/include/PmLogLib.h" ] && \
        { echo "#include <ares.h>" | gcc -E -I"$DEPS/include" - >/dev/null 2>&1; } && return 0

    echo "== bootstrapping webOS deps into $DEPS/"
    mkdir -p "$DEPS/src" "$DEPS/include/PmStateMachineEngine" "$DEPS/lib"

    [ -d "$DEPS/src/pmloglib" ] || \
        git clone -q --depth 1 https://github.com/webOS-ports/pmloglib \
            "$DEPS/src/pmloglib" || return 1
    [ -d "$DEPS/src/pmstatemachineengine" ] || \
        git clone -q --depth 1 \
            https://github.com/webOS-ports/pmstatemachineengine \
            "$DEPS/src/pmstatemachineengine" || return 1

    # PmLogLib public header is a configure template with a single
    # substitution
    sed 's/@PMLOG_ENABLE_LOGGING@/1/' \
        "$DEPS/src/pmloglib/include/public/PmLogLib.h.in" \
        > "$DEPS/include/PmLogLib.h"
    cp "$DEPS/src/pmloglib/include/public/PmLogMsg.h" "$DEPS/include/"
    cp "$DEPS/src/pmstatemachineengine/include/public/PmStateMachineEngine/"*.h \
        "$DEPS/include/PmStateMachineEngine/"

    # Host stub for PmLogLib (the real one drags in pbnjson etc.; the
    # tests don't need actual log output)
    cat > "$DEPS/src/pmlog_stub.c" <<'EOF'
#include <stdarg.h>
typedef void* PmLogContext;
int PmLogGetContext(const char* n, PmLogContext* c){(void)n;*c=0;return 0;}
int PmLogPrint_(PmLogContext c, int l, const char* f, ...){(void)c;(void)l;(void)f;return 0;}
EOF
    gcc -shared -fPIC -o "$DEPS/lib/libPmLogLib.so" \
        "$DEPS/src/pmlog_stub.c" || return 1

    # c-ares headers/libs: use the system copy when present, else pull
    # the distro packages (no root needed for download+extract)
    if ! echo '#include <ares.h>' | gcc -E - >/dev/null 2>&1; then
        echo "== fetching c-ares into $DEPS/"
        ( cd "$DEPS/src" && \
          apt-get download libc-ares-dev libcares2 >/dev/null 2>&1 && \
          for d in libc-ares*.deb libcares*.deb; do \
              [ -f "$d" ] && dpkg-deb -x "$d" cares-root; \
          done ) || return 1
        cp "$DEPS/src/cares-root/usr/include/"ares*.h "$DEPS/include/"
        cp -a "$DEPS/src/cares-root/usr/lib/"*/libcares.so* "$DEPS/lib/"
    fi

    # Real PmStateMachineEngine (the FSM engine is load-bearing).
    # --allow-multiple-definition works around a duplicate helper in
    # the upstream sources.
    gcc -shared -fPIC -Wno-deprecated-declarations \
        -Wl,--allow-multiple-definition \
        -o "$DEPS/lib/libPmStateMachineEngine.so" \
        "$DEPS/src/pmstatemachineengine/src/"*.c \
        -I"$DEPS/include" -I"$DEPS/src/pmstatemachineengine/src" \
        -I"$DEPS/include/PmStateMachineEngine" \
        -DFSM_CONFIG_WEBOS_FEATURES=1 \
        -L"$DEPS/lib" -lPmLogLib || return 1
}

bootstrap_deps || { echo "dependency bootstrap FAILED"; exit 2; }

declare -A results
overall=0

run_one() {
    local label="$1"; shift
    echo
    echo "==== $label ===="
    if make clean "$@" >/dev/null && make check "$@" 2>&1 | tail -20; then
        results[$label]=ok
    else
        results[$label]=FAILED
        overall=1
    fi
}

run_one "system-openssl" BUILD=build-sys
run_one "system-openssl-asan" BUILD=build-asan ASAN=1

for prefix in "$@"; do
    if [ ! -f "$prefix/include/openssl/ssl.h" ]; then
        echo "ERROR: $prefix has no OpenSSL headers; skipping" >&2
        results["openssl-$(basename "$prefix")"]=MISSING
        overall=1
        continue
    fi
    ver=$("$prefix/bin/openssl" version 2>/dev/null | awk '{print $2}')
    run_one "openssl-${ver:-$(basename "$prefix")}" \
        BUILD="build-$(basename "$prefix")" OPENSSL_PREFIX="$prefix"
done

echo
echo "==== matrix summary ===="
for k in "${!results[@]}"; do
    printf '  %-28s %s\n' "$k" "${results[$k]}"
done
exit $overall
