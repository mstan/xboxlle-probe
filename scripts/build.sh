#!/usr/bin/env sh
# SPDX-License-Identifier: MIT
set -eu

if [ -z "${NXDK_DIR:-}" ]; then
    echo "error: NXDK_DIR must point to a recursive nxdk checkout" >&2
    exit 2
fi

if [ ! -x "$NXDK_DIR/bin/activate" ]; then
    echo "error: $NXDK_DIR/bin/activate not found; clone nxdk recursively" >&2
    exit 2
fi

eval "$("$NXDK_DIR/bin/activate" -s)"
exec make -j"${JOBS:-4}" "$@"
