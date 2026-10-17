#!/usr/bin/env bash
# Instrument the first-party boundary and its adversarial fixture. The pinned
# upstream static library is not instrumented by this command.
set -euo pipefail
: "${NESTLINK_CODEC_PREFIX:?Set NESTLINK_CODEC_PREFIX to the pinned Linux codec prefix}"
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=$(mktemp "${TMPDIR:-/tmp}/nestlink-vp8-sanitizer.XXXXXX")
trap 'rm -f -- "$binary"' EXIT
"${CC:-gcc}" -std=c11 -Wall -Wextra -Werror -O1 -g \
  -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -no-pie \
  -I"$NESTLINK_CODEC_PREFIX/include" \
  "$repo_root/crates/media-codec/src/vp8.c" \
  "$repo_root/crates/media-codec/tests/vp8-boundary-sanitizer.c" \
  "$NESTLINK_CODEC_PREFIX/lib/libvpx.a" -lm -lpthread -o "$binary"
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$binary"
