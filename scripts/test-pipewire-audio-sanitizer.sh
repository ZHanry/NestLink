#!/usr/bin/env bash
# Instrument the exact first-party ABI and corpus, with system PipeWire linked.
set -euo pipefail
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=$(mktemp "${TMPDIR:-/tmp}/nestlink-pipewire-audio-sanitizer.XXXXXX")
trap 'rm -f -- "$binary"' EXIT
read -r -a pw_flags <<< "$(pkg-config --cflags --libs libpipewire-0.3)"
"${CC:-gcc}" -std=gnu11 -Wall -Wextra -Werror -O1 -g \
    -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -no-pie \
    "$repo_root/crates/platform-audio/tests/pipewire-audio-boundary-sanitizer.c" \
    "${pw_flags[@]}" -o "$binary"
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 "$binary"
