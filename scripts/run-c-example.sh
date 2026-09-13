#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p canokey-c --locked
example_target_dir=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
example_build_dir=$(mktemp -d "$example_target_dir/c-example.XXXXXX")
trap 'rm -rf "$example_build_dir"' EXIT
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I crates/canokey-c/include crates/canokey-c/examples/probe.c \
    -L "$example_target_dir/debug" -Wl,-rpath,"$example_target_dir/debug" \
    -lcanokey_c -o "$example_build_dir/probe"
"$example_build_dir/probe"
