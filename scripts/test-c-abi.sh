#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p canokey-c --locked
abi_target_dir=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
abi_build_dir=$(mktemp -d "$abi_target_dir/c-abi.XXXXXX")
trap 'rm -rf "$abi_build_dir"' EXIT
for abi_source in crates/canokey-c/tests/*.c; do
    abi_name=$(basename "$abi_source" .c)
    "${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
        -I crates/canokey-c/include "$abi_source" \
        -L "$abi_target_dir/debug" -Wl,-rpath,"$abi_target_dir/debug" \
        -lcanokey_c -o "$abi_build_dir/$abi_name"
    "$abi_build_dir/$abi_name"
done
cat > "$abi_build_dir/header.cpp" <<'CPP'
#include "canokey.h"
int main() { return cnk_abi_version() == 1 ? 0 : 1; }
CPP
"${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror \
    -I crates/canokey-c/include "$abi_build_dir/header.cpp" \
    -L "$abi_target_dir/debug" -Wl,-rpath,"$abi_target_dir/debug" \
    -lcanokey_c -o "$abi_build_dir/header"
"$abi_build_dir/header"
printf '%s\n' 'C transcript and C++ header/link checks passed'
