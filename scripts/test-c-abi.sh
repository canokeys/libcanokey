#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
abi_mode=${1:-full}
case "$abi_mode" in
    full) set -- ;;
    piv) set -- --no-default-features --features piv ;;
    *) printf '%s\n' 'Usage: test-c-abi.sh [full|piv]' >&2; exit 2 ;;
esac
cargo build -p canokey-c --locked "$@"
abi_target_dir=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
abi_build_dir=$(mktemp -d "$abi_target_dir/c-abi.XXXXXX")
trap 'rm -rf "$abi_build_dir"' EXIT
for abi_source in crates/canokey-c/tests/*.c; do
    abi_name=$(basename "$abi_source" .c)
    if [ "$abi_mode" = piv ]; then
        case "$abi_name" in admin|oath|openpgp|legacy) continue ;; esac
    fi
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

if [ "$abi_mode" = piv ]; then
    python3 - "$abi_target_dir" <<'PY'
import ctypes
import pathlib
import re
import sys
root = pathlib.Path(sys.argv[1]) / "debug"
library = ctypes.CDLL(str(root / ("libcanokey_c.dylib" if sys.platform == "darwin" else "libcanokey_c.so")))
header = pathlib.Path("crates/canokey-c/include/canokey.h").read_text()
excluded = set(re.findall(r"\b(cnk_(?:admin|oath|openpgp)_\w+)\s*\(", header))
assert excluded
assert not [name for name in excluded if hasattr(library, name)], "Excluded applet symbols remain exported"
print(f"PIV-only ABI excludes {len(excluded)} unrelated applet symbols")
PY
fi
