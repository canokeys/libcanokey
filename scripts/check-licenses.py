#!/usr/bin/env python3
"""Check SPDX metadata and portable package copies of the canonical root license."""
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parent.parent
workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
if workspace["package"].get("license") != "Apache-2.0" or "license-file" in workspace["package"]:
    raise SystemExit("workspace must declare only license = Apache-2.0")
canonical = (root / "LICENSE").read_bytes()
for member in workspace["members"]:
    directory = root / member
    package = tomllib.loads((directory / "Cargo.toml").read_text())["package"]
    if package.get("license") != {"workspace": True} or "license-file" in package:
        raise SystemExit(f"{member}: inherit license.workspace without license-file")
    license_path = directory / "LICENSE"
    if (license_path.is_symlink() or not license_path.is_file()
            or license_path.read_bytes() != canonical):
        raise SystemExit(f"{member}: copy the root LICENSE into this crate as a regular file")
print(f"SPDX metadata and license copies verified for {len(workspace['members'])} crates")
