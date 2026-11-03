#!/usr/bin/env python3
"""Verify Cargo's actual source-file list against the release boundary."""
import argparse
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
from version import ROOT

ROOT_FILES = {".cargo_vcs_info.json", "Cargo.lock", "Cargo.toml", "Cargo.toml.orig", "LICENSE", "NOTICE", "README.md", "VERSION", "build.rs"}


def validate_paths(paths):
    normalized = {name.replace("\\", "/") for name in paths if name}
    for name in normalized:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not (name in ROOT_FILES or name.startswith(("src/", "docs/"))):
            raise ValueError("Cargo includes a file outside the public source boundary")
    if not {"LICENSE", "NOTICE", "VERSION", "README.md", "build.rs", "src/main.rs"} <= normalized:
        raise ValueError("Cargo omits a required release file")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default=shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo.exe"))
    args = parser.parse_args()
    local = ROOT / "local-docs"
    local.mkdir(exist_ok=True)
    # Exercise the original failure with real ignored files, not a model of
    # Cargo's include-pattern implementation.
    with tempfile.TemporaryDirectory(prefix="package-boundary-", dir=local) as temporary:
        fixture = Path(temporary)
        (fixture / "docs").mkdir()
        (fixture / "README.md").write_text("Synthetic excluded package fixture.\n")
        (fixture / "docs/security.md").write_text("Synthetic excluded package fixture.\n")
        result = subprocess.run([args.cargo, "package", "--locked", "--allow-dirty", "--offline", "--list"], cwd=ROOT, check=True, capture_output=True, text=True)
        validate_paths(result.stdout.splitlines())
    print("Cargo source boundary verified against ignored README/docs fixtures")


if __name__ == "__main__":
    main()
