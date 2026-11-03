#!/usr/bin/env python3
"""Check or update the single release version and its Cargo mirrors."""
import argparse
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SEMVER = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"


def check(root=ROOT, tag=None):
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(SEMVER, version):
        raise ValueError("VERSION must contain a stable X.Y.Z version")
    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    package = manifest["package"]
    if package["name"] != "agent-creds" or package["version"] != version:
        raise ValueError("Cargo.toml identity/version differs from VERSION")
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    matches = [p for p in lock["package"] if p["name"] == "agent-creds"]
    if len(matches) != 1 or matches[0]["version"] != version:
        raise ValueError("Cargo.lock version differs from VERSION")
    if tag is not None and tag != f"v{version}":
        raise ValueError("release tag differs from VERSION")
    return version


def set_version(value, root=ROOT):
    if not re.fullmatch(SEMVER, value):
        raise ValueError("version must be a stable X.Y.Z version")
    current = check(root)
    paths = [root / name for name in ("VERSION", "Cargo.toml", "Cargo.lock")]
    originals = [p.read_bytes() for p in paths]
    manifest = paths[1].read_text(encoding="utf-8")
    manifest, count = re.subn(r'(?m)^version = "' + re.escape(current) + r'"$', f'version = "{value}"', manifest, count=1)
    if count != 1:
        raise ValueError("cannot locate Cargo package version")
    lock = paths[2].read_text(encoding="utf-8")
    lock, count = re.subn(r'(\[\[package\]\]\nname = "agent-creds"\nversion = ")' + re.escape(current) + '"', lambda m: m[1] + value + '"', lock)
    if count != 1:
        raise ValueError("cannot locate Cargo lock entry")
    try:
        for path, text in zip(paths, (value + "\n", manifest, lock)):
            path.write_text(text, encoding="utf-8", newline="\n")
        check(root)
    except Exception:
        for path, original in zip(paths, originals):
            path.write_bytes(original)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--set", metavar="X.Y.Z")
    parser.add_argument("--tag", help="Require an exact vX.Y.Z release tag")
    args = parser.parse_args()
    try:
        if args.set is not None:
            set_version(args.set)
        print(f"agent-creds version {check(tag=args.tag)} is consistent")
    except (ValueError, KeyError, OSError, tomllib.TOMLDecodeError) as error:
        parser.exit(1, f"version check: {error}\n")


if __name__ == "__main__":
    main()
