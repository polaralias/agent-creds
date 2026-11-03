#!/usr/bin/env python3
"""Create a platform archive containing the tested binary and its notices."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from version import ROOT, check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", choices=["x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"], required=True)
    parser.add_argument("--out", type=Path, default=Path("dist"))
    args = parser.parse_args()
    version = check()
    binary = args.binary.resolve(strict=True)
    observed = subprocess.check_output([str(binary), "--version"], text=True).strip()
    if observed != f"agent-creds {version}":
        parser.error("binary version does not match VERSION")
    args.out.mkdir(parents=True, exist_ok=True)
    basename = f"agent-creds-{version}-{args.target}"
    with tempfile.TemporaryDirectory() as temporary:
        package = Path(temporary) / basename
        package.mkdir()
        executable = package / ("agent-creds.exe" if "windows" in args.target else "agent-creds")
        shutil.copy2(binary, executable)
        executable.chmod(0o755)
        for name in ("LICENSE", "NOTICE", "README.md", "VERSION"):
            shutil.copy2(ROOT / name, package / name)
        shutil.copytree(ROOT / "docs", package / "docs")
        (package / "INSTALL.txt").write_text("Extract the archive, then run agent-creds --help (agent-creds.exe on Windows).\nLinux requires libdbus-1 and an unlocked Secret Service keyring; see docs/linux.md.\nAdd the executable directory to PATH if desired. Source builds: https://github.com/polaralias/agent-creds\n", encoding="utf-8")
        if "windows" in args.target:
            archive = args.out / f"{basename}.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
                for path in sorted(package.rglob("*")):
                    if path.is_file():
                        output.write(path, f"{basename}/{path.relative_to(package).as_posix()}")
        else:
            archive = args.out / f"{basename}.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(package, arcname=basename)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(f"{digest}  {archive.name}\n", encoding="utf-8", newline="\n")
    print(f"Packaged {archive.name}")


if __name__ == "__main__":
    main()
