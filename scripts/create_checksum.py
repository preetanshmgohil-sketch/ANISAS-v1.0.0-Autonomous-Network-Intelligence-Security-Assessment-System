#!/usr/bin/env python3
"""
Create a SHA256 checksum file for an artifact and optionally create a detached GPG signature.
Usage: python scripts/create_checksum.py /path/to/artifact [--sign]
"""
import argparse
import hashlib
import subprocess
from pathlib import Path
import sys


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description="Create SHA256 checksum and optional GPG signature")
    p.add_argument("artifact", type=Path)
    p.add_argument("--sign", action="store_true", help="Create a detached GPG signature (.asc) if gpg is available")
    args = p.parse_args()

    art = args.artifact
    if not art.exists():
        print(f"Artifact not found: {art}")
        sys.exit(2)

    sha = sha256_of_file(art)
    sha_file = art.with_suffix(art.suffix + ".sha256")
    # write in common '<hex>  filename' format
    sha_file.write_text(f"{sha}  {art.name}\n", encoding="utf-8")
    print(f"Wrote checksum: {sha_file}")

    if args.sign:
        gpg = shutil.which("gpg") or shutil.which("gpg2")
        if not gpg:
            print("gpg not found in PATH; cannot sign")
            return
        sig = art.with_suffix(art.suffix + ".asc")
        subprocess.check_call([gpg, "--armor", "--detach-sign", "-o", str(sig), str(art)])
        print(f"Created detached signature: {sig}")

if __name__ == '__main__':
    import shutil
    main()
