#!/usr/bin/env python3
"""
Simple artifact verifier: checks SHA256 checksum and optionally verifies a detached GPG signature
Usage: python scripts/verify_model_artifact.py /path/to/artifact --sha256-file artifact.sha256 [--sig artifact.asc]
"""
import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def read_expected_sha256(file: Path) -> str:
    # Support plain hex or "<hex>  <filename>" formats
    text = file.read_text(encoding="utf-8").strip()
    if not text:
        raise SystemExit("Checksum file is empty")
    # take first token that looks like hex
    for token in text.split():
        token = token.strip()
        if len(token) == 64 and all(c in '0123456789abcdefABCDEF' for c in token):
            return token.lower()
    raise SystemExit("Could not find a valid SHA256 hex in checksum file")


def verify_gpg_signature(artifact: Path, sig: Path) -> bool:
    gpg = shutil.which("gpg") or shutil.which("gpg2")
    if not gpg:
        print("gpg not found in PATH; skipping signature verification")
        return False
    try:
        subprocess.check_call([gpg, "--status-fd=1", "--verify", str(sig), str(artifact)])
        return True
    except subprocess.CalledProcessError:
        return False


def main():
    p = argparse.ArgumentParser(description="Verify model artifact SHA256 and optional GPG signature")
    p.add_argument("artifact", type=Path)
    p.add_argument("--sha256-file", type=Path, required=True, help="Path to .sha256 file containing expected checksum")
    p.add_argument("--sig", type=Path, help="Optional detached signature file to verify with gpg")
    args = p.parse_args()

    artifact = args.artifact
    if not artifact.exists():
        print(f"Artifact not found: {artifact}")
        sys.exit(2)

    sha_file = args.sha256_file
    if not sha_file.exists():
        print(f"Checksum file not found: {sha_file}")
        sys.exit(2)

    expected = read_expected_sha256(sha_file)
    actual = sha256_of_file(artifact)
    print(f"Expected: {expected}")
    print(f"Actual:   {actual}")
    if expected != actual:
        print("SHA256 mismatch! Do NOT use this artifact.")
        sys.exit(3)
    else:
        print("SHA256 verified OK")

    if args.sig:
        sig = args.sig
        if not sig.exists():
            print(f"Signature file not found: {sig}")
            sys.exit(2)
        ok = verify_gpg_signature(artifact, sig)
        if ok:
            print("GPG signature verification succeeded")
            sys.exit(0)
        else:
            print("GPG signature verification failed or skipped")
            sys.exit(4)

if __name__ == "__main__":
    main()
