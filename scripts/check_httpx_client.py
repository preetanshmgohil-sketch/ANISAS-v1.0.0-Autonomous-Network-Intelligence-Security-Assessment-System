"""Simple runtime check for the shared httpx.AsyncClient factory.

This script is intentionally dependency-free (no pytest). It verifies:
- get_client() returns the same instance on repeated calls
- aclose() closes and resets the shared client so a new instance is created afterwards

Run with: python scripts\check_httpx_client.py
Exit code 0 == success
"""

from __future__ import annotations

import asyncio
import os
import sys

# Ensure the repository root is on sys.path so `from anisas...` works when running
# the script from the scripts/ directory.
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from anisas.httpx_client import get_client, aclose


async def main() -> int:
    c1 = get_client()
    c2 = get_client()
    if c1 is not c2:
        print("ERROR: get_client() returned different instances", file=sys.stderr)
        return 2

    # ensure client has expected attributes
    if not hasattr(c1, "get") or not hasattr(c1, "aclose"):
        print("ERROR: client missing expected methods", file=sys.stderr)
        return 3

    # Close and ensure a new instance is created afterwards
    await aclose()
    c3 = get_client()
    if c3 is c1:
        print("ERROR: aclose() did not reset the client", file=sys.stderr)
        return 4

    await aclose()
    print("OK: shared httpx.AsyncClient behavior verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))