"""Shared httpx.AsyncClient factory.

Provides lazy creation and aclose() for a single shared AsyncClient to reduce
connection setup/teardown overhead across the application.
"""

from __future__ import annotations

from typing import Optional

import httpx

# Match existing modules' timeout configuration
_TIMEOUT = httpx.Timeout(8.0, connect=5.0)

_client: Optional[httpx.AsyncClient] = None


def get_client() -> httpx.AsyncClient:
    """Return a shared AsyncClient, creating it lazily if necessary.

    The client is returned as-is; callers that need an independent client should
    create their own. Callers MUST NOT call aclose() on the returned client
    unless they own its lifecycle.
    """
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
    return _client


async def aclose() -> None:
    """Close the shared client if it exists.

    Intended to be called during application shutdown to release resources.
    """
    global _client
    if _client is not None:
        try:
            await _client.aclose()
        finally:
            _client = None
