Shared httpx.AsyncClient (anisas.httpx_client)

Summary
- Use anisas.httpx_client.get_client() to obtain a lazily-created shared httpx.AsyncClient.
- Call anisas.httpx_client.aclose() during application shutdown to gracefully close connections.

Why
- Reusing a single AsyncClient reduces TCP/TLS connection setup overhead and improves throughput across many short requests.

Usage
- Prefer passing an existing client to helper functions that accept a client parameter.
- If no client is provided, call get_client() to access the shared instance.

Shutdown
- In long-running applications, ensure aclose() is called on shutdown. Example (async):

    from anisas.httpx_client import aclose
    import asyncio

    async def shutdown():
        await aclose()

    # call shutdown() from your application's cleanup hook

Notes
- get_client() returns the same AsyncClient instance; do NOT call aclose() on it unless handling app shutdown.
- If independent, short-lived clients are needed, create your own httpx.AsyncClient(...) as before.