"""CLI entry point for ANISAS Module 7 — Unified GUI Dashboard."""

from __future__ import annotations

import argparse
import sys


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anisas-dashboard",
        description="ANISAS Module 7 — Unified GUI Dashboard & Pipeline Orchestrator",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't auto-open browser",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn is required. Install with: pip install uvicorn", file=sys.stderr)
        sys.exit(1)

    print(f"Starting ANISAS Dashboard at http://{args.host}:{args.port}", file=sys.stderr)
    print("Press Ctrl+C to stop.", file=sys.stderr)

    if not args.no_browser:
        import webbrowser
        import threading
        def open_browser():
            import time
            time.sleep(1.5)
            webbrowser.open(f"http://{args.host}:{args.port}")
        threading.Thread(target=open_browser, daemon=True).start()

    from .app import app
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
