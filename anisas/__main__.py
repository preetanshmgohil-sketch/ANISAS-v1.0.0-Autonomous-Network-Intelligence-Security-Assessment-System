"""CLI entry point for ANISAS Module 1 — ASN & ISP Intelligence Engine."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from ._safety import safe_filename, safe_path
from .engine import run_engine


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anisas",
        description="ANISAS Module 1 — ASN & ISP Intelligence Engine",
    )
    parser.add_argument(
        "ip",
        help="Target public IPv4 or IPv6 address",
    )
    parser.add_argument(
        "-o", "--output",
        default=".",
        help="Output directory for reports (default: current directory)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print JSON to stdout only (no PDF)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def _validate_output_dir(output_dir: str) -> str:
    """Canonicalize and validate the output directory."""
    resolved = Path(output_dir).resolve()
    if not resolved.is_dir():
        try:
            resolved.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ValueError(f"Cannot create output directory {resolved}: {exc}") from exc
    return str(resolved)


def _build_output_paths(base_dir: str, ip: str) -> tuple[str | None, str | None]:
    """Build safe, sanitized output file paths within base_dir."""
    safe_ip = safe_filename(ip)
    json_path = safe_path(base_dir, f"anisas_report_{safe_ip}.json")
    pdf_path = safe_path(base_dir, f"anisas_report_{safe_ip}.pdf")
    return json_path, pdf_path


async def _async_main(args: argparse.Namespace) -> int:
    ip = args.ip

    if args.json_only:
        json_path = None
        pdf_path = None
    else:
        base_dir = _validate_output_dir(args.output)
        json_path, pdf_path = _build_output_paths(base_dir, ip)

    try:
        report = await run_engine(
            target_ip=ip,
            pdf_output=pdf_path,
            json_output=json_path,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Pipeline error: {exc}", file=sys.stderr)
        logging.getLogger(__name__).debug("Traceback:", exc_info=True)
        return 2

    # Always print JSON to stdout
    print(report.model_dump_json(indent=2))

    if not args.json_only:
        print(f"\nPDF report:  {pdf_path}", file=sys.stderr)
        print(f"JSON report: {json_path}", file=sys.stderr)

    return 0


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    _setup_logging(args.verbose)
    exit_code = asyncio.run(_async_main(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
