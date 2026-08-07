"""CLI entry point for ANISAS Module 1 — ASN & ISP Intelligence Engine."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .engine import run_engine


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    try:
        from .logging_config import configure_logging
        configure_logging(level=level)
    except Exception:
        # Fallback to basic config if custom configure fails
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
        default=None,
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


async def _async_main(args: argparse.Namespace) -> int:
    ip = args.ip
    out_dir = args.output or "."

    if args.json_only:
        json_path = None
        pdf_path = None
    else:
        json_path = f"{out_dir}/anisas_report_{ip.replace(':', '_')}.json"
        pdf_path = f"{out_dir}/anisas_report_{ip.replace(':', '_')}.pdf"

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
