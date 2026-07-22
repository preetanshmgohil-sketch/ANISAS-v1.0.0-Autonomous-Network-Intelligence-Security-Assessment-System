"""CLI entry point for ANISAS Module 2 — Network Reconnaissance Engine."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .engine import NetworkReconEngine
from .stealth import StealthConfig


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anisas-recon",
        description="ANISAS Module 2 — Network Reconnaissance Engine",
    )
    parser.add_argument(
        "target",
        help="Target CIDR prefix (e.g., 10.0.0.0/24) or Module 1 JSON report path",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output directory for reports (default: current directory)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print JSON to stdout only",
    )
    parser.add_argument(
        "--max-prefix-len",
        type=int,
        default=28,
        help="Maximum prefix length to enumerate (default: /28)",
    )
    parser.add_argument(
        "--no-stealth",
        action="store_true",
        help="Disable stealth mode (faster but more detectable)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Socket timeout in seconds per probe (default: 1.5)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Maximum concurrent threads (default: 100)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    _setup_logging(args.verbose)

    stealth = StealthConfig(
        enabled=not args.no_stealth,
        timeout_seconds=args.timeout,
        max_threads=args.threads,
    )

    engine = NetworkReconEngine(
        max_prefix_len=args.max_prefix_len,
        stealth=stealth,
    )

    out_dir = args.output or "."
    target_safe = args.target.replace("/", "_").replace(",", "_")[:50]

    json_path = None
    if not args.json_only:
        json_path = f"{out_dir}/recon_report_{target_safe}.json"

    try:
        report = engine.run(
            args.target,
            json_output=json_path,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Pipeline error: {exc}", file=sys.stderr)
        logging.getLogger(__name__).debug("Traceback:", exc_info=True)
        sys.exit(2)

    # Always print JSON to stdout
    print(report.model_dump_json(indent=2))

    if not args.json_only and json_path:
        print(f"\nJSON report: {json_path}", file=sys.stderr)
        print(f"Hosts found: {report.scan_metadata.total_hosts_found}", file=sys.stderr)
        print(f"Scan time:   {report.scan_metadata.scan_duration_seconds}s", file=sys.stderr)


if __name__ == "__main__":
    main()
