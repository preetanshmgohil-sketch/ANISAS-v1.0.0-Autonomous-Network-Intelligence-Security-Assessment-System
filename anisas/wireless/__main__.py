"""CLI entry point for ANISAS Module 5 — Wireless Network Intelligence."""

from __future__ import annotations

import argparse
import logging
import sys

from .engine import WirelessIntelligenceEngine


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anisas-wireless",
        description="ANISAS Module 5 — Wireless Network Intelligence & MAC Analysis",
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Network interface for MAC cloning (auto-detected if not specified)",
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
        "--no-dry-run",
        action="store_true",
        help="Actually perform MAC cloning (default: dry run only)",
    )
    parser.add_argument(
        "--bssid",
        default=None,
        help="Target BSSID for focused analysis",
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

    engine = WirelessIntelligenceEngine(
        interface=args.interface,
        dry_run=not args.no_dry_run,
        target_bssid=args.bssid,
    )

    out_dir = args.output or "."

    json_path = None
    if not args.json_only:
        json_path = f"{out_dir}/wireless_report.json"

    try:
        report = engine.run(json_output=json_path)
    except Exception as exc:
        print(f"Pipeline error: {exc}", file=sys.stderr)
        logging.getLogger(__name__).debug("Traceback:", exc_info=True)
        sys.exit(2)

    print(report.model_dump_json(indent=2))

    if not args.json_only and json_path:
        print(f"\nJSON report: {json_path}", file=sys.stderr)
        print(f"APs found:       {len(report.access_points)}", file=sys.stderr)
        print(f"Clients found:   {len(report.enumerated_clients)}", file=sys.stderr)
        print(f"Anomalous:       {len(report.ai_anomaly_detection.anomalous_devices_flagged)}", file=sys.stderr)
        print(f"Recommendations: {len(report.hardening_recommendations)}", file=sys.stderr)


if __name__ == "__main__":
    main()
