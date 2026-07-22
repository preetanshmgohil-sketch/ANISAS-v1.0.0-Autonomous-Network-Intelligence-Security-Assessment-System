"""CLI entry point for ANISAS Module 3 — Security Perimeter Detection."""

from __future__ import annotations

import argparse
import logging
import sys

from .engine import SecurityPerimeterEngine


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anisas-perimeter",
        description="ANISAS Module 3 — Security Perimeter Detection & Evasion Analysis",
    )
    parser.add_argument(
        "target",
        help="Target IP address or Module 2 JSON report path",
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
        "--timeout",
        type=float,
        default=2.0,
        help="Socket timeout per probe (default: 2.0s)",
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

    engine = SecurityPerimeterEngine(timeout=args.timeout)

    out_dir = args.output or "."
    target_safe = args.target.replace("/", "_").replace("\\", "_")[:50]

    json_path = None
    if not args.json_only:
        json_path = f"{out_dir}/perimeter_report_{target_safe}.json"

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

    print(report.model_dump_json(indent=2))

    if not args.json_only and json_path:
        print(f"\nJSON report: {json_path}", file=sys.stderr)
        posture = report.overall_security_posture
        print(f"Risk Level: {posture.risk_level}", file=sys.stderr)
        defs = report.perimeter_defenses
        print(f"Firewall: {defs['firewall']['detected']}", file=sys.stderr)
        print(f"IDS/IPS:  {defs['ids_ips']['detected']}", file=sys.stderr)
        print(f"DMZ:      {defs['dmz']['detected']}", file=sys.stderr)
        print(f"WAF:      {defs['waf']['detected']}", file=sys.stderr)


if __name__ == "__main__":
    main()
