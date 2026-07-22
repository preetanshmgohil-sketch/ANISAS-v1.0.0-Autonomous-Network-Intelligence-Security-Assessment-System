"""CLI entry point for ANISAS Module 6 — AI/ML Classification & Anomaly Detection."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .engine import AIMLEngine


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anisas-ai",
        description="ANISAS Module 6 — AI/ML Classification & Anomaly Detection",
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        help="Module JSON files (mod1.json mod2.json ... mod5.json)",
    )
    parser.add_argument(
        "-m1", "--module1", default=None, help="Module 1 JSON path"
    )
    parser.add_argument(
        "-m2", "--module2", default=None, help="Module 2 JSON path"
    )
    parser.add_argument(
        "-m3", "--module3", default=None, help="Module 3 JSON path"
    )
    parser.add_argument(
        "-m4", "--module4", default=None, help="Module 4 JSON path"
    )
    parser.add_argument(
        "-m5", "--module5", default=None, help="Module 5 JSON path"
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory for reports",
    )
    parser.add_argument(
        "--json-only", action="store_true",
        help="Print JSON to stdout only",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    _setup_logging(args.verbose)

    engine = AIMLEngine()

    # Build module paths from arguments
    paths = {}
    if args.module1:
        paths["module1"] = args.module1
    if args.module2:
        paths["module2"] = args.module2
    if args.module3:
        paths["module3"] = args.module3
    if args.module4:
        paths["module4"] = args.module4
    if args.module5:
        paths["module5"] = args.module5

    # Also accept positional args as module files
    if args.inputs:
        for i, path in enumerate(args.inputs, 1):
            key = f"module{i}"
            if key not in paths:
                paths[key] = path

    out_dir = args.output or "."

    json_path = None
    if not args.json_only:
        json_path = f"{out_dir}/ai_engine_report.json"

    try:
        report = engine.run(paths, json_output=json_path)
    except Exception as exc:
        print(f"Pipeline error: {exc}", file=sys.stderr)
        logging.getLogger(__name__).debug("Traceback:", exc_info=True)
        sys.exit(2)

    print(report.model_dump_json(indent=2))

    if not args.json_only and json_path:
        s = report.ai_analytics_summary
        print(f"\nJSON report: {json_path}", file=sys.stderr)
        print(f"Devices analyzed:  {s.total_devices_analyzed}", file=sys.stderr)
        print(f"Anomalies found:   {s.anomalies_detected_count}", file=sys.stderr)
        print(f"Health score:      {s.network_health_score}/100", file=sys.stderr)


if __name__ == "__main__":
    main()
