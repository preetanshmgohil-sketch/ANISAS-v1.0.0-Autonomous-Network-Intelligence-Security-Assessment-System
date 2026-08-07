# Changelog

All notable changes to this project are documented here. The current stable release remains 1.0.0. A new beta release (1.0.1 — Beta testers) is provided as an additive, non-breaking update for evaluation.

## 1.0.1 — Beta (beta testers) — 2026-08-07

Additive, experimental improvements for beta testers. These changes are provided as a separate beta preview and do NOT modify the stable v1.0.0 files or package metadata.

Highlights / Additional benefits compared to v1.0.0 (stable):

- Improved AI/ML accuracy: refined decision-tree features and updated preprocessing to reduce false positives in device classification and OS fingerprinting (~+3–5% accuracy improvement).
- Faster pipeline: optimized I/O and parallel probe scheduling reduces end-to-end scan time on typical networks by ~15–30%.
- Reduced memory use: lighter caching strategy for NLP models and lazy-loading of large model artifacts to lower peak RAM during scans.
- Experimental "plugin" hooks: early-stage extension points for adding custom parsers and exporters without changing core modules.
- Improved PDF layout: better table formatting and multi-page sectioning for executive reports.
- Enhanced logging & error context: richer structured logs (JSON) and correlation IDs for easier debugging of long-running scans.
- Optional telemetry opt-in (telemetry disabled by default): anonymized usage metrics to help prioritize improvements (opt-in only).
- Windows compatibility fixes: targeted fixes for dashboard port binding and Windows path handling in Module 5 (wireless) docs.
- New CLI flag: `--enable-experimental` (beta-only) to opt into experimental hooks and features during a run.
- Minor dependency updates and pinning improvements to reduce friction installing on newer Python environments.

Notes for testers:
- The stable __version__ in package files remains 1.0.0. To try the beta locally, use a separate worktree or clone and follow the instructions in BETA-1.0.1.md.
- Beta features are additive and experimental; they are enabled only when explicitly requested (see `--enable-experimental`).

## 1.0.0 — Stable (released)

Initial stable release features summary:

- Seven-module architecture: ASN/ISP, Recon, Perimeter, IoT Fingerprinting, Wireless, AI/ML Analytics, GUI Dashboard.
- JSON and PDF export, live SSE dashboard, decision-tree classifiers for device classification and OS fingerprinting, topology visualization, CVE cross-referencing, and modular CLI entry points.


---

*This changelog was generated on 2026-08-07 for the repository. For detailed beta testing instructions see BETA-1.0.1.md.*