ANISAS 1.0.1 — Beta tester notes (2026-08-07)

Purpose

This document lists the experimental improvements included in the 1.0.1 beta and explains safe ways to evaluate the beta without affecting the stable v1.0.0 installation.

Key improvements (details)

- AI/ML accuracy improvements
  - Updated feature preprocessing and small refinements to the decision-tree training pipeline to reduce misclassification of embedded/IoT device types.

- Performance & memory
  - Parallel probe scheduling improvements and lazy-loading of heavy NLP model artifacts reduce scan time and peak memory.

- Plugin hooks
  - Added experimental hook points (extension_point.*) to load simple parsers/exporters; API is unstable and only available behind the `--enable-experimental` flag.

- Reporting and logs
  - Better PDF layout and structured JSON logs with correlation IDs for long-running scans.

How to test safely (non-destructive)

1. Create a separate worktree or clone the repo so stable files are not modified:

   git clone <repo-url> anisas-beta
   cd anisas-beta

   or (worktree):

   git worktree add ../anisas-beta HEAD
   cd ../anisas-beta

2. Option A — Try beta features without changing package metadata

   - Run scans from the beta copy directly (no install required):

     python -m anisas 8.8.8.8 --enable-experimental

   - Launch dashboard from the beta copy:

     python -m anisas.dashboard --port 8001 --no-browser

3. Option B — Install beta locally (isolated virtualenv)

   python -m venv .venv
   .\.venv\Scripts\Activate.ps1   # Windows PowerShell
   pip install -r requirements.txt
   pip install -e .

   (If you want the package to show the beta version, manually update anisas/__init__.py to set __version__ = "1.0.1-beta" in your test copy only.)

Notes

- Do NOT modify files in your main stable checkout. Use a clone or worktree for testing.
- Beta features are experimental. Report issues or feedback to the project's issue tracker and reference "beta-1.0.1" in the title.

Contact

For beta coordination, share test reports publicly or with the core maintainers as appropriate.