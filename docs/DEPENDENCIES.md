Dependency inventory and audit notes

This file lists the top-level dependencies declared in pyproject.toml and requirements.txt and provides guidance for pinning and auditing.

Declared dependencies (from pyproject.toml / requirements.txt):

- httpx>=0.27.0
- pydantic>=2.0.0
- reportlab>=4.0
- transformers>=4.30.0
- torch>=2.0.0
- fastapi>=0.100.0
- uvicorn>=0.23.0

Audit guidance

- Pin exact versions in production (e.g., httpx==0.27.4) and maintain a constraints file for reproducible installs.
- Run pip-audit regularly (CI workflow added). Investigate any CVEs and upgrade or patch accordingly.
- Inspect direct dependencies for install-time scripts (setup.py / pyproject hooks) that execute shell commands.
- Consider replacing high-risk non-essential packages or adding sandboxing for modules that execute untrusted code.
- Prefer wheels from official PyPI sources and signed releases where possible.

Automated updates

- Dependabot configured to open weekly PRs for pip dependency updates (.github/dependabot.yml).
- Review Dependabot PRs and run CI tests before merging.

Recommendations

- Create a constraints.txt by resolving dependencies in a clean environment and committing it to the repo.
- Consider using pip-tools or Poetry lockfiles for stronger reproducibility.
- Add a CI job to fail builds if pip-audit returns critical vulnerabilities for direct dependencies.
