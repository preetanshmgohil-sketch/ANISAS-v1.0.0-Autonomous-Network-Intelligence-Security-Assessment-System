Security Policy

Reporting

If you discover a security vulnerability or supply-chain issue in this repository or its artifacts, please open a private security issue (if available) or contact the maintainers directly. Include: a concise summary, proof-of-concept steps, affected versions, and remediation suggestions. If you need to share sensitive exploit details, request an email address or coordinated disclosure channel from the maintainers.

Model artifact integrity

All model artifacts (weights, checkpoints, packaged models) must ship with a SHA256 checksum file (*.sha256) and, when possible, a detached GPG signature (*.asc). Use the included script scripts/verify_model_artifact.py to validate checksums and optionally signatures before use.

Supply-chain and dependency guidance

- Pin direct dependencies where possible and prefer reproducible build directives.
- Review install-time scripts in dependencies for network or shell execution.
- Use verified sources for model weights; prefer signed, checksummed releases.
- Enable automated dependency scanning (Dependabot, Snyk, OSV) in CI.

Report sanitization and PII

- Reports and logs must avoid including PII or identifying information by default.
- Use configurable sanitization routines when generating reports; default to redaction of IPs, emails, and API tokens.

Runtime safety and resource limits

- Enforce container or process-level CPU/memory limits and timeouts for model inference/training jobs.
- Apply quotas to prevent resource exhaustion and runaway processes.

CI and deployment hardening

- Avoid storing long-lived credentials in workflows. Use short-lived tokens and least privilege roles.
- Enable secret scanning and require branch protection for deployment branches.
- Prefer self-hosted runners with restricted scopes only when necessary.

Contact and disclosure

For coordinated disclosure or to report an urgent incident, please open an issue and mark it "security" or reach out to the maintainers listed in the repository's README. Provide a secure contact method if needed.
