Artifact integrity and signing

This project requires model artifacts (weights, checkpoints, packaged models) to include integrity metadata and, when possible, signatures.

Creating checksums

- Use scripts/create_checksum.py to create a SHA256 checksum file alongside the artifact:

  python scripts/create_checksum.py /path/to/model.bin

- The script writes model.bin.sha256 containing a line: <hex>  model.bin

Signing artifacts

- If maintainers have a GPG key, create a detached signature:

  python scripts/create_checksum.py /path/to/model.bin --sign

- Verify signatures with scripts/verify_model_artifact.py --sig model.bin.asc

Provenance

- Record provenance metadata (source URL, release tag, build environment) in a small JSON file next to the artifact (example: model.bin.prov.json). Include fields: source, release, built_by, build_date, checksum.

Storage and distribution

- Prefer hosting artifacts on signed releases or verified package registries.
- Avoid distributing artifacts via untrusted third-party storage without checksums and signatures.

Verification

- The CI workflow (.github/workflows/security-audit.yml) runs verification over any checked-in .sha256 files. Always verify before consuming artifacts.
