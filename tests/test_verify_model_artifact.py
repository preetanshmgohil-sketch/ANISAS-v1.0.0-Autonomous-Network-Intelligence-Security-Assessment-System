import tempfile
import pathlib
import subprocess
import hashlib


def test_verify_model_artifact_success():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        art = tmp_path / "model.bin"
        art.write_bytes(b"dummy-model-contents")
        sha = hashlib.sha256(art.read_bytes()).hexdigest()
        sha_file = tmp_path / "model.bin.sha256"
        # Write checksum in '<hex>  filename' format
        sha_file.write_text(f"{sha}  {art.name}")

        # Run verifier script
        proc = subprocess.run(["python", "scripts/verify_model_artifact.py", str(art), "--sha256-file", str(sha_file)])
        assert proc.returncode == 0
