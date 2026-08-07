from anisas.sanitizer import sanitize_model, REDACTED
from pydantic import BaseModel


class DummyModel(BaseModel):
    email: str
    api_key: str
    notes: str


def test_sanitize_model_redacts_pii():
    d = DummyModel(
        email="user@example.com",
        api_key="dummy_api_key",
        notes="Observed on 203.0.113.5. Contact admin@example.com for details."
    )
    sanitized = sanitize_model(d)
    # sanitize_model attempts to reconstruct the same model class; allow dict fallback
    if hasattr(sanitized, "email"):
        assert sanitized.email == REDACTED
        assert sanitized.api_key == REDACTED
        assert "203.0.113.5" not in sanitized.notes
        assert "admin@example.com" not in sanitized.notes
    else:
        # dict fallback
        assert sanitized["email"] == REDACTED
        assert sanitized["api_key"] == REDACTED
        assert "203.0.113.5" not in sanitized["notes"]
        assert "admin@example.com" not in sanitized["notes"]
