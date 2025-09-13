# tests/conftest.py
import os
import pytest
import sys
from pathlib import Path

# --- Force test env BEFORE importing the app (CI-safe) ---
os.environ["OIDC_VERIFY"] = "false"
os.environ["OIDC_DEV_HS256_SECRET"] = os.environ.get("OIDC_DEV_HS256_SECRET", "test-secret")
# Avoid prod verification path & mismatches during tests
os.environ.pop("OIDC_JWKS_URL", None)
os.environ.pop("OIDC_AUDIENCE", None)
os.environ.pop("OIDC_ISSUER", None)
# ---------------------------------------------------------

# Ensure project root is importable for 'app'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # import AFTER env is set

@pytest.fixture()
def app():
    return create_app()

@pytest.fixture()
def client(app):
    return app.test_client()