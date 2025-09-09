# tests/conftest.py
import os
import pytest
import sys
from pathlib import Path

# Ensure project root is importable for 'app' when tests run from any cwd
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app

@pytest.fixture(scope="session", autouse=True)
def _env():
    # Test env: enable dev verification (HS256) and disable JWKS path.
    os.environ.setdefault("OIDC_VERIFY", "false")
    os.environ.setdefault("OIDC_DEV_HS256_SECRET", "test-secret")
    # Do not enforce audience/issuer in tests unless explicitly set.
    os.environ.pop("OIDC_JWKS_URL", None)
    os.environ.pop("OIDC_AUDIENCE", None)
    os.environ.pop("OIDC_ISSUER", None)
    yield

@pytest.fixture()
def app():
    return create_app()

@pytest.fixture()
def client(app):
    return app.test_client()