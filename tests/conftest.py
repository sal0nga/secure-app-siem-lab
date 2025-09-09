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
    # Loosen verification for local tests; we inject tokens manually.
    os.environ.setdefault("OIDC_VERIFY", "false")
    os.environ.setdefault("OIDC_AUDIENCE", "test-client")
    os.environ.setdefault("OIDC_ISSUER", "https://example.test/realms/test")
    os.environ.setdefault("OIDC_JWKS_URL", f"{os.environ['OIDC_ISSUER']}/protocol/openid-connect/certs")
    yield

@pytest.fixture()
def app():
    return create_app()

@pytest.fixture()
def client(app):
    return app.test_client()