# tests/conftest.py
import os
import pytest
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