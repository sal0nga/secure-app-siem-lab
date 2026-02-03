# app/auth.py
import os
from functools import wraps
from flask import request, jsonify, g
import jwt
from jwt import PyJWKClient, InvalidTokenError

OIDC_ISSUER   = os.getenv("OIDC_ISSUER")     # e.g., https://keycloak.local/realms/secure-lab
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE")   # your client_id
OIDC_JWKS_URL = os.getenv("OIDC_JWKS_URL")   # e.g., https://.../protocol/openid-connect/certs
OIDC_VERIFY   = os.getenv("OIDC_VERIFY", "true").lower() not in ("0","false","no")

# Dev verification materials (used only when OIDC_VERIFY is false)
OIDC_DEV_HS256_SECRET = os.getenv("OIDC_DEV_HS256_SECRET")  # symmetric test secret
OIDC_DEV_PUBLIC_KEY   = os.getenv("OIDC_DEV_PUBLIC_KEY")    # PEM-encoded RSA/EC public key

_jwks = PyJWKClient(OIDC_JWKS_URL) if OIDC_JWKS_URL else None

def _bearer_token():
    h = request.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return h[7:].strip()
    return None

def _extract_claim_roles(claims: dict) -> list[str]:
    roles = set()
    # Keycloak realm roles
    for r in (claims.get("realm_access", {}) or {}).get("roles", []) or []:
        roles.add(r)
    # Client (resource) roles
    aud = OIDC_AUDIENCE or claims.get("aud")
    ra = claims.get("resource_access") or {}
    if isinstance(aud, str) and aud in ra:
        for r in ra[aud].get("roles", []) or []:
            roles.add(r)
    return sorted(roles)

def verify_request_token():
    """
    If a valid token is present, populate g.user, g.sub, g.roles, g.mfa, g.session_id.
    If no/invalid token, leave them unset; route decorators decide what to do.
    """
    token = _bearer_token()
    if not token:
        return

    try:
        if OIDC_VERIFY:
            if not _jwks:
                # No JWKS configured: cannot verify — treat as authn error
                g.authn_error = "JWKS URL not configured; cannot verify token"
                return
            signing_key = _jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
                audience=OIDC_AUDIENCE,
                issuer=OIDC_ISSUER,
                options={"require": ["exp", "iat"]}
            )
        else:
            # Dev mode: still verify using a local key/secret instead of disabling verification
            if OIDC_DEV_HS256_SECRET:
                claims = jwt.decode(
                    token,
                    OIDC_DEV_HS256_SECRET,
                    algorithms=["HS256"],
                    audience=OIDC_AUDIENCE,
                    issuer=OIDC_ISSUER,
                    options={"require": ["exp", "iat"]}
                )
            elif OIDC_DEV_PUBLIC_KEY:
                claims = jwt.decode(
                    token,
                    OIDC_DEV_PUBLIC_KEY,
                    algorithms=["RS256"],
                    audience=OIDC_AUDIENCE,
                    issuer=OIDC_ISSUER,
                    options={"require": ["exp", "iat"]}
                )
            else:
                g.authn_error = "DEV verification key not set; set OIDC_DEV_HS256_SECRET or OIDC_DEV_PUBLIC_KEY"
                return
    except InvalidTokenError as e:
        # Mark an authn failure for downstream logging, but don't abort here
        g.authn_error = str(e)
        return

    g.sub         = claims.get("sub")
    g.user        = claims.get("preferred_username") or claims.get("email") or g.sub
    g.session_id  = claims.get("sid")
    g.roles       = _extract_claim_roles(claims)
    amr           = claims.get("amr") or []
    g.mfa         = bool("otp" in amr or "mfa" in amr)
    g.claims      = claims  # optional, handy for debugging

def current_roles() -> list[str]:
    return getattr(g, "roles", []) or []

def require_roles(required: list[str]):
    need = set(required)
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            roles = set(current_roles())
            if not need.issubset(roles):
                # Don’t log here; the route will log denial with context
                return jsonify(error="forbidden", missing=sorted(need - roles)), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator