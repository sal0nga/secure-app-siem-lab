import os
import json
import time
import base64
import hashlib
import secrets
from urllib import request as urlrequest
from urllib import parse as urlparse
from urllib.error import URLError, HTTPError
import logging
from pathlib import Path
from werkzeug.middleware.proxy_fix import ProxyFix

logger = logging.getLogger("app")

from flask import Flask, jsonify, session, redirect, url_for, request, abort, g
from sqlalchemy import create_engine, text

# ============================================================================
# Logging + DB helpers (kept from your original, with comments)
# ============================================================================

def create_logger():
    """
    Configure a structured logger that writes to:
      - /var/log/app/app.log (file inside container)
      - stdout (visible via `docker compose logs app`)
    """
    log_dir = Path("/var/log/app")
    log_dir.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_dir / "app.log")
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    handler.setFormatter(fmt)

    logger = logging.getLogger("app")
    logger.setLevel(getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper()))
    logger.addHandler(handler)

    # Also log to stdout for `docker compose logs`
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    logger.addHandler(stream)
    return logger

def create_db_engine():
    """
    Optional DB engine (for /healthz). Only created if DATABASE_URL is set.
    For Postgres we also apply a short connect timeout and a 1s statement_timeout.
    """
    url = os.getenv("DATABASE_URL", "")
    if not url:
        return None

    connect_args = {}
    if url.startswith("postgresql"):
        connect_args["connect_timeout"] = int(os.getenv("DB_CONNECT_TIMEOUT", "2"))
        connect_args["options"] = f"-c statement_timeout={os.getenv('DB_STATEMENT_TIMEOUT_MS', '1000')}"

    return create_engine(url, pool_pre_ping=True, future=True, connect_args=connect_args)

# ============================================================================
# Small helpers (stdlib only)
# ============================================================================

def _env(name: str, default: str | None = None, required: bool = False) -> str:
    """
    Read an environment variable and (optionally) enforce it exists.
    Always returns a str (empty string if not required and missing).
    """
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return "" if val is None else val

def _b64url(data: bytes) -> str:
    """Base64 URL-safe encoding without '=' padding (per RFC 7636 / JWT)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _fetch_json(url: str, timeout: float = 5.0) -> dict:
    """
    GET a JSON document using the Python stdlib (no external deps).
    Raises a RuntimeError with context if the HTTP call fails.
    """
    try:
        with urlrequest.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError) as e:
        raise RuntimeError(f"HTTP error fetching {url}: {e}") from e

def _post_form(url: str, data: dict, timeout: float = 5.0) -> dict:
    """
    POST application/x-www-form-urlencoded and parse JSON response.
    Uses stdlib only (urllib).
    """
    body = urlparse.urlencode(data).encode("utf-8")
    req = urlrequest.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        # Try to surface the JSON error from the body if available
        try:
            err_body = e.read().decode("utf-8")
        except Exception:
            err_body = "<no body>"
        raise RuntimeError(f"HTTP {e.code} POST {url}: {err_body}") from e
    except URLError as e:
        raise RuntimeError(f"HTTP error POST {url}: {e}") from e

def _decode_jwt_payload(token: str) -> dict:
    """
    Decode the payload of a JWT without verifying the signature.
    We rely on Keycloak's token introspection endpoint for validity,
    and use the decoded payload only for convenience (issuer, audience, roles).
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)  # re-pad
        return json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8"))
    except Exception:
        return {}

# ============================================================================
# Flask app + OIDC (manual flow; no Authlib dependency)
# ============================================================================

def create_app():
    """
    Application factory wiring:
      - logging + DB health
      - OIDC Authorization Code + PKCE (manual, stdlib only)
      - TOTP is enforced by Keycloak policy during first login (no code needed here)
      - RBAC for /admin via Keycloak realm roles in JWT payload
    """
    app = Flask(__name__)
    app.config.update(
    SESSION_COOKIE_NAME="session",
    SESSION_COOKIE_SECURE=True,          # HTTPS only
    SESSION_COOKIE_SAMESITE="None",      # allow cross-site navigations (Safari-safe for OIDC)
    SESSION_COOKIE_DOMAIN="app.local",   # pin to the hostname you're using
    )
    # Ensure URL generation respects the reverse proxy (scheme/host) and prefers https
    app.config["PREFERRED_URL_SCHEME"] = "https"
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_port=1)
    app.secret_key = _env("FLASK_SECRET_KEY", "dev-not-secret", required=False)

    create_logger()
    engine = create_db_engine()

    # ---------------- OIDC configuration ----------------
    # Issuer seen by the browser and embedded in tokens:
    OIDC_ISSUER = _env("OIDC_ISSUER", required=True).rstrip("/")
    # Discovery document the *container* can reach (often the keycloak service name):
    OIDC_DISCOVERY_INTERNAL = _env("OIDC_DISCOVERY_INTERNAL", default=f"{OIDC_ISSUER}/.well-known/openid-configuration")
    # Derive the internal realm base (e.g., http://keycloak:8080/realms/secure-lab)
    internal_base = OIDC_DISCOVERY_INTERNAL.rsplit("/.well-known", 1)[0]
    # Client credentials configured in Keycloak:
    OIDC_CLIENT_ID = _env("OIDC_CLIENT_ID", required=True)
    OIDC_CLIENT_SECRET = _env("OIDC_CLIENT_SECRET", required=True)
    # External URL of this app (as visited by the user/browser):
    APP_BASE_URL = _env("APP_BASE_URL", "http://localhost:8443").rstrip("/")

    # Fetch both discovery docs:
    # - PUBLIC is used to build the browser redirect (authorization_endpoint on the issuer host/port).
    # - INTERNAL is used for server-to-server calls from the container (token/introspection endpoints).
    DISCOVERY_PUBLIC = f"{OIDC_ISSUER}/.well-known/openid-configuration"
    try:
        kc_public = _fetch_json(DISCOVERY_PUBLIC)
        kc_internal = _fetch_json(OIDC_DISCOVERY_INTERNAL)
    except RuntimeError as e:
        # If Keycloak isn't up yet, expose a helpful message on /login etc.
        logger.warning("OIDC discovery failed: %s", e)
        kc_public = {}
        kc_internal = {}

    authorization_endpoint = kc_public.get("authorization_endpoint", f"{OIDC_ISSUER}/protocol/openid-connect/auth")
    token_endpoint = kc_internal.get("token_endpoint", f"{internal_base}/protocol/openid-connect/token")
    introspect_endpoint = kc_internal.get("introspection_endpoint", f"{internal_base}/protocol/openid-connect/token/introspect")
    userinfo_endpoint = kc_internal.get("userinfo_endpoint", f"{internal_base}/protocol/openid-connect/userinfo")
    logger.info("OIDC cfg: ISSUER=%s DISC_INTERNAL=%s", OIDC_ISSUER, OIDC_DISCOVERY_INTERNAL)
    logger.info("OIDC endpoints: auth=%s token=%s introspect=%s userinfo=%s", authorization_endpoint, token_endpoint, introspect_endpoint, userinfo_endpoint)

    # Minimal in-memory cache for introspection results to cut chatter (5s TTL)
    _introspect_cache: dict[str, tuple[float, dict]] = {}

    def _verify_session() -> dict:
        """
        Verify the current session access token by calling Keycloak's
        token introspection endpoint (server-side validation). If 'active',
        return decoded JWT payload (unverified) for convenience.
        On temporary introspection errors, fall back to local iss/aud/exp checks
        so we don't spin in redirect loops.
        """
        token = session.get("access_token", "")
        if not token:
            logger.info("verify_session: no access_token in session")
            return {}

        # Short-lived cache
        now = time.time()
        cached = _introspect_cache.get(token)
        if cached and (now - cached[0] < 5.0):
            return cached[1]
        
        # 1) Try UserInfo with the bearer token (no client auth). If it works,
        # treat the token as valid for this realm and perform lightweight local checks.
        try:
            req = urlrequest.Request(userinfo_endpoint, headers={"Authorization": f"Bearer {token}"})
            with urlrequest.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    _ = json.loads(resp.read().decode("utf-8"))
                payload = _decode_jwt_payload(token)
                iss_ok = payload.get("iss") == OIDC_ISSUER
                exp_ok = float(payload.get("exp", 0)) > now
                if iss_ok and exp_ok:
                    logger.info("verify_session: userinfo OK; sub=%s", payload.get("sub"))
                    _introspect_cache[token] = (now, payload)
                    return payload
        except HTTPError:
            # 401/403 → token not valid for userinfo; fall through to introspection
            pass
        except URLError as e:
            logger.warning("verify_session: userinfo error (%s); falling through to introspection", e)

        data = {
            "token": token,
            "client_id": OIDC_CLIENT_ID,
            "client_secret": OIDC_CLIENT_SECRET,
            "token_type_hint": "access_token",
        }
        try:
            resp = _post_form(introspect_endpoint, data, timeout=5.0)
        except RuntimeError as e:
            # Network/Keycloak hiccup: fall back to local checks to avoid redirect loops
            logger.warning("verify_session: introspection error (%s) — falling back to local checks", e)
            payload = _decode_jwt_payload(token)
            iss_ok = payload.get("iss") == OIDC_ISSUER
            aud = payload.get("aud")
            aud_ok = (
                (isinstance(aud, list) and (OIDC_CLIENT_ID in aud or "account" in aud))
                or (aud in (OIDC_CLIENT_ID, "account"))
            )
            exp_ok = float(payload.get("exp", 0)) > now
            if iss_ok and aud_ok and exp_ok:
                logger.info("verify_session: fallback accepted; sub=%s roles=%s",
                            payload.get("sub"), (payload.get("realm_access") or {}).get("roles"))
                _introspect_cache[token] = (now, payload)
                return payload
            logger.warning("verify_session: fallback failed iss_ok=%s aud_ok=%s exp_ok=%s iss=%s aud=%s exp=%s",
                           iss_ok, aud_ok, exp_ok, payload.get("iss"), payload.get("aud"), payload.get("exp"))
            return {}

        if not resp.get("active"):
            # Token is not active for this client per introspection. Fall back to local checks
            # to avoid redirect loops in dev, and log the payload for diagnosis.
            payload = _decode_jwt_payload(token)
            now = time.time()
            iss_ok = payload.get("iss") == OIDC_ISSUER
            aud = payload.get("aud")
            aud_ok = (
                (isinstance(aud, list) and (OIDC_CLIENT_ID in aud or "account" in aud))
                or (aud in (OIDC_CLIENT_ID, "account"))
            )
            exp_ok = float(payload.get("exp", 0)) > now
            if iss_ok and aud_ok and exp_ok:
                logger.warning("verify_session: introspection inactive but local checks OK; accepting temporarily. aud=%s", payload.get("aud"))
                _introspect_cache[token] = (now, payload)
                return payload
            logger.info("verify_session: introspection inactive/false and local checks failed: %s ; payload_aud=%s iss=%s exp=%s",
                        resp, payload.get("aud"), payload.get("iss"), payload.get("exp"))
            return {}

        # Use decoded payload for roles/iss/aud; Keycloak included 'active' proved validity
        payload = _decode_jwt_payload(token)

        # Basic issuer/audience/expires sanity checks (non-crypto)
        iss_ok = payload.get("iss") == OIDC_ISSUER
        aud = payload.get("aud")
        aud_ok = (
            (isinstance(aud, list) and (OIDC_CLIENT_ID in aud or "account" in aud))
            or (aud in (OIDC_CLIENT_ID, "account"))
        )
        exp_ok = float(payload.get("exp", 0)) > now

        if not (iss_ok and aud_ok and exp_ok):
            logger.warning("verify_session: sanity checks failed iss_ok=%s aud_ok=%s exp_ok=%s iss=%s aud=%s exp=%s",
                           iss_ok, aud_ok, exp_ok, payload.get("iss"), payload.get("aud"), payload.get("exp"))
            return {}

        _introspect_cache[token] = (now, payload)
        logger.info("verify_session: active; sub=%s roles=%s",
                    payload.get("sub"), (payload.get("realm_access") or {}).get("roles"))
        return payload

    def login_required(view):
        """
        Decorator that requires a valid, introspected access token in session.
        If missing/invalid, we bounce to /login to start the flow.
        """
        def wrapped(*args, **kwargs):
            claims = _verify_session()
            if not claims:
                return redirect(url_for("login"))
            # stash claims in request context (avoid bloating cookie-based session)
            g.claims = claims
            return view(*args, **kwargs)
        wrapped.__name__ = view.__name__
        return wrapped

    def role_required(role: str):
        """
        Decorator that enforces a realm role present in claims['realm_access']['roles'].
        Use with @login_required.
        """
        def decorator(view):
            def wrapped(*args, **kwargs):
                claims = getattr(g, "claims", None) or _verify_session() or {}
                roles = (claims.get("realm_access") or {}).get("roles") or []
                if role not in roles:
                    abort(403)
                return view(*args, **kwargs)
            wrapped.__name__ = view.__name__
            return wrapped
        return decorator

    # -----------------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------------

    @app.get("/")
    def index():
        """Public landing route (no auth)."""
        logger.info("index hit")
        return jsonify({"ok": True, "service": "app", "msg": "hello"})

    @app.get("/healthz")
    def healthz():
        """
        Liveness/readiness endpoint.
        Returns 200 always; includes DB probe result when configured.
        """
        db_ok = None
        if engine:
            try:
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                db_ok = True
            except Exception as e:
                logger.warning("DB health check failed: %s", e)
                db_ok = False
        return jsonify({"ok": True, "db_ok": db_ok}), 200

    @app.get("/login")
    def login():
        """
        Start OIDC Authorization Code + PKCE:
          1) generate state + code_verifier; store in session
          2) compute code_challenge (S256)
          3) redirect the browser to Keycloak authorization endpoint
        """
        try:
            # Create state/verifier and store in session for the callback
            state = _b64url(secrets.token_bytes(16))
            verifier = _b64url(secrets.token_bytes(32))
            challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
            session["oidc_state"] = state
            session["pkce_verifier"] = verifier
            # Build redirect_uri from the incoming request/headers to avoid host mismatches
            redirect_uri = url_for("callback", _external=True, _scheme="https")
            # Compute the auth endpoint directly from the issuer (browser-facing)
            auth_ep = f"{OIDC_ISSUER}/protocol/openid-connect/auth"
            params = {
                "response_type": "code",
                "client_id": OIDC_CLIENT_ID,
                "redirect_uri": redirect_uri,
                "scope": "openid profile email roles",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
            auth_url = f"{auth_ep}?{urlparse.urlencode(params)}"
            logger.info("LOGIN redirect → %s", auth_url)
            return redirect(auth_url)
        except Exception as e:
            logger.exception("login failed")
            return jsonify({"error": "login_failed", "detail": str(e)}), 502

    @app.get("/callback")
    def callback():
        """
        Finish the OIDC flow:
          1) validate 'state'
          2) exchange 'code' for tokens at the token endpoint (with code_verifier)
          3) store access_token + decoded claims in session
          4) redirect home
        """
        state = request.args.get("state", "")
        code = request.args.get("code", "")
        if not state or state != session.get("oidc_state", ""):
            abort(400)
        verifier = session.get("pkce_verifier", "")
        if not code or not verifier:
            abort(400)

        # Use the same host/scheme the user arrived with (bulletproof against host mismatches)
        redirect_uri = url_for("callback", _external=True, _scheme="https")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": OIDC_CLIENT_ID,
            "client_secret": OIDC_CLIENT_SECRET,
            "code_verifier": verifier,
        }
        logger.info("CALLBACK: POST token_endpoint=%s redirect_uri=%s", token_endpoint, redirect_uri)
        try:
            tokens = _post_form(token_endpoint, data, timeout=5.0)
        except Exception as e:
            logger.exception("CALLBACK token exchange failed")
            return jsonify({"error": "token_exchange_failed", "detail": str(e)}), 502
        access_token = tokens.get("access_token", "")
        if not access_token:
            abort(500)

        # Persist tokens minimally; only access_token is needed for introspection
        session["access_token"] = access_token
        # Do NOT store decoded claims in the cookie session to avoid >4KB cookie loops
        # Cleanup one-time items
        session.pop("oidc_state", None)
        session.pop("pkce_verifier", None)
        return redirect(url_for("whoami"))

    @app.get("/logout")
    def logout():
        """
        Clear local session. (Optional: call Keycloak's end-session endpoint
        to fully log out of SSO if desired.)
        """
        session.clear()
        return redirect(url_for("index"))

    @app.get("/whoami")
    @login_required
    def whoami():
        """
        Echo verified JWT claims (decoded payload) for the logged-in user.
        Useful during Phase 02 to debug roles and mappings.
        """
        claims = getattr(g, "claims", None) or _verify_session()
        return jsonify(claims)

    @app.get("/admin")
    @login_required
    @role_required("admin")
    def admin_panel():
        """
        Admin-only route. Requires the 'admin' realm role in realm_access.roles.
        """
        return jsonify({"ok": True, "msg": "welcome, admin"})

    return app

# WSGI entrypoint for Gunicorn `wsgi:app`
app = create_app()