# app/logging_utils.py
import json, os
from datetime import datetime, timezone
from flask import request, g


APP_VERSION = os.getenv("APP_VERSION", "0.3.0")

DEFAULT_LARGE_RESP_BYTES = 65536  # 64 KiB default
def _get_large_resp_bytes() -> int:
    try:
        return int(os.getenv("LOG_LARGE_RESP_BYTES", str(DEFAULT_LARGE_RESP_BYTES)))
    except (TypeError, ValueError):
        return DEFAULT_LARGE_RESP_BYTES

def is_large_response(n: int | None) -> bool:
    """Return True if response length exceeds LOG_LARGE_RESP_BYTES."""
    threshold = _get_large_resp_bytes()
    return n is not None and n > threshold

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _client_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr

def log_event(event: str, **extra):
    payload = {
        "ts": _now(),
        "event": event,
        "trace_id": getattr(g, "trace_id", None),
        "user": extra.pop("user", None),
        "sub": extra.pop("sub", None),
        "session_id": extra.pop("session_id", None),
        "src_ip": _client_ip(),
        "outcome": extra.pop("outcome", None),
        "reason": extra.pop("reason", None),
        "path": request.path,
        "method": request.method,
        "status": extra.pop("status", None),
        "resp_bytes": extra.pop("resp_bytes", None),
        "roles": extra.pop("roles", []),
        "mfa": extra.pop("mfa", None),
        "authn_client": extra.pop("authn_client", "keycloak"),
        "app_version": APP_VERSION,
    }
    payload.update(extra)
    print(json.dumps(payload), flush=True)