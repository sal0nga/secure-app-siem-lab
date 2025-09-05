# app/logging_utils.py
import json, os
from datetime import datetime, timezone
from flask import request, g

APP_VERSION = os.getenv("APP_VERSION", "0.3.0")

def _now():
    return datetime.now(timezone.utc).isoformat()

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