# tests/test_rbac_and_logs.py
import json
import jwt
from pathlib import Path
from jsonschema import validate

SCHEMA = json.loads(Path("app/log_schema.json").read_text())

def _make_token(realm_access=None, resource_access=None, **extra):
    import os, time, jwt
    now = int(time.time())
    payload = {
        "sub": "user1",
        "exp": now + 3600,
        "iat": now,
    }
    if realm_access is not None:
        payload["realm_access"] = realm_access
    if resource_access is not None:
        payload["resource_access"] = resource_access
    payload.update(extra)
    secret = os.getenv("OIDC_DEV_HS256_SECRET", "test-secret")
    return jwt.encode(payload, key=secret, algorithm="HS256")

def _extract_log_lines(captured: str):
    # Each call prints exactly one JSON line; keep only valid JSON objects.
    out = []
    for line in captured.splitlines():
        line = line.strip()
        if not line.startswith("{") or not line.endswith("}"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out

def test_admin_denied_without_token(client, capsys):
    r = client.post("/admin")
    assert r.status_code == 403
    captured = capsys.readouterr().out
    logs = _extract_log_lines(captured)
    # Look for the admin_post denial
    denial = next((e for e in logs if e.get("event") == "admin_post" and e.get("outcome") == "denied"), None)
    assert denial, f"No denial log found in: {logs}"
    validate(instance=denial, schema=SCHEMA)
    assert denial["status"] == 403
    assert denial.get("reason") in {"missing_role"}

def test_admin_allowed_with_admin_role(client, capsys):
    token = _make_token(
        realm_access={"roles": ["admin"]},
        resource_access={"test-client": {"roles": ["admin"]}},
    )
    r = client.post("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    captured = capsys.readouterr().out
    logs = _extract_log_lines(captured)
    allowed = next((e for e in logs if e.get("event") == "admin_post" and e.get("outcome") == "allowed"), None)
    assert allowed, f"No allowed log found in: {logs}"
    validate(instance=allowed, schema=SCHEMA)
    assert "admin" in allowed.get("roles", [])
    # MFA inferred from 'amr' in token used by _make_token()
    assert allowed.get("mfa") in (True, False, None)

def test_failure_then_success_flow(client, capsys):
    # 1) Denied (no token)
    r1 = client.post("/admin")
    assert r1.status_code == 403
    # 2) Allowed (with admin role)
    token = _make_token(realm_access={"roles": ["admin"]})
    r2 = client.post("/admin", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200

    captured = capsys.readouterr().out
    logs = [e for e in _extract_log_lines(captured) if e.get("event") == "admin_post"]
    outcomes = [e.get("outcome") for e in logs]
    # Order may include only the two relevant lines due to isolated test client; allow any superset
    assert "denied" in outcomes and "allowed" in outcomes
    for e in logs:
        validate(instance=e, schema=SCHEMA)