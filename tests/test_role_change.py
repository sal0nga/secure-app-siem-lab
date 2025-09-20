import json
from pathlib import Path
from jsonschema import validate
import jwt

SCHEMA = json.loads(Path("app/log_schema.json").read_text())

def _extract(out: str):
    evts = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                evts.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return evts

def _token_with_admin(**extra):
    import os, time, jwt
    now = int(time.time())
    payload = {
        "sub": "admin-user",
        "realm_access": {"roles": ["admin"]},
        "resource_access": {"test-client": {"roles": ["admin"]}},
        "exp": now + 3600,
        "iat": now,
    }
    payload.update(extra)
    secret = os.getenv("OIDC_DEV_HS256_SECRET", "test-secret")
    return jwt.encode(payload, key=secret, algorithm="HS256")

def test_role_change_denied_without_token(client, capsys):
    r = client.post("/admin/roles", json={"target_sub": "user-999", "add_roles": ["analyst"]})
    assert r.status_code == 403
    # denial is logged via the after_request hook in admin.py for /admin (root) only,
    # so here we just assert no 2xx without token; schema is covered by allowed/failure tests below.

def test_role_change_missing_target_logs_failure(client, capsys):
    token = _token_with_admin()
    r = client.post("/admin/roles", headers={"Authorization": f"Bearer {token}"}, json={})
    assert r.status_code == 400
    events = _extract(capsys.readouterr().out)
    e = next((x for x in events if x.get("event") == "role_change" and x.get("outcome") == "failure"), None)
    assert e and e.get("reason") == "missing_target_sub"
    validate(instance=e, schema=SCHEMA)

def test_role_change_allowed_logs_schema(client, capsys):
    token = _token_with_admin()
    body = {"target_sub": "user-999", "add_roles": ["analyst"], "remove_roles": ["viewer"]}
    r = client.post("/admin/roles", headers={"Authorization": f"Bearer {token}"}, json=body)
    assert r.status_code == 202
    events = _extract(capsys.readouterr().out)
    e = next((x for x in events if x.get("event") == "role_change" and x.get("outcome") == "allowed"), None)
    assert e, f"no role_change allowed log in {events}"
    validate(instance=e, schema=SCHEMA)
    assert e.get("target_sub") == "user-999"
    assert "analyst" in (e.get("add_roles") or [])