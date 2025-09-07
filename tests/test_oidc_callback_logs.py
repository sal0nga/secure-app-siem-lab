import json
from pathlib import Path
from jsonschema import validate

SCHEMA = json.loads(Path("app/log_schema.json").read_text())

def _extract_log_lines(captured: str):
    out = []
    for line in captured.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out

def test_oidc_callback_success_logs_and_trace_header(client, capsys):
    r = client.get("/oidc/callback?code=abc&state=xyz")
    assert r.status_code == 200
    assert "X-Trace-Id" in r.headers and r.headers["X-Trace-Id"]
    logs = _extract_log_lines(capsys.readouterr().out)
    e = next((x for x in logs if x.get("event") == "oidc_callback" and x.get("outcome") == "success"), None)
    assert e, f"no success oidc_callback log in {logs}"
    validate(instance=e, schema=SCHEMA)
    assert e["status"] == 200

def test_oidc_callback_missing_code_logs_failure(client, capsys):
    r = client.get("/oidc/callback?state=xyz")
    assert r.status_code == 400
    logs = _extract_log_lines(capsys.readouterr().out)
    e = next((x for x in logs if x.get("event") == "oidc_callback" and x.get("outcome") == "failure"), None)
    assert e and e.get("reason") == "missing_code"
    validate(instance=e, schema=SCHEMA)
    assert e["status"] == 400

def test_oidc_callback_missing_state_logs_failure(client, capsys):
    r = client.get("/oidc/callback?code=abc")
    assert r.status_code == 400
    logs = _extract_log_lines(capsys.readouterr().out)
    e = next((x for x in logs if x.get("event") == "oidc_callback" and x.get("outcome") == "failure"), None)
    assert e and e.get("reason") == "missing_state"
    validate(instance=e, schema=SCHEMA)
    assert e["status"] == 400