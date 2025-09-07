import json
from jsonschema import validate
from pathlib import Path

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

def test_tickets_list_logs_schema(client, capsys):
    r = client.get("/tickets")
    assert r.status_code == 200
    logs = _extract_log_lines(capsys.readouterr().out)
    e = next((x for x in logs if x.get("event") == "tickets_list"), None)
    assert e, f"no tickets_list log in {logs}"
    validate(instance=e, schema=SCHEMA)
    assert e["outcome"] == "success"
    assert e["status"] == 200
    assert isinstance(e["resp_bytes"], int) and e["resp_bytes"] >= 0

def test_tickets_create_logs_schema(client, capsys):
    r = client.post("/tickets", json={"title": "test"})
    assert r.status_code == 201
    logs = _extract_log_lines(capsys.readouterr().out)
    e = next((x for x in logs if x.get("event") == "ticket_create"), None)
    assert e, f"no ticket_create log in {logs}"
    validate(instance=e, schema=SCHEMA)
    assert e["status"] == 201

def test_large_response_reason_flag(client, capsys, monkeypatch):
    # Force threshold tiny so any response triggers the flag
    monkeypatch.setenv("LOG_LARGE_RESP_BYTES", "1")
    r = client.get("/tickets")
    assert r.status_code == 200
    logs = _extract_log_lines(capsys.readouterr().out)
    e = next((x for x in logs if x.get("event") == "tickets_list"), None)
    assert e and e.get("reason") == "large_response"