# Threat-Driven Secure App + SIEM Lab

A hands-on consulting lab that demonstrates end-to-end security thinking: you design a small API, secure it (identity, config, SDLC), instrument it with useful logs, and pipe those logs into a SIEM to detect real attacks. The repo is intentionally minimal up front; each phase deepens capabilities without thrash.

## Repo layout (Phase 0)
```
secure-app-siem-lab/
├─ app/           # application source (to be added in Phase 1+)
├─ iam/           # identity-as-code; realm/clients/roles seed (Phase 2+)
├─ docs/          # architecture notes, diagrams, runbooks
├─ evidence/      # captured artifacts: screenshots, pcaps, logs, SARIF
├─ docker-compose.yml
├─ Makefile
└─ README.md
```

## Canonical log format
Use **JSON Lines** (one JSON object per line). RFC3339 timestamps in UTC (with trailing `Z`). Stick to short, stable keys so logs survive across tools.

**Base fields** (add more as needed):
- `ts` (string): timestamp, e.g. `2025-08-28T17:00:00Z`
- `src` (string): emitter, e.g. `app`, `reverse-proxy`, `siem`
- `evt` (string): event type, e.g. `login`, `signup`, `error`, `http_request`
- `level` (string): `debug|info|warn|error`
- `msg` (string): human-readable summary
- `ip` (string): client ip if applicable
- `http.method`, `http.path`, `http.status` (numbers/strings) when HTTP applies
- `user.id` (string|null): normalized user identifier when available
- `trace.id`, `span.id` (strings): for distributed tracing correlation
- `labels` (object): free-form small map for extra tags

**Example** (`.jsonl`, one-object-per-line):
```json
{"ts":"2025-08-28T17:00:00Z","src":"app","evt":"http_request","level":"info","http.method":"GET","http.path":"/healthz","http.status":200,"trace.id":"b6e7...","msg":"ok"}
{"ts":"2025-08-28T17:02:11Z","src":"app","evt":"login","level":"info","user.id":"u-123","ip":"203.0.113.10","msg":"login succeeded"}
{"ts":"2025-08-28T17:03:42Z","src":"app","evt":"error","level":"error","msg":"db timeout","labels":{"retry":1}}
```

## Evidence conventions
- **Foldering:** `evidence/YYYY-MM-DD/<phase>/<component>/...`
  - Example: `evidence/2025-08-28/P0/scaffold/notes.md`
- **Filenames:** `<YYYYMMDD>-<phase>-<short-thing>-<artifact>.<ext>`  
  - Example: `20250828-P0-scaffold-screenshot.png`
- Commit lightweight notes and diagrams; large binaries (pcaps, long logs) are ignored by `.gitignore` by default.

## Make targets (stubs in Phase 0)
Run `make help` to see target hints. Targets are placeholders until later phases wire them to real actions.

## Next
- **Phase 1:** Minimal API + container baseline
- **Phase 2:** IAM (Keycloak) + app integration
- **Phase 3:** SIEM + detections + attack sims
