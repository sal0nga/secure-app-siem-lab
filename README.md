# Threat-Driven Secure App + SIEM Lab

A concise, threat‑driven lab: containerized Flask service behind Nginx/TLS, with logs normalized via Fluent Bit for SIEM and detection engineering.

## Status
**Phase 1 complete** (local stack running):
- Nginx reverse proxy with TLS for `app.local`
- Flask + Gunicorn app (`/` and `/healthz`)
- Postgres reachable from the app
- Fluent Bit tails Nginx + app logs → `logs/collected/collected.log` (JSON lines)

## Quick start
```bash
make up
# health (use :8443 if your host maps 8443→443)
curl -sk https://app.local/healthz || curl -sk https://app.local:8443/healthz
```

If needed, map the hostname once:
```bash
echo "127.0.0.1 app.local" | sudo tee -a /etc/hosts
```

## Layout
```
.
├─ app/          # Flask app
├─ nginx/        # reverse proxy config + TLS termination
├─ fluent-bit/   # log collection config
├─ docker-compose.yml
├─ Makefile
├─ .env.example
└─ README.md
```

## Roadmap
- **Phase 2:** Keycloak + OIDC (protect `/`, leave `/healthz` public)
- **Phase 3:** SIEM integration (ship logs, detections, attack sims)