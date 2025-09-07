# App Security Log Contract (v1)

**Purpose.** Every security-relevant action emits a single JSON line to stdout. These are picked up by the log pipeline and land in the SIEM.

**Required fields**
- `ts` (ISO 8601 UTC), `event`, `trace_id`, `src_ip`, `outcome`, `path`, `method`,
  `status` (int), `resp_bytes` (int), `roles` (array of strings), `app_version` (string)

**Optional fields**
- `user`, `sub`, `session_id`, `reason`, `mfa`, `authn_client`, plus any enrichment (e.g., `target_sub`, `add_roles`)

**Schema.** See `app/log_schema.json` (draft-07). `additionalProperties: true` allows enrichment.

**Examples**
```json
{"ts":"2025-09-07T02:13:04.531Z","event":"oidc_callback","outcome":"failure","reason":"missing_code","trace_id":"6c2...","src_ip":"127.0.0.1","path":"/oidc/callback","method":"GET","status":400,"resp_bytes":48,"roles":[],"app_version":"0.3.0"}
{"ts":"2025-09-07T02:13:09.201Z","event":"admin_post","outcome":"denied","reason":"missing_role","trace_id":"20e...","src_ip":"127.0.0.1","path":"/admin","method":"POST","status":403,"resp_bytes":36,"roles":[],"app_version":"0.3.0"}
{"ts":"2025-09-07T02:13:12.944Z","event":"admin_post","outcome":"allowed","trace_id":"20e...","src_ip":"127.0.0.1","user":"alice","sub":"user-123","path":"/admin","method":"POST","status":200,"resp_bytes":29,"roles":["admin"],"mfa":true,"app_version":"0.3.0"}
{"ts":"2025-09-07T02:13:18.102Z","event":"tickets_list","outcome":"success","trace_id":"9a1...","src_ip":"127.0.0.1","path":"/tickets","method":"GET","status":200,"resp_bytes":20,"roles":[],"app_version":"0.3.0"}
{"ts":"2025-09-07T02:13:23.477Z","event":"role_change","outcome":"allowed","trace_id":"b7f...","src_ip":"127.0.0.1","path":"/admin/roles","method":"POST","status":202,"resp_bytes":20,"roles":["admin"],"user":"alice","sub":"user-123","target_sub":"user-999","add_roles":["analyst"],"remove_roles":["viewer"],"app_version":"0.3.0"}