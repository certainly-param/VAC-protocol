# VAC API Reference

## Sidecar API

**Base URL:** `http://localhost:3000`

**Request headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <base64_root_biscuit>` |
| `X-Correlation-ID` | No | UUID (auto-generated if missing) |
| `X-VAC-Receipt` | No | Receipt Biscuit(s); multiple headers allowed |

**Response:** On 2xx, `X-VAC-Receipt` header contains the new receipt.

**Flow:** Client → Sidecar (policy check) → Upstream API (with injected API key) → Response + receipt.

## Control Plane API

**Base URL:** `http://localhost:8081`

- `POST /heartbeat` — Sidecar heartbeat (returns `healthy`, `revoked_token_ids`)
- `POST /revoke` — Revoke a token ID
- `POST /kill` — Activate kill switch (all heartbeats return unhealthy)
- `POST /revive` — Deactivate kill switch
- `GET /sidecars` — List registered sidecars

## Datalog Policy

**Context facts (sidecar):** `operation(method, path)`, `correlation_id(uuid)`

**Receipt facts:** `prior_event(operation, correlation_id, timestamp)`

**Example — allow charge only after search:**
```datalog
allow if operation("POST", "/charge"), prior_event($op, $cid, $ts), $op.starts_with("GET /search");
allow if operation("GET", $path);
```

**Global:** `deny if depth($d), $d > 5` (max delegation depth 5).

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success (receipt in header on 2xx) |
| 400 | Invalid token format |
| 401 | Missing/invalid Authorization |
| 403 | Policy denied (signature, expired receipt, policy violation, deny) |
| 409 | Correlation ID mismatch |
| 502 | Upstream/proxy error |

Errors are plain text in the response body (e.g. `Policy violation: Missing required fact: prior_event('GET /search')`).
