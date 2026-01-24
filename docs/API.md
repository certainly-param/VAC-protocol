# VAC API Reference

**Complete API documentation for the VAC Sidecar and Control Plane.**

---

## Table of Contents

1. [Sidecar API](#sidecar-api)
2. [Control Plane API](#control-plane-api)
3. [Datalog Policy Reference](#datalog-policy-reference)
4. [Error Codes](#error-codes)
5. [Request/Response Examples](#requestresponse-examples)

---

## Sidecar API

The sidecar acts as a transparent HTTP proxy that enforces VAC policies.

### Base URL

```
http://localhost:3000
```

### Request Format

All requests must include:
- `Authorization: Bearer <Root_Biscuit>` header (required)
- Optional: `X-Correlation-ID` header (auto-generated if missing)
- Optional: `X-VAC-Receipt` header(s) for state gates (can be multiple)
- Optional: `X-VAC-Delegation` header(s) for multi-agent delegation (one per hop)

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <base64_encoded_root_biscuit>` - Root Biscuit token |
| `X-Correlation-ID` | No | UUID v4 for request correlation (auto-generated if missing) |
| `X-VAC-Receipt` | No | Base64-encoded receipt Biscuit(s) for state gates (can be multiple headers) |
| `X-VAC-Delegation` | No | Base64-encoded delegation chain token(s) - one header per hop (root → ... → current) |

### Response Headers

| Header | Description |
|--------|-------------|
| `X-VAC-Receipt` | Base64-encoded receipt Biscuit (only on successful 2xx responses) |

### Request Flow

```
Client Request → Sidecar → Policy Check → Upstream API → Response
```

**If policy allows:**
- Request is forwarded to upstream API with injected API key
- On success (2xx), receipt is minted and added to response header

**If policy denies:**
- Request is rejected with appropriate error code
- No upstream request is made

### Example Request

```bash
curl -X GET http://localhost:3000/api/search?q=flights \
  -H "Authorization: Bearer eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0..." \
  -H "X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000"
```

### Example Response (Success)

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-VAC-Receipt: eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0...

{
  "results": [...]
}
```

### Example Response (Policy Violation)

```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Policy violation: Missing required fact: prior_event('GET /search')
```

---

## Control Plane API

The Control Plane manages sidecar health, revocation, and kill switches.

### Base URL

```
http://localhost:8081
```

### Endpoints

#### POST /heartbeat

Receive heartbeat from sidecar.

**Request Body:**
```json
{
  "sidecar_id": "550e8400-e29b-41d4-a716-446655440000",
  "session_key_pub": "base64_encoded_public_key",
  "timestamp": 1704067200
}
```

**Response (200 OK):**
```json
{
  "healthy": true,
  "revoked_token_ids": [
    [32, 45, 67, ...],  // 32-byte array
    [12, 34, 56, ...]
  ]
}
```

**Response (Unhealthy):**
```json
{
  "healthy": false,
  "revoked_token_ids": null
}
```

**Status Codes:**
- `200 OK` - Heartbeat processed
- `400 Bad Request` - Invalid request format
- `500 Internal Server Error` - Server error

#### POST /revoke

Revoke a token ID.

**Request Body:**
```json
{
  "token_id": "a1b2c3d4e5f6..."  // Hex-encoded 32-byte token ID
}
```

**Response:**
- `200 OK` - Token revoked
- `400 Bad Request` - Invalid token ID format

#### POST /kill

Activate kill switch (all sidecars become unhealthy).

**Request Body:** None

**Response:**
- `200 OK` - Kill switch activated

**Effect:** All subsequent heartbeat responses return `healthy: false`

#### POST /revive

Deactivate kill switch (normal operation resumes).

**Request Body:** None

**Response:**
- `200 OK` - Kill switch deactivated

#### GET /sidecars

List all registered sidecars.

**Response (200 OK):**
```json
{
  "sidecars": [
    {
      "sidecar_id": "550e8400-e29b-41d4-a716-446655440000",
      "session_key_pub": "base64_encoded_public_key",
      "last_heartbeat": 1704067200
    }
  ],
  "count": 1
}
```

---

## Datalog Policy Reference

VAC uses **Datalog** (a logic programming language) for policy definition. Policies are embedded in Root Biscuits.

### Fact Types

#### Context Facts (Added by Sidecar)

```datalog
operation("GET", "/search")
correlation_id("550e8400-e29b-41d4-a716-446655440000")
```

#### Receipt Facts (From Receipt Biscuits)

```datalog
prior_event("GET /search", "550e8400-e29b-41d4-a716-446655440000", 1704067200)
```

**Format**: `prior_event(operation, correlation_id, timestamp)`

#### Delegation Facts (From Delegation Chain)

```datalog
depth(2)  # Current delegation depth (0 = root, 1, 2, ...)
delegation_chain("token_id_hex_1")
delegation_chain("token_id_hex_2")
```

**Format**: 
- `depth(N)` - Current delegation depth (enforced: max depth = 5)
- `delegation_chain(token_id_hex)` - Token IDs in the delegation chain (one fact per hop)

### Policy Rules

#### Allow Rules

```datalog
allow if <condition>;
```

**Example:**
```datalog
allow if operation("GET", "/search");
allow if operation("POST", "/charge"), prior_event($op, $cid, $ts), $op.starts_with("GET /search");
```

#### Check Rules

```datalog
check if <condition>;
```

**Example:**
```datalog
check if time($t), $t < 2026-02-01T00:00:00Z;
```

### Policy Examples

#### Example 1: Simple Allow

```datalog
allow if true;  # Allow all operations
```

#### Example 2: Method-Based

```datalog
allow if operation("GET", $path);
allow if operation("POST", $path), $path != "/admin";
```

#### Example 3: State Gate (Requires Receipt)

```datalog
# Allow charge only if prior search exists
allow if operation("POST", "/charge"), 
      prior_event($op, $cid, $ts), 
      $op.starts_with("GET /search");

# Allow all other operations
allow if operation($method, $path), $path != "/charge";
```

#### Example 4: Time-Based

```datalog
check if time($t), $t < 2026-02-01T00:00:00Z;
allow if operation($method, $path);
```

### String Operations

Datalog supports string operations:

- `$str.starts_with("prefix")` - Check if string starts with prefix
- `$str == "value"` - String equality
- `$str != "value"` - String inequality

### Variable Binding

Variables start with `$`:

```datalog
allow if operation($method, $path), $path != "/admin";
```

Variables are bound by facts and can be used in conditions.

### Global Policy Rules

The sidecar enforces a global depth limit policy:

```datalog
deny if depth($d), $d > 5;
```

This ensures delegation chains cannot exceed depth 5, preventing unbounded delegation.

---

## Error Codes

### HTTP Status Codes

| Code | Error | Description |
|------|-------|-------------|
| `200 OK` | Success | Request allowed, receipt minted (if successful) |
| `400 Bad Request` | InvalidTokenFormat | Malformed token or header |
| `401 Unauthorized` | MissingToken | No Authorization header |
| `403 Forbidden` | InvalidSignature, ReceiptExpired, PolicyViolation, Deny | Policy denied request |
| `409 Conflict` | CorrelationIdMismatch | Receipt correlation ID doesn't match request |
| `500 Internal Server Error` | InternalError, ConfigError | Server error |
| `502 Bad Gateway` | ProxyError | Upstream API error |

### Error Response Format

```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Policy violation: Missing required fact: prior_event('GET /search')
```

### Error Types

#### MissingToken (401)

**Cause**: No `Authorization` header or missing `Bearer` prefix

**Example:**
```http
HTTP/1.1 401 Unauthorized

Missing authorization token
```

#### InvalidTokenFormat (400)

**Cause**: Malformed token (not valid base64 or Biscuit format)

**Example:**
```http
HTTP/1.1 400 Bad Request

Invalid token format
```

#### InvalidSignature (403)

**Cause**: Biscuit signature verification failed or token is revoked

**Example:**
```http
HTTP/1.1 403 Forbidden

Invalid biscuit signature
```

#### ReceiptExpired (403)

**Cause**: Receipt timestamp is older than 5 minutes + 30s grace period

**Example:**
```http
HTTP/1.1 403 Forbidden

Receipt expired
```

#### CorrelationIdMismatch (409)

**Cause**: Receipt correlation ID doesn't match request correlation ID

**Example:**
```http
HTTP/1.1 409 Conflict

Correlation ID mismatch
```

#### PolicyViolation (403)

**Cause**: Datalog policy evaluation failed

**Example:**
```http
HTTP/1.1 403 Forbidden

Policy violation: Missing required fact: prior_event('GET /search')
```

#### Deny (403)

**Cause**: Fail-closed policy (catch-all denial)

**Example:**
```http
HTTP/1.1 403 Forbidden

Request denied by fail-closed policy
```

#### ProxyError (502)

**Cause**: Upstream API request failed

**Example:**
```http
HTTP/1.1 502 Bad Gateway

Proxy error: HTTP request failed: connection timeout
```

---

## Request/Response Examples

### Example 1: Simple GET Request

**Request:**
```http
GET /api/search?q=flights HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0...
X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-VAC-Receipt: eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0...

{
  "results": [
    {"flight": "AA123", "price": 350}
  ]
}
```

### Example 2: State Gate (Charge Requires Search)

**Step 1: Search Request**

**Request:**
```http
GET /api/search?q=flights HTTP/1.1
Authorization: Bearer <Root_Biscuit>
X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000
```

**Response:**
```http
HTTP/1.1 200 OK
X-VAC-Receipt: <Receipt_1>

{"results": [...]}
```

**Step 2: Charge Request (with Receipt)**

**Request:**
```http
POST /api/charge HTTP/1.1
Authorization: Bearer <Root_Biscuit>
X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000
X-VAC-Receipt: <Receipt_1>
Content-Type: application/json

{"amount": 350, "currency": "USD"}
```

**Response:**
```http
HTTP/1.1 200 OK
X-VAC-Receipt: <Receipt_2>

{"transaction_id": "txn_123"}
```

### Example 3: Multi-Receipt Chain

**Request:**
```http
POST /api/charge HTTP/1.1
Authorization: Bearer <Root_Biscuit>
X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000
X-VAC-Receipt: <Receipt_Search>
X-VAC-Receipt: <Receipt_Select>
Content-Type: application/json

{"amount": 350}
```

**Note**: Multiple `X-VAC-Receipt` headers are supported (HTTP spec allows multiple headers with same name).

### Example 4: Multi-Agent Delegation

**Request with Delegation Chain:**
```http
POST /api/charge HTTP/1.1
Authorization: Bearer <Delegated_Token_Depth_2>
X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000
X-VAC-Delegation: <Root_Token_Depth_0>
X-VAC-Delegation: <Intermediate_Token_Depth_1>
Content-Type: application/json

{"amount": 350, "currency": "USD"}
```

**Delegation Chain Rules:**
- One `X-VAC-Delegation` header per hop
- Order: Root → ... → current (last token must match Authorization token)
- Maximum depth: 5 (enforced globally)
- Each token must contain `depth(N)` fact with incrementing depth (0, 1, 2, ...)
- All tokens must be signed under the root public key

**Response (Success):**
```http
HTTP/1.1 200 OK
X-VAC-Receipt: <Receipt_with_delegation_chain_embedded>

{"transaction_id": "txn_123"}
```

The receipt includes the delegation chain token IDs for audit trail.

### Example 5: Policy Violation

**Request:**
```http
POST /api/charge HTTP/1.1
Authorization: Bearer <Root_Biscuit>
X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000
Content-Type: application/json

{"amount": 350}
```

**Response:**
```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Policy violation: Missing required fact: prior_event('GET /search')
```

### Example 5: Expired Receipt

**Request:**
```http
POST /api/charge HTTP/1.1
Authorization: Bearer <Root_Biscuit>
X-Correlation-ID: 550e8400-e29b-41d4-a716-446655440000
X-VAC-Receipt: <Expired_Receipt>  # Timestamp > 5 minutes old
```

**Response:**
```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain

Receipt expired
```

---

## Biscuit Format

### Root Biscuit Structure

Root Biscuits are base64-encoded Biscuit tokens containing:

1. **Authority Block**: Policies and facts
2. **Signature**: Ed25519 signature by user's root key

### Receipt Biscuit Structure

Receipt Biscuits are base64-encoded Biscuit tokens containing:

1. **Authority Block**: `prior_event(operation, correlation_id, timestamp)` fact
2. **Signature**: Ed25519 signature by sidecar's session key

### Encoding

- **Transport**: Base64-encoded strings in HTTP headers
- **Storage**: Binary format (Biscuit internal format)

---

## Rate Limiting

**Current Implementation**: No rate limiting (Phase 3)

**Phase 4**: Will add rate limiting to prevent DoS attacks

---

## Authentication

### Root Biscuit Authentication

- **Format**: `Authorization: Bearer <base64_biscuit>`
- **Verification**: Ed25519 signature check against root public key
- **Revocation**: Checked against revocation filter before verification

### Receipt Authentication

- **Format**: `X-VAC-Receipt: <base64_receipt>`
- **Verification**: Ed25519 signature check against sidecar's session key
- **Expiry**: 5 minutes + 30s grace period

---

**Last Updated**: January 2026  
**Version**: 0.1.0 (Phase 3 Complete)
