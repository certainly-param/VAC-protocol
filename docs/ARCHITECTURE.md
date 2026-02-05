# VAC Architecture

## System Overview

VAC is a **capability-based security** system using a sidecar pattern.

- **Control Plane** (trusted): Issues Root Biscuits, heartbeats, revocation, kill switch.
- **Sidecar** (semi-trusted): Verifies Biscuits, evaluates Datalog policies, mints receipts, injects API keys. Can be compromised; mitigation: short-lived session keys, heartbeat revocation.
- **Agent** (untrusted): Never sees API keys; carries receipts; all requests go through sidecar.

## Components

**Sidecar** (`sidecar/`): `main.rs` (routing), `config.rs`, `state.rs`, `biscuit.rs`, `receipt.rs`, `policy.rs`, `proxy.rs`, `heartbeat.rs`, `revocation.rs`, `adapter.rs`, `delegation.rs`.

**Control Plane** (`control-plane/`): Mock server — heartbeat, revocation, kill switch, sidecar registry.

## Request Flow

1. Extract token, correlation ID, receipts.
2. Verify Root Biscuit (revocation check, signature).
3. Verify receipts (signature, expiry, correlation ID match); inject `prior_event` facts.
4. Add context facts (`operation`, `correlation_id`).
5. Evaluate Datalog policy (fail-closed).
6. If allow: forward to upstream with API key; on 2xx, mint receipt and add `X-VAC-Receipt`.

## State

Sidecar is **stateless** for request processing. Session key rotates every 5 min; receipts expire in 5 min + 30s. Agents carry receipts; policy uses receipt facts, not a DB.

## Security

- **Fail-closed:** Deny unless policy explicitly allows.
- **Bounded risk:** Session key rotation (5 min), heartbeat (60s), receipt expiry (5 min).
