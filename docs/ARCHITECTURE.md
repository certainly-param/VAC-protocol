# VAC Architecture Guide

**Complete technical architecture documentation for the VAC Protocol implementation.**

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Request Flow](#request-flow)
4. [State Management](#state-management)
5. [Security Model](#security-model)
6. [Module Breakdown](#module-breakdown)
7. [Data Flow Diagrams](#data-flow-diagrams)

---

## System Overview

VAC implements a **capability-based security system** using a sidecar pattern. The system consists of three main components:

### Core Components

```
┌─────────────────┐
│ Control Plane   │ (User's Device - Trusted)
│ (God)           │
│                 │ - Issues Root Biscuits
│                 │ - Receives heartbeats
│                 │ - Manages revocation
│                 │ - Kill switch control
└────────┬────────┘
         │
         │ Heartbeat (60s)
         │ Revocation updates
         │
         ▼
┌─────────────────┐
│ Sidecar         │ (Gatekeeper - Semi-Trusted)
│ (Orange Zone)   │
│                 │ - Verifies Biscuits
│                 │ - Evaluates policies
│                 │ - Mints receipts
│                 │ - Injects API keys
│                 │ - Enforces lockdown
└────────┬────────┘
         │
         │ HTTP Requests
         │ (with Biscuits)
         │
         ▼
┌─────────────────┐
│ Agent           │ (Enemy - Untrusted)
│ (Red Zone)      │
│                 │ - Never sees API keys
│                 │ - Carries receipts
│                 │ - Makes requests
└─────────────────┘
```

### Trust Boundaries

1. **Green Zone (Trusted)**: Control Plane
   - User's device or secure service
   - Issues Root Biscuits
   - Manages revocation lists
   - Controls kill switch

2. **Orange Zone (Semi-Trusted)**: Sidecar
   - Holds API keys in memory
   - Enforces policies
   - Can be compromised (assume attacker gains root access)
   - Mitigation: Short-lived session keys, heartbeat revocation

3. **Red Zone (Untrusted)**: Agent
   - Actively malicious (assume worst case)
   - Never sees API keys
   - Can only make requests with valid Biscuits

---

## Component Architecture

### Sidecar Components

```
sidecar/
├── main.rs          # Entry point, request routing, structured logging
├── config.rs        # Configuration loading (files, CLI, env vars with precedence)
├── state.rs         # Shared state management, session key rotation
├── biscuit.rs       # Biscuit verification (root & receipt), revocation checks
├── receipt.rs       # Receipt extraction & verification
├── policy.rs        # Datalog policy evaluation, depth limiting
├── proxy.rs         # HTTP proxying to upstream APIs
├── heartbeat.rs     # Heartbeat protocol implementation
├── revocation.rs    # Token revocation checking (HashSet-based)
├── adapter.rs       # WASM adapter execution, registry management
└── delegation.rs    # Multi-agent delegation chain verification
```

### Control Plane Components

```
control-plane/
└── main.rs          # Mock Control Plane server
                     # - Heartbeat endpoint
                     # - Revocation management
                     # - Kill switch
                     # - Sidecar registry
```

---

## Request Flow

### Complete Request Lifecycle

```
1. Agent Request
   ├─ Authorization: Bearer <Root_Biscuit>
   ├─ X-Correlation-ID: <uuid>
   └─ X-VAC-Receipt: <receipt1>, <receipt2>, ...
        │
        ▼
2. Sidecar Processing
   ├─ A. Extract Token (Root Biscuit)
   ├─ B. Extract Correlation ID (or generate)
   ├─ C. Verify Root Biscuit
   │   ├─ Check revocation filter
   │   └─ Verify signature
   ├─ D. Build Authorizer
   │   └─ Add root token
   ├─ C.1 Verify Delegation Chain (if present)
   │   ├─ Parse X-VAC-Delegation headers
   │   ├─ Verify all token signatures
   │   ├─ Check depth progression (0, 1, 2, ...)
   │   ├─ Enforce max depth (5)
   │   └─ Inject delegation_chain facts
   ├─ E. Process Receipts
   │   ├─ Verify signatures (session key)
   │   ├─ Extract facts (operation, correlation_id, timestamp)
   │   ├─ Check expiry (5 min + 30s grace)
   │   ├─ Verify correlation ID match
   │   └─ Inject facts into authorizer
   ├─ F. Add Context Facts
   │   ├─ operation(method, path)
   │   └─ correlation_id(uuid)
   ├─ F.1 Optional WASM Adapter Facts
   │   ├─ Extract adapter_hash from Root Biscuit
   │   ├─ Execute WASM adapter (if pinned)
   │   └─ Inject adapter facts
   ├─ G. Evaluate Policy
   │   ├─ Enforce global depth limit (max 5)
   │   └─ Datalog engine checks rules
   └─ H. Forward Request (if policy allows)
        │
        ▼
3. Upstream API
   ├─ Receives request with injected API key
   └─ Returns response
        │
        ▼
4. Sidecar Response
   ├─ If successful (2xx):
   │   ├─ Mint Receipt Biscuit
   │   │   ├─ prior_event(operation, correlation_id, timestamp)
   │   │   ├─ delegation_chain(token_id_hex) (if delegation present)
   │   │   ├─ depth(N) (if delegation present)
   │   │   └─ Signed with session key
   │   ├─ Log receipt minting (structured fields)
   │   └─ Add X-VAC-Receipt header
   └─ Return response to agent (with structured logging)
```

### Detailed Step Breakdown

#### Step C: Root Biscuit Verification

```rust
verify_root_biscuit(token_str, root_public_key, revocation_filter)
  ├─ Extract token ID (SHA-256 hash of biscuit)
  ├─ Check revocation filter
  │   └─ If revoked → InvalidSignature error
  ├─ Parse Biscuit from base64
  ├─ Verify signature with root public key
  └─ Return verified Biscuit
```

#### Step E: Receipt Processing

```rust
for each X-VAC-Receipt header:
  ├─ Parse receipt from base64
  ├─ Verify signature (session key)
  ├─ Extract receipt info:
  │   ├─ Query Datalog: receipt_data($op, $id, $ts) <- prior_event($op, $id, $ts)
  │   └─ Parse: (operation, correlation_id, timestamp)
  ├─ Verify expiry: now < timestamp + 300s + 30s
  ├─ Verify correlation ID: receipt.cid == request.cid
  └─ Inject fact: prior_event(operation, correlation_id, timestamp)
```

#### Step G: Policy Evaluation

```rust
evaluate_policy(authorizer)
  ├─ Authorizer contains:
  │   ├─ Root Biscuit (with policies)
  │   ├─ Receipt facts (prior_event)
  │   └─ Context facts (operation, correlation_id)
  ├─ Run Datalog engine
  │   ├─ Check all `check if` rules
  │   ├─ Evaluate all `allow if` rules
  │   └─ Default deny (fail-closed)
  └─ Return success or PolicyViolation error
```

---

## State Management

### Sidecar State

The sidecar maintains minimal state:

```rust
pub struct SidecarState {
    // Cryptographic keys
    pub session_key: KeyPair,              // Ephemeral (rotates every 5 min)
    pub user_root_public_key: PublicKey,  // From config (trusted)
    
    // API configuration
    pub api_key: String,                  // For upstream requests
    pub upstream_url: String,              // Upstream API base URL
    
    // Proxy instance
    pub proxy: Arc<AxumProxy>,            // HTTP client
    
    // Heartbeat state
    pub sidecar_id: String,               // UUID for identification
    pub heartbeat_healthy: bool,          // Last heartbeat status
    pub heartbeat_failure_count: u32,     // Consecutive failures
    pub lockdown_mode: bool,              // Emergency shutdown
    pub last_heartbeat: SystemTime,       // Timestamp
    pub last_key_rotation: SystemTime,    // For rotation tracking
    
    // Revocation
    pub revocation_filter: Arc<RwLock<RevocationFilter>>, // Revoked tokens
    
    // WASM Adapters
    pub adapter_registry: Arc<AdapterRegistry>, // Loaded adapters keyed by hash
}
```

### Stateless Design

**Key Principle**: The sidecar is **stateless** for request processing. All state is either:
- **Ephemeral**: Session keys, heartbeat status (lost on restart)
- **Configuration**: Root public key, API key (from config file, CLI, or env vars)
- **Derived**: Receipt facts extracted from tokens
- **Cached**: WASM adapters (loaded by hash, cached in memory)

**Why Stateless?**
- Scalability: No shared state database
- Simplicity: No state synchronization
- Security: Less attack surface

**State in Tokens:**
- Agents carry receipts (cryptographic proofs)
- Receipts contain: operation, correlation_id, timestamp
- Policy evaluation uses receipt facts, not database queries

---

## Security Model

### Fail-Closed Enforcement

**Default Behavior**: All requests are denied unless explicitly allowed.

```rust
// Every match statement must have explicit catch-all
match result {
    Ok(val) => val,
    Err(e) => return Err(VacError::Deny),  // Fail-closed
    _ => return Err(VacError::Deny),       // Explicit catch-all
}
```

### Bounded Risk

1. **Session Keys**: Rotate every 5 minutes
   - Limits exposure if key is compromised
   - Old receipts become invalid automatically

2. **Heartbeat**: Every 60 seconds
   - 3 failures → lockdown mode
   - Instant revocation capability

3. **Receipt Expiry**: 5 minutes + 30s grace
   - Prevents stale receipts
   - Handles clock skew

### Cryptographic Guarantees

1. **Root Biscuits**: Signed by user's root key
   - Cannot be forged without private key
   - Verified before every request

2. **Receipts**: Signed by sidecar's session key
   - Cannot be forged without session key
   - Verified before fact extraction

3. **Token IDs**: SHA-256 hash of biscuit
   - Consistent identifier for revocation
   - Collision-resistant

---

## Module Breakdown

### `config.rs` - Configuration Management

**Purpose**: Load configuration with precedence: CLI arguments > environment variables > config file > defaults

**Key Functions**:
- `Config::load(cli_args)` - Main entry point, applies precedence
- `Config::load_from_file(path)` - Loads TOML/YAML config files
- `Config::load_from_env()` - Loads from environment variables
- **Fail-fast**: Crashes if `root_public_key` or `api_key` missing

**Configuration Methods**:
1. **Config Files** (TOML/YAML) - Recommended for production
2. **CLI Arguments** - Override any setting via `--flag` options
3. **Environment Variables** - Traditional method (VAC_*)
4. **Defaults** - Fallback values

**Configuration Options**:
- `root_public_key` (required) - Hex-encoded Ed25519 public key (64 chars)
- `api_key` (required) - API key for upstream requests
- `upstream_url` (optional, default: `http://localhost:8080`) - Upstream API base URL
- `control_plane_url` (optional, default: `http://localhost:8081`) - Control Plane URL
- `heartbeat_interval_secs` (optional, default: 60) - Heartbeat interval
- `session_key_rotation_interval_secs` (optional, default: 300) - Key rotation interval
- `adapters_dir` (optional) - Directory for WASM adapters
- `log_level` (optional, default: "info") - Logging verbosity (trace, debug, info, warn, error)

### `state.rs` - State Management

**Purpose**: Manage sidecar's shared state

**Key Functions**:
- `SidecarState::new()` - Initialize with generated session key
- `rotate_session_key()` - Generate new session key
- `should_rotate_key()` - Check if rotation needed
- `enter_lockdown()` - Activate lockdown mode
- `is_read_only()` - Check if method is read-only

**Thread Safety**: Uses `Arc<RwLock<SidecarState>>` for shared access

### `biscuit.rs` - Biscuit Verification

**Purpose**: Verify Root and Receipt Biscuits

**Key Functions**:
- `verify_root_biscuit()` - Verify Root Biscuit signature + revocation check
- `verify_receipt_biscuit()` - Verify Receipt Biscuit signature

**Revocation Integration**: Checks revocation filter before signature verification

### `receipt.rs` - Receipt Processing

**Purpose**: Extract and verify receipt information

**Key Functions**:
- `extract_receipt_info()` - Query Datalog to extract receipt facts
- `verify_receipt_expiry()` - Check receipt hasn't expired
- `verify_correlation_id_match()` - Ensure correlation IDs match

**Datalog Query**: `receipt_data($op, $id, $ts) <- prior_event($op, $id, $ts)`

### `policy.rs` - Policy Evaluation

**Purpose**: Evaluate Datalog policies

**Key Functions**:
- `evaluate_policy()` - Run Datalog engine
- `add_context_facts()` - Add operation and correlation_id facts
- `add_receipt_facts()` - Manually inject receipt facts (bypasses multi-key limitation)

**Critical Discovery**: Must use manual fact injection for receipts (see Implementation Discoveries)

### `proxy.rs` - HTTP Proxying

**Purpose**: Forward requests to upstream APIs

**Key Functions**:
- `Proxy::forward()` - Forward request with API key injection
- `AxumProxy::forward()` - Implementation using reqwest

**Features**:
- Strips VAC internal headers (X-VAC-Receipt, etc.)
- Injects API key into Authorization header
- Converts reqwest::Response to axum::Response

### `heartbeat.rs` - Heartbeat Protocol

**Purpose**: Maintain liveness with Control Plane

**Key Functions**:
- `start_heartbeat_task()` - Background task that pings Control Plane
- `send_heartbeat()` - Send heartbeat request and process response

**Behavior**:
- Pings every 60s (configurable)
- 3 failures → lockdown mode
- Receives revocation list updates
- Triggers session key rotation

### `revocation.rs` - Token Revocation

**Purpose**: Check if tokens are revoked

**Key Functions**:
- `RevocationFilter::is_revoked()` - Check token ID
- `RevocationFilter::revoke()` - Add token to revocation list
- `extract_token_id()` - Generate token ID from biscuit (SHA-256)

**Implementation**: Uses HashSet for Phase 3 (can upgrade to Bloom Filter in Phase 4)

---

## Data Flow Diagrams

### Happy Path: Multi-Step Workflow

```
Agent                    Sidecar                  Upstream API
  │                         │                          │
  │── GET /search ──────────>│                          │
  │   Bearer <Root>         │── GET /search ──────────>│
  │                          │   Authorization: <API>   │
  │                          │<── 200 OK ───────────────│
  │<── 200 OK ───────────────│                          │
  │   X-VAC-Receipt: <R1>    │                          │
  │                          │                          │
  │── POST /charge ──────────>│                          │
  │   Bearer <Root>          │                          │
  │   X-VAC-Receipt: <R1>    │                          │
  │                          │── POST /charge ──────────>│
  │                          │   Authorization: <API>   │
  │                          │<── 200 OK ───────────────│
  │<── 200 OK ───────────────│                          │
  │   X-VAC-Receipt: <R2>    │                          │
```

### Heartbeat Flow

```
Sidecar                  Control Plane
  │                           │
  │── POST /heartbeat ────────>│
  │   sidecar_id,             │
  │   session_key_pub,         │
  │   timestamp                │
  │                           │
  │<── 200 OK ─────────────────│
  │   healthy: true,           │
  │   revoked_token_ids: [...] │
  │                           │
  │ (Update revocation filter)│
  │                           │
  │ (Wait 60s)                │
  │                           │
  │── POST /heartbeat ────────>│
  │   ...                      │
```

### Lockdown Mode Activation

```
Sidecar                  Control Plane
  │                           │
  │── POST /heartbeat ────────>│
  │                           │<── Network failure
  │                           │
  │ (failure_count = 1)       │
  │                           │
  │── POST /heartbeat ────────>│
  │                           │<── Network failure
  │                           │
  │ (failure_count = 2)       │
  │                           │
  │── POST /heartbeat ────────>│
  │                           │<── Network failure
  │                           │
  │ (failure_count = 3)       │
  │ (lockdown_mode = true)    │
  │                           │
  │ (Reject all non-GET)      │
```

---

## Implementation Details

### Authorizer Construction Pattern

**Critical Discovery**: `root_biscuit.authorizer()` doesn't allow adding tokens signed with different keys.

**Solution**: Manual authorizer construction:

```rust
// 1. Create empty authorizer
let mut authorizer = Authorizer::new();

// 2. Add root token
authorizer.add_token(&root_biscuit)?;

// 3. For receipts: Extract facts and inject manually
for receipt in receipts {
    let receipt_info = extract_receipt_info(&receipt)?;
    add_receipt_facts(&mut authorizer, &receipt_info)?;
}

// 4. Add context facts
add_context_facts(&mut authorizer, method, path, correlation_id)?;

// 5. Evaluate policy
evaluate_policy(&mut authorizer)?;
```

### Receipt Fact Injection

Instead of `authorizer.add_token(receipt)`, we manually inject facts:

```rust
pub fn add_receipt_facts(authorizer: &mut Authorizer, info: &ReceiptInfo) {
    authorizer.add_fact(Fact::new(
        "prior_event".to_string(),
        vec![
            biscuit_auth::builder::string(&info.operation),
            biscuit_auth::builder::string(&info.correlation_id),
            biscuit_auth::builder::int(info.timestamp),
        ],
    ))?;
}
```

**Why**: Bypasses biscuit-auth's multi-key token limitation.

---

## Performance Characteristics

### Request Processing

- **Biscuit Verification**: ~1-2ms (signature check)
- **Datalog Evaluation**: ~0.5-1ms (policy engine)
- **Receipt Extraction**: ~0.5ms (Datalog query)
- **HTTP Proxying**: Network-bound (depends on upstream API)

**Total Overhead**: ~2-4ms per request (excluding network)

### Memory Usage

- **Sidecar State**: ~1KB (keys, config)
- **Revocation Filter**: ~3.2MB for 100k tokens (HashSet, Phase 3)
  - Can be reduced to ~100KB with Bloom Filter (Phase 4)

### Scalability

- **Stateless Design**: Horizontal scaling supported
- **No Shared State**: No database bottlenecks
- **Connection Pooling**: Reqwest client handles connection reuse

---

## Future Enhancements (Phase 4)

1. **WASM Adapters**: Sandboxed fact extraction from request bodies
2. **Bloom Filter**: Memory-efficient revocation (100KB vs 3.2MB)
3. **Multi-Agent Delegation**: Stack depth limiting
4. **Observability**: Metrics, distributed tracing
5. **Production Hardening**: Memory protection, rate limiting

---

**Last Updated**: January 2026  
**Version**: 0.1.0 (Phase 3 Complete)
