<p align="center">
  <img src="assets/logo.png" alt="VAC Protocol" width="500">
</p>

<p align="center">
  <strong>A capability-based security system for AI agents</strong>
</p>

<p align="center">
  <a href="https://github.com/certainly-param/VAC-protocol"><img src="https://img.shields.io/github/stars/certainly-param/VAC-protocol?style=social&label=Star" alt="GitHub stars"></a>
  <img src="https://img.shields.io/badge/status-under%20development-yellow.svg" alt="Under Development">
  <img src="https://img.shields.io/badge/rust-1.70+-orange.svg" alt="Rust">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/maintained-yes-green.svg" alt="Maintained">
</p>

## What is VAC?

VAC solves the **"over-privileged agent" problem** by shifting from identity-based to capability-based security. Instead of giving agents permanent API keys with broad permissions, VAC issues **task-scoped, context-aware credentials** that enforce fine-grained policies and enable instant revocation.

### The Problem

Today's AI agents often get **"God Mode"** access: permanent API keys, no context awareness (can't tell "book flight" from "delete database"), weak revocation, and poor accountability. A single leaked key can cause serious harm.

### What We Want Instead

- **Task-scoped credentials** — e.g. "This agent may only charge up to $400 for this booking."
- **Context-aware policies** — e.g. "Charge only after a prior search step."
- **Fast revocation** — stop a credential within seconds, not days.
- **Clear proofs** — cryptographic evidence of what was allowed and performed.

### Why Not...?

| Approach | Why It's Not Enough |
|----------|---------------------|
| **Sandbox / scoped APIs** | Too rigid; doesn't solve "right amount of power per task." |
| **Human-in-the-loop** | Kills autonomy; approval fatigue. |
| **Constitutional AI** | Relies on AI to constrain AI; hallucination/bypass risks. |
| **OAuth 2.0** | Built for humans; long-lived tokens; no workflow context. |

**VAC's approach:** Receipt-based state (agents carry proofs), sidecar enforcement, deterministic Datalog policies, and bounded risk (short-lived keys, heartbeats, instant revocation).

### Key Features

- **Capability-Based Security** — "What can this agent do?" not "Who is this agent?"
- **Receipt-Based State Transitions** — Cryptographic proofs of completed actions
- **Offline Delegation** — Biscuit tokens with attenuation support
- **Instant Revocation** — Heartbeat-based liveness checks
- **Deterministic Policies** — Datalog logic, not AI reasoning
- **Fail-Closed Security** — Deny by default, explicit allow rules

## Quick Start

### Prerequisites

- Rust 1.70+ ([Install Rust](https://www.rust-lang.org/tools/install))
- A Control Plane (use the mock server for testing)

### Running the Sidecar

You can configure the sidecar using **config files**, **CLI arguments**, or **environment variables** (precedence: CLI > env > file > defaults).

#### Option 1: Config File (Recommended)

1. **Generate a root key pair:**

```bash
cd sidecar
cargo run --example generate_test_keys
```

This outputs a public key (64 hex characters) - copy it for your config file.

2. **Copy `config.toml.example` to `config.toml`**, then set `root_public_key` (from step 1) and `api_key`:

```bash
cp config.toml.example config.toml
# Edit config.toml with your values.
```

3. **Run the sidecar:**

```bash
cd sidecar
cargo run --bin vac-sidecar -- --config-file ../config.toml
```

#### Option 2: CLI Arguments

```bash
cd sidecar
cargo run --bin vac-sidecar -- \
  --root-public-key "a1b2c3d4e5f6..." \
  --api-key "your-api-key" \
  --upstream-url "http://localhost:8080" \
  --log-level "info"
```

#### Option 3: Environment Variables

```bash
# Required
export VAC_ROOT_PUBLIC_KEY="a1b2c3d4e5f6..."  # 64 hex characters
export VAC_API_KEY="sk_test_..."

# Optional
export VAC_UPSTREAM_URL="http://localhost:8080"
export VAC_CONTROL_PLANE_URL="http://localhost:8081"
export VAC_HEARTBEAT_INTERVAL_SECS="60"
export VAC_SESSION_KEY_ROTATION_INTERVAL_SECS="300"
export VAC_LOG_LEVEL="info"

cd sidecar
cargo run
```

The sidecar will listen on `0.0.0.0:3000` and start the heartbeat task.

**See [Deployment Guide](docs/DEPLOYMENT.md) for configuration options and production deployment.**

### Running the Control Plane Mock Server

For testing, use the included mock Control Plane:

```bash
cd control-plane
cargo run
```

The Control Plane will listen on `0.0.0.0:8081`.

### Example Request

1. **Generate a test Root Biscuit:**

```bash
cd sidecar
cargo run --example create_test_biscuit
```

This outputs a Root Biscuit token - copy it for the request below.

2. **Send a request through the sidecar:**

```bash
# Single-line command (replace <TOKEN> with token from step 1)
curl -X POST http://localhost:3000/charge -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" -d "{\"amount\": 5000, \"currency\": \"usd\"}"

# Response includes X-VAC-Receipt header for subsequent requests
```

**Note:** Make sure the demo API is running on port 8080 (see `demo-api/README.md`).

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Rust |
| Web | Axum, Tokio, Reqwest |
| Tokens & crypto | Biscuit Auth, Ed25519 |
| Config | Clap, `config` crate, env |
| Logging | Tracing |
| WASM | Wasmtime (adapters) |
| Security | zeroize, libc (mlock) |
| Rate limiting | Custom token bucket |
| Replay cache | DashMap (optional) |

## Project Structure

```
vac/
├── config.toml.example   # Config template (copy to config.toml)
├── LICENSE               # MIT
├── sidecar/              # VAC Sidecar implementation
│   ├── src/
│   │   ├── main.rs       # Entry point, request routing
│   │   ├── config.rs     # Config (files, CLI, env)
│   │   ├── state.rs      # State, session key, rate limiter, replay cache
│   │   ├── biscuit.rs    # Biscuit verification
│   │   ├── receipt.rs    # Receipt extraction & verification
│   │   ├── policy.rs     # Datalog policy evaluation
│   │   ├── proxy.rs      # HTTP proxying, API key injection
│   │   ├── heartbeat.rs  # Heartbeat protocol
│   │   ├── revocation.rs # Token revocation
│   │   ├── adapter.rs    # WASM adapter execution
│   │   ├── delegation.rs # Multi-agent delegation
│   │   ├── security.rs   # Input validation, secure memory
│   │   ├── rate_limit.rs # Token-bucket rate limiting
│   │   ├── replay_cache.rs # Optional replay mitigation
│   │   └── error.rs      # Error types, fail-closed
│   ├── examples/
│   │   ├── generate_test_keys.rs
│   │   └── create_test_biscuit.rs
│   └── tests/
│       ├── integration_test.rs
│       ├── delegation_chain_integration_test.rs
│       ├── wasm_adapter_test.rs
│       └── security_test.rs
├── control-plane/        # Mock Control Plane server
├── demo-api/             # Demo upstream API for testing
├── docs/                 # Architecture, API, deployment, security
├── sdks/
│   └── python/           # Python client library
│       ├── vac_client.py
│       └── example.py
└── examples/
    └── biscuit_spike.rs
```

## Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)** — Detailed system architecture
- **[API Reference](docs/API.md)** — HTTP API and Datalog policy reference
- **[Deployment Guide](docs/DEPLOYMENT.md)** — Production deployment instructions
- **[Security Guide](docs/SECURITY.md)** — Security considerations and threat model
- **[VAC vs Alternatives](docs/VAC_VS_ALTERNATIVES.md)** — Comparison with OAuth, API keys, etc.
- **[LangChain Integration](docs/INTEGRATION_LANGCHAIN.md)** — Using VAC with LangChain agents
- **[Python SDK](sdks/python/)** — Python client library

## Architecture Overview

```
┌─────────────────┐
│ Control Plane   │  Issues credentials, heartbeats, revokes (user's trusted device)
│ (Trusted)       │
└────────┬────────┘
         │ Heartbeat, Revocation, Kill Switch
         ▼
┌─────────────────┐
│ Sidecar         │  Verifies tokens, policy; mints receipts; injects API key
│ (Semi-Trusted)  │
└────────┬────────┘
         │ HTTP (Agent → Sidecar → Upstream API)
         ▼
┌─────────────────┐
│ Agent           │  Never sees API key; carries tokens + receipts
│ (Untrusted)     │
└─────────────────┘
```

### The Three Laws of VAC Trust

1. **The Agent is the Enemy** — Assume actively malicious; never give it the API key.
2. **The Sidecar is the Gatekeeper (but Mortal)** — Trusted but can be compromised; we mitigate with short-lived keys and heartbeat.
3. **The Control Plane is God** — Single source of truth (user's device).

### How It Works (Receipt-Based State)

The agent carries **proofs (receipts)** of completed actions. The sidecar checks those before allowing the next step.

**Example: "Search then Charge"**

1. Control Plane issues a **Root Biscuit** with policy: `allow charge only if receipt("search")`.
2. Agent calls `GET /search` with the Biscuit + correlation ID. Sidecar verifies → forwards → **mints a Receipt** (signed proof of "search").
3. Agent calls `POST /charge` with Biscuit + Receipt + same correlation ID. Sidecar verifies both, checks policy → allows → forwards (injecting API key).

**Why it works:** Stateless (no central DB), scalable, and secure — receipts are signed; the agent can't forge them.

### Main Concepts

| Term | Meaning |
|------|---------|
| **Root Biscuit** | Signed credential from Control Plane with policy rules |
| **Receipt** | Signed proof of a completed action (operation + correlation ID + time); short-lived (~5 min) |
| **Correlation ID** | UUID tying a chain of requests (e.g. search → charge) together |
| **Datalog** | Logic language for policies (allow/deny rules); deterministic |
| **State gate** | Rule that requires a prior action (e.g. "search before charge") |
| **Lockdown** | Mode where only read-only requests allowed (e.g. after heartbeat failures) |

## Security Model

- **Fail-Closed** — Any error leads to deny.
- **Bounded Risk** — 5-minute session keys, 60-second heartbeats, instant revocation.
- **Cryptographic Proofs** — Receipt-based state transitions, not inference.
- **Zero Trust** — Agent never sees API keys; sidecar enforces policies.

## Testing

Run the integration test suite:

```bash
cd sidecar
cargo test --test integration_test
```

Current test coverage:
- Root Biscuit verification, receipt minting and extraction, multi-receipt chain, state gates
- Error handling (missing token, invalid signature, expired receipt)
- WASM adapter execution, multi-agent delegation chains
- Configuration loading (files, CLI, env vars), config precedence
- Security: validation, rate limiting, replay cache (`security_test`)

**Note:** Config tests: run with `--test-threads=1` (env isolation):
```bash
cargo test --lib -- --test-threads=1
```

## Contributing

This is a research project. For questions or contributions, see the [Architecture](docs/ARCHITECTURE.md) and [Security](docs/SECURITY.md) guides.

## License

MIT License - See LICENSE file for details

## Acknowledgments

- [Biscuit Auth](https://www.biscuitsec.org/) — Capability-based tokens with offline attenuation
- [Axum](https://github.com/tokio-rs/axum) — Web framework
- [Tokio](https://tokio.rs/) — Async runtime

---

**If you find this project useful, please consider giving it a star on [GitHub](https://github.com/certainly-param/VAC-protocol).**

**Made with 🍇!**

---

`rust` `security` `ai-agents` `capability` `biscuit` `sidecar` `credentials` `revocation` `datalog`
