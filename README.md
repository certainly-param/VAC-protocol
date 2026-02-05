<p align="center">
  <img src="assets/logo.png" alt="VAC Protocol" width="500">
</p>

<p align="center">
  <strong>Capability-based security for AI agents</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.70+-orange.svg" alt="Rust">
</p>

## What is VAC?

Agents today often get broad, long-lived API keys with no real context or fast revocation. VAC gives them **task-scoped credentials** instead: policies (Datalog) define what’s allowed; receipts prove what was done; a sidecar enforces both and injects the real API key. Revocation is heartbeat-based (seconds, not days).

**In short:** the agent never sees the API key. It gets a signed Biscuit and, after each allowed call, a signed Receipt. The next call can only be allowed if policy says so and the right receipts are present.

## Quick Start

**Prerequisites:** Rust 1.70+, a Control Plane (use the mock in `control-plane/` for testing).

1. **Generate a root key and create config:**

```bash
cd sidecar
cargo run --example generate_test_keys   # copy the public key
cp ../config.toml.example ../config.toml
# Edit config.toml: set root_public_key and api_key
```

2. **Run sidecar and Control Plane:**

```bash
# Terminal 1
cargo run --bin vac-sidecar -- --config-file ../config.toml

# Terminal 2
cd control-plane && cargo run
```

Sidecar listens on `0.0.0.0:3000`, Control Plane on `0.0.0.0:8081`. Optional: run the demo API (`demo-api/` or `demo-api-python/`) on 8080.

3. **Get a test Biscuit and send a request:**

```bash
cd sidecar
cargo run --example create_test_biscuit   # copy the token

curl -X POST http://localhost:3000/charge \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"amount": 5000, "currency": "usd"}'
```

Response will include `X-VAC-Receipt` for use in follow-up requests. More options (CLI, env): [Deployment](docs/DEPLOYMENT.md).

## Docs

| Doc | Description |
|-----|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Components, request flow, state |
| [API](docs/API.md) | HTTP API, headers, Datalog policy |
| [Deployment](docs/DEPLOYMENT.md) | Config, Docker, Kubernetes |
| [Observability](docs/OBSERVABILITY.md) | Tracing, OpenTelemetry |
| [LangChain integration](docs/INTEGRATION_LANGCHAIN.md) | Using VAC with LangChain / LangGraph |
| [Python SDK](sdks/python/README.md) | Client library and examples |

## How it works

- **Control Plane** (trusted): issues Root Biscuits, runs heartbeats, revocation, kill switch.
- **Sidecar** (semi-trusted): verifies Biscuits and receipts, evaluates Datalog policy, mints receipts, forwards to upstream with API key. Can be compromised; we use short-lived session keys and heartbeat revocation to limit impact.
- **Agent** (untrusted): never sees the API key; sends Biscuit + receipts; all traffic goes through the sidecar.

Receipts are signed proofs of completed actions (e.g. “search” done). Policies can require them (e.g. “allow charge only if receipt(search)”). Same workflow is tied together by a **correlation ID**. Receipts expire in ~5 minutes; session keys rotate on the same order.

| Term | Meaning |
|------|---------|
| **Root Biscuit** | Signed credential from Control Plane; embeds policy |
| **Receipt** | Signed proof of one completed action; short-lived |
| **Correlation ID** | Ties a chain of requests (e.g. search → charge) |
| **Datalog** | Policy language (allow/deny); deterministic |
| **Lockdown** | Mode where only read-only is allowed (e.g. after heartbeat failures) |

## Repo layout

```
vac/
├── sidecar/          # Main proxy: biscuit, receipt, policy, proxy, heartbeat, revocation, etc.
├── control-plane/    # Mock server (heartbeat, revoke, kill)
├── demo-api/         # Rust demo upstream API
├── demo-api-python/  # FastAPI demo upstream
├── sdks/python/      # Python client (vac_client, example)
├── docs/             # Architecture, API, deployment, observability, LangChain
├── examples/         # langgraph_vac.py, biscuit_spike.rs
├── mcp-server/       # MCP server (vac_request, vac_receipts_count)
└── k8s/              # Kubernetes sidecar deployment
```

## Tech stack

Rust (Axum, Tokio, Reqwest), Biscuit Auth, Ed25519, Clap + config + env, tracing, Wasmtime (WASM adapters), token-bucket rate limiting, optional replay cache. See [Architecture](docs/ARCHITECTURE.md).

## Testing

```bash
cd sidecar
cargo test --lib -- --test-threads=1
cargo test --test integration_test --test delegation_chain_integration_test \
  --test delegation_depth_test --test heartbeat_test --test revocation_test \
  --test security_test --test wasm_adapter_test -- --test-threads=1
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). For design and layout, [Architecture](docs/ARCHITECTURE.md).

## License

MIT. See [LICENSE](LICENSE).

## Thanks

[Biscuit Auth](https://www.biscuitsec.org/), [Axum](https://github.com/tokio-rs/axum), [Tokio](https://tokio.rs/).

<p align="center">Made while eating a lot of 🍊!</p>!
