# VAC + LangChain Integration

## Overview

LangChain agents call tools (APIs). Without VAC they often use raw API keys. With VAC: agents get **task-scoped credentials** (Root Biscuits), each action yields a **receipt**, policies enforce workflows (e.g. search before charge), and **revocation** is fast.

**Flow:** Agent → VAC Client (adds Biscuit + receipts) → VAC Sidecar (policy) → Upstream API. Receipt returned for next steps.

## Setup

1. **Run sidecar:** `cd sidecar && cargo run --bin vac-sidecar -- --config-file ../config.toml`
2. **Python client:** Use `sdks/python` (see [sdks/python/README.md](../sdks/python/README.md)) or `pip install -e sdks/python`
3. **Root Biscuit:** `cd sidecar && cargo run --example create_test_biscuit` — use token in your agent

## LangGraph Example

Runnable example: [examples/langgraph_vac.py](../examples/langgraph_vac.py). Two-node workflow (search → charge); receipts auto-accumulate.

```bash
pip install langgraph
# Set ROOT_BISCUIT, run sidecar + demo-api, then:
python examples/langgraph_vac.py
```

## Patterns

**VAC-aware tool:** Wrap tool logic to call `vac.post("/charge", json={...})` (or get/search). On 403, surface policy message to the agent.

**Multi-step workflow:** One `VACClient` per workflow; call `get("/search", params={"q": "..."})` then `post("/charge", json={...})`. Receipts accumulate automatically; policy can require prior steps.

## Error Handling

- **401:** Missing/invalid token — check `root_biscuit`
- **403:** Policy denied — if "prior_event" in message, complete prior step; if "expired", restart workflow
- **409:** Correlation ID mismatch — use one correlation ID per workflow

## See Also

- [API Reference](API.md)
- [Architecture](ARCHITECTURE.md)
- [Security](SECURITY.md)
