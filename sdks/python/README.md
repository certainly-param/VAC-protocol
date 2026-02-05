# VAC Python Client

Simple Python client for the VAC (Verifiable Agentic Credential) Protocol.

## Installation

```bash
# Copy vac_client.py to your project, or:
pip install httpx  # Recommended for proper multi-header support
```

## Quick Start

```python
from vac_client import VACClient

# Create client
vac = VACClient(
    sidecar_url="http://localhost:3000",
    root_biscuit="<your-biscuit-token>"
)

# Make requests - receipts auto-accumulate
response = vac.get("/search", params={"q": "flights"})
print(f"Search: {response.status_code}")

response = vac.post("/charge", json={"amount": 100, "currency": "usd"})
print(f"Charge: {response.status_code}")

# Start new workflow (clears receipts, new correlation ID)
vac.clear_receipts()
```

## Features

- Automatic receipt accumulation
- Correlation ID management
- Multiple `X-VAC-Receipt` header support (with httpx)
- Error classification (policy violation, expired, etc.)

## Error Handling

```python
from vac_client import VACClient, VACError

vac = VACClient(root_biscuit="...")

try:
    response = vac.post("/charge", json={"amount": 100})
    response.raise_for_status()
except VACError as e:
    if e.is_missing_receipt:
        print("Need to complete prior steps first")
    elif e.is_expired:
        print("Receipt expired - restart workflow")
    elif e.is_policy_violation:
        print(f"Policy denied: {e.message}")
```

## Multi-Step Workflows

```python
import uuid
from vac_client import VACClient

# All requests in a workflow share a correlation ID
vac = VACClient(
    root_biscuit="...",
    correlation_id=str(uuid.uuid4())  # Or let it auto-generate
)

# Step 1: Search
vac.get("/search", params={"q": "flights to NYC"})

# Step 2: Select (policy may require search first)
vac.post("/select", json={"flight_id": "AA123"})

# Step 3: Charge (policy may require search + select)
vac.post("/charge", json={"amount": 35000})

# Receipts are automatically included in each request
print(f"Receipts collected: {len(vac.receipts)}")
```

## Requirements

- Python 3.7+
- `httpx` (recommended) or `requests`

**Observability:** For OpenTelemetry tracing of VAC requests, install with `pip install vac-client[opentelemetry]` and use `opentelemetry-instrumentation-httpx`, or see [docs/OBSERVABILITY.md](../../docs/OBSERVABILITY.md) in the repo.

**Multi-step workflows (search → select → charge):** The sidecar expects multiple `X-VAC-Receipt` headers, one per prior step. The `requests` library cannot send multiple headers with the same name, so multi-step workflows will fail with `requests`. Use `httpx` for any flow that accumulates more than one receipt.

## License

MIT
