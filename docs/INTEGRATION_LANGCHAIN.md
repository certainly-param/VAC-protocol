# VAC + LangChain Integration Guide

**How to secure your LangChain agents with VAC Protocol.**

---

## Overview

LangChain agents can call external tools (APIs, databases, etc.). Without VAC, these agents typically use raw API keys — giving them unlimited access.

With VAC:
- Agents get **task-scoped credentials** (Root Biscuits)
- Each action generates a **receipt** (cryptographic proof)
- Policies enforce **"search before charge"** style workflows
- Instant **revocation** if something goes wrong

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Your Application                                            │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐ │
│  │ LangChain   │───▶│ VAC Client  │───▶│ VAC Sidecar     │ │
│  │ Agent       │    │ (Python)    │    │ (localhost:3000)│ │
│  └─────────────┘    └─────────────┘    └────────┬────────┘ │
│                                                  │          │
└──────────────────────────────────────────────────┼──────────┘
                                                   │
                                                   ▼
                                          ┌───────────────┐
                                          │ Upstream API  │
                                          │ (Stripe, etc.)│
                                          └───────────────┘
```

**Flow:**
1. Agent decides to call a tool (e.g., "charge customer")
2. VAC Client adds the Root Biscuit + receipts to the request
3. VAC Sidecar verifies policies, forwards to upstream API
4. Receipt returned — agent stores it for next steps

---

## Setup

### 1. Run the VAC Sidecar

```bash
# From the VAC repo
cd sidecar
cargo run --bin vac-sidecar -- --config-file ../config.toml
```

### 2. Install the VAC Python Client

```bash
pip install vac-client  # Coming soon — see below for manual setup
```

Or use the manual client (see [Python Client](#python-client) section below).

### 3. Create a Root Biscuit

```bash
cd sidecar
cargo run --example create_test_biscuit
```

Copy the token — you'll use it in your agent.

---

## Integration Patterns

### Pattern 1: VAC-Aware Tool

Wrap your LangChain tools to use VAC:

```python
from langchain.tools import BaseTool
from vac_client import VACClient

class VACProtectedTool(BaseTool):
    name = "charge_customer"
    description = "Charge a customer's payment method"
    
    def __init__(self, vac_client: VACClient):
        super().__init__()
        self.vac = vac_client
    
    def _run(self, amount: int, currency: str = "usd") -> str:
        response = self.vac.post(
            "/charge",
            json={"amount": amount, "currency": currency}
        )
        
        if response.status_code == 403:
            return f"Policy denied: {response.text}"
        
        return f"Charged {amount} {currency}. Transaction ID: {response.json()['id']}"
```

### Pattern 2: Workflow with Receipts

For multi-step workflows (search → select → charge):

```python
from vac_client import VACClient
import uuid

# Create client with a correlation ID for this workflow
correlation_id = str(uuid.uuid4())
vac = VACClient(
    sidecar_url="http://localhost:3000",
    root_biscuit="<your-biscuit-token>",
    correlation_id=correlation_id
)

# Step 1: Search (gets a receipt)
search_result = vac.get("/search", params={"q": "flights to NYC"})
# Receipt automatically stored in vac.receipts

# Step 2: Select (requires search receipt)
select_result = vac.post("/select", json={"flight_id": "AA123"})
# Another receipt stored

# Step 3: Charge (requires search + select receipts)
charge_result = vac.post("/charge", json={"amount": 35000, "currency": "usd"})
# Policy: "allow charge if receipt(search) AND receipt(select)"
```

### Pattern 3: LangChain Agent with VAC Toolkit

```python
from langchain.agents import initialize_agent, AgentType
from langchain.llms import OpenAI
from vac_langchain import VACToolkit  # Hypothetical integration

# Initialize VAC
vac_toolkit = VACToolkit(
    sidecar_url="http://localhost:3000",
    root_biscuit="<your-biscuit-token>"
)

# Create agent with VAC-protected tools
agent = initialize_agent(
    tools=vac_toolkit.get_tools(),
    llm=OpenAI(temperature=0),
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True
)

# Run the agent — all tool calls go through VAC
result = agent.run("Book me a flight to NYC under $400")
```

---

## Python Client

Until `vac-client` is published to PyPI, use this minimal client:

```python
# vac_client.py
import requests
from typing import Optional, Dict, Any, List

class VACClient:
    """Simple VAC Protocol client for Python."""
    
    def __init__(
        self,
        sidecar_url: str = "http://localhost:3000",
        root_biscuit: str = "",
        correlation_id: Optional[str] = None
    ):
        self.sidecar_url = sidecar_url.rstrip("/")
        self.root_biscuit = root_biscuit
        self.correlation_id = correlation_id or self._generate_correlation_id()
        self.receipts: List[str] = []
    
    def _generate_correlation_id(self) -> str:
        import uuid
        return str(uuid.uuid4())
    
    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.root_biscuit}",
            "X-Correlation-ID": self.correlation_id,
        }
        # Add all receipts
        for i, receipt in enumerate(self.receipts):
            # Multiple X-VAC-Receipt headers
            headers[f"X-VAC-Receipt"] = receipt  # Last one wins in dict
        return headers
    
    def _build_receipt_headers(self) -> List[tuple]:
        """For requests that need multiple headers with same name."""
        headers = [
            ("Authorization", f"Bearer {self.root_biscuit}"),
            ("X-Correlation-ID", self.correlation_id),
        ]
        for receipt in self.receipts:
            headers.append(("X-VAC-Receipt", receipt))
        return headers
    
    def request(
        self,
        method: str,
        path: str,
        **kwargs
    ) -> requests.Response:
        url = f"{self.sidecar_url}{path}"
        
        # Use prepared request for multiple same-name headers
        req = requests.Request(method, url, **kwargs)
        req.headers = dict(self._build_receipt_headers())
        
        session = requests.Session()
        prepared = session.prepare_request(req)
        
        # Fix headers for multiple X-VAC-Receipt
        if len(self.receipts) > 1:
            receipt_headers = "\r\n".join(
                f"X-VAC-Receipt: {r}" for r in self.receipts
            )
            # This is a simplification — proper impl needs raw socket or httpx
        
        response = session.send(prepared)
        
        # Store new receipt if present
        if "X-VAC-Receipt" in response.headers:
            self.receipts.append(response.headers["X-VAC-Receipt"])
        
        return response
    
    def get(self, path: str, **kwargs) -> requests.Response:
        return self.request("GET", path, **kwargs)
    
    def post(self, path: str, **kwargs) -> requests.Response:
        return self.request("POST", path, **kwargs)
    
    def put(self, path: str, **kwargs) -> requests.Response:
        return self.request("PUT", path, **kwargs)
    
    def delete(self, path: str, **kwargs) -> requests.Response:
        return self.request("DELETE", path, **kwargs)
    
    def clear_receipts(self):
        """Clear stored receipts (start new workflow)."""
        self.receipts = []
        self.correlation_id = self._generate_correlation_id()
```

### Usage

```python
from vac_client import VACClient

# Create client
vac = VACClient(
    sidecar_url="http://localhost:3000",
    root_biscuit="Em0KC...<your-token>..."
)

# Make requests — receipts auto-accumulate
r1 = vac.get("/search", params={"q": "flights"})
print(f"Search: {r1.status_code}")

r2 = vac.post("/charge", json={"amount": 100})
print(f"Charge: {r2.status_code}")  # Works if policy allows after search

# Start new workflow
vac.clear_receipts()
```

---

## Policies for LangChain Agents

Example Datalog policies for common agent patterns:

### Read-Only Agent

```datalog
// Allow only GET requests
allow if operation("GET", $path);
```

### Search-Before-Action Agent

```datalog
// Allow search anytime
allow if operation("GET", "/search");

// Allow charge only after search
allow if operation("POST", "/charge"),
      prior_event($op, $cid, $ts),
      $op.starts_with("GET /search");
```

### Budget-Limited Agent

```datalog
// Allow charges under $500 (amount in cents)
allow if operation("POST", "/charge"),
      prior_event("GET /search", $cid, $ts);

// Note: Amount checking requires WASM adapter to extract from body
```

### Time-Boxed Agent

```datalog
// Only allow operations until a deadline
check if time($t), $t < 2026-02-01T00:00:00Z;
allow if operation($method, $path);
```

---

## Error Handling

VAC returns specific errors — handle them in your agent:

```python
def safe_tool_call(vac: VACClient, path: str, **kwargs):
    response = vac.post(path, **kwargs)
    
    if response.status_code == 401:
        raise Exception("Missing or invalid token — check root_biscuit")
    
    if response.status_code == 403:
        error = response.text
        if "prior_event" in error:
            raise Exception(f"Policy requires prior step: {error}")
        if "expired" in error.lower():
            raise Exception("Receipt expired — retry workflow from start")
        raise Exception(f"Policy denied: {error}")
    
    if response.status_code == 409:
        raise Exception("Correlation ID mismatch — receipts from different workflow")
    
    return response
```

---

## Best Practices

1. **One correlation ID per task** — Don't reuse across unrelated tasks
2. **Store receipts** — You need them for multi-step workflows
3. **Handle 403s gracefully** — Policy denials are expected, not errors
4. **Short-lived biscuits** — Issue new credentials per task, not per session
5. **Log correlation IDs** — Makes debugging much easier

---

## Next Steps

- [API Reference](API.md) — Full protocol details
- [Security Guide](SECURITY.md) — Threat model and best practices
- [Architecture Guide](ARCHITECTURE.md) — How VAC works internally

---

**Questions?** Open an issue on [GitHub](https://github.com/certainly-param/VAC-protocol).
