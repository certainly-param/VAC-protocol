# VAC MCP Server

Exposes VAC (Verifiable Agent Credentials) as **MCP (Model Context Protocol)** tools so AI agents can call the sidecar via MCP.

## Tools

- **vac_request(method, path, body?)** — Send an HTTP request through the VAC sidecar. Returns status, response text, and whether a receipt was issued.
- **vac_receipts_count()** — Info tool (each `vac_request` uses a fresh client; use the Python SDK for multi-step receipt chains).

## Setup

1. Install dependencies (from repo root or mcp-server):

   ```bash
   pip install -r mcp-server/requirements.txt
   pip install -e sdks/python   # so vac_client is available
   ```

2. Set env (or use defaults):

   - `VAC_SIDECAR_URL` — default `http://localhost:3000`
   - `VAC_ROOT_BISCUIT` — your Root Biscuit token (required for real requests)

3. Run the sidecar (and control-plane, demo-api) so the MCP server can reach it.

## Run

**stdio (for Claude Desktop / other MCP clients):**

```bash
cd mcp-server
VAC_ROOT_BISCUIT="<your-token>" python server.py
```

Or add to your MCP client config (e.g. Claude Desktop) with command pointing to this script and env set.

**Streamable HTTP (optional):**

If your MCP server supports it, you can switch to `mcp.run(transport="streamable-http")` and run with a tool like `uv run --with mcp server.py`.

## Resume

This component supports listing **MCP** and **Agentic** on your skills/resume.
