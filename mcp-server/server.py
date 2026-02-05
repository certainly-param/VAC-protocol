"""
VAC MCP Server

Exposes VAC (Verifiable Agent Credentials) as MCP tools so AI agents can
call the sidecar via the Model Context Protocol. Requires sidecar URL and
root biscuit (env or defaults).
"""

import os
import sys
from typing import Any, Optional

# Allow importing vac_client from sibling sdks/python when run from mcp-server/
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_sdks_python = os.path.join(_REPO_ROOT, "sdks", "python")
if _sdks_python not in sys.path:
    sys.path.insert(0, _sdks_python)

from vac_client import VACClient, VACError

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    raise ImportError("Install MCP SDK: pip install mcp")

SIDECAR_URL = os.environ.get("VAC_SIDECAR_URL", "http://localhost:3000")
ROOT_BISCUIT = os.environ.get("VAC_ROOT_BISCUIT", "")

mcp = FastMCP(
    "VAC",
    description="Verifiable Agent Credentials: task-scoped credentials and receipt-chained requests via VAC sidecar.",
)


@mcp.tool()
def vac_request(
    method: str,
    path: str,
    body: Optional[dict] = None,
) -> dict:
    """Send an HTTP request through the VAC sidecar. Method (GET, POST, etc.), path (e.g. /search, /charge), and optional JSON body. Returns status, response body, and whether a receipt was issued."""
    if not ROOT_BISCUIT:
        return {"ok": False, "error": "VAC_ROOT_BISCUIT not set"}
    client = VACClient(sidecar_url=SIDECAR_URL, root_biscuit=ROOT_BISCUIT)
    try:
        method = method.upper()
        if method == "GET":
            resp = client.get(path, params=body or None)
        elif method == "POST":
            resp = client.post(path, json=body)
        elif method == "PUT":
            resp = client.put(path, json=body)
        elif method == "PATCH":
            resp = client.patch(path, json=body)
        else:
            resp = client._request(method, path, json=body)
    except VACError as e:
        return {
            "ok": False,
            "status_code": e.status_code,
            "message": e.message,
            "is_missing_receipt": e.is_missing_receipt,
            "is_expired": e.is_expired,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}
    out = {"ok": resp.ok, "status_code": resp.status_code, "text": resp.text[:500] if resp.text else ""}
    if resp.receipt:
        out["receipt_issued"] = True
    try:
        out["json"] = resp.json()
    except Exception:
        pass
    return out


@mcp.tool()
def vac_receipts_count() -> dict:
    """Return the number of receipts the current VAC client session has (for debugging). Each vac_request uses a fresh client, so this always returns 0 unless you use the SDK directly."""
    return {"receipts_count": 0, "note": "Each vac_request uses a new client; use Python SDK for multi-step receipt chains."}


if __name__ == "__main__":
    mcp.run(transport="stdio")
