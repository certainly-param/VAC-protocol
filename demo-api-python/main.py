"""
VAC Demo API (FastAPI)

Python counterpart to the Rust demo-api. Same endpoints and response shapes
so the VAC sidecar can use this as upstream. Used for testing and as a
Backend (FastAPI) showcase.
"""

import os
import uuid
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel

app = FastAPI(
    title="VAC Demo API",
    description="Demo upstream API for VAC sidecar (Python/FastAPI)",
    version="0.1.0",
)

# Config from env (same as Rust: DEMO_API_KEY, DEMO_API_PORT)
API_KEY = os.environ.get("DEMO_API_KEY", "demo-api-key")
PORT = int(os.environ.get("DEMO_API_PORT", "8080"))


# --- Request/Response models (match Rust demo-api) ---

class ApiResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None


class SearchRequest(BaseModel):
    query: str


class ChargeRequest(BaseModel):
    amount: int
    currency: str
    description: Optional[str] = None


def verify_api_key(authorization: Optional[str] = Header(None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization[7:].strip()
    if token != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health", response_model=ApiResponse)
async def health():
    """Health check (no auth required)."""
    return ApiResponse(success=True, message="Demo API is healthy", data=None)


@app.post("/search", response_model=ApiResponse)
async def search(
    payload: SearchRequest,
    _: None = Depends(verify_api_key),
):
    """Search endpoint (requires API key). Sidecar injects Bearer token."""
    results = [
        {"id": "1", "title": f"Result for: {payload.query}", "score": 0.95},
        {"id": "2", "title": f"Another result for: {payload.query}", "score": 0.87},
    ]
    return ApiResponse(
        success=True,
        message=f"Found {len(results)} results",
        data={
            "results": results,
            "count": len(results),
            "query": payload.query,
        },
    )


@app.post("/charge", response_model=ApiResponse)
async def charge(
    payload: ChargeRequest,
    _: None = Depends(verify_api_key),
):
    """Charge endpoint (requires API key). Sidecar injects Bearer token."""
    charge_id = f"ch_{uuid.uuid4().hex}"
    return ApiResponse(
        success=True,
        message="Charge processed successfully",
        data={
            "id": charge_id,
            "amount": payload.amount,
            "currency": payload.currency,
            "status": "succeeded",
            "description": payload.description,
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
