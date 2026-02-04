"""
VAC Protocol Python Client

A simple client for interacting with VAC sidecars from Python applications.

Usage:
    from vac_client import VACClient
    
    vac = VACClient(
        sidecar_url="http://localhost:3000",
        root_biscuit="<your-biscuit-token>"
    )
    
    # Make requests - receipts auto-accumulate
    response = vac.get("/search", params={"q": "flights"})
    response = vac.post("/charge", json={"amount": 100})
"""

import uuid
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

try:
    import httpx
    USE_HTTPX = True
except ImportError:
    import requests
    USE_HTTPX = False


@dataclass
class VACResponse:
    """Response from VAC sidecar.
    Note: headers is a single-value-per-name dict; duplicate header names in the
    raw response collapse to one value (use the receipt field for X-VAC-Receipt).
    """
    status_code: int
    headers: Dict[str, str]
    text: str
    receipt: Optional[str] = None
    
    def json(self) -> Any:
        """Parse response body as JSON. Returns None if body is empty; raises json.JSONDecodeError if not valid JSON."""
        import json
        return json.loads(self.text) if self.text else None
    
    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300
    
    def raise_for_status(self):
        if not self.ok:
            raise VACError(self.status_code, self.text)


class VACError(Exception):
    """Error from VAC sidecar."""
    
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"VAC Error {status_code}: {message}")
    
    @property
    def is_policy_violation(self) -> bool:
        return self.status_code == 403
    
    @property
    def is_missing_receipt(self) -> bool:
        return self.status_code == 403 and (
            "prior_event" in self.message or "prior step" in self.message
        )
    
    @property
    def is_expired(self) -> bool:
        return self.status_code == 403 and "expired" in self.message.lower()
    
    @property
    def is_correlation_mismatch(self) -> bool:
        return self.status_code == 409


@dataclass
class VACClient:
    """
    VAC Protocol client for Python.
    
    Handles:
    - Authorization header with Root Biscuit
    - Correlation ID tracking
    - Receipt accumulation for multi-step workflows
    - Multiple X-VAC-Receipt headers
    
    Args:
        sidecar_url: URL of the VAC sidecar (default: http://localhost:3000)
        root_biscuit: Base64-encoded Root Biscuit token
        correlation_id: Optional correlation ID (auto-generated if not provided)
    """
    sidecar_url: str = "http://localhost:3000"
    root_biscuit: str = ""
    correlation_id: Optional[str] = None
    receipts: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        self.sidecar_url = self.sidecar_url.rstrip("/")
        if self.correlation_id is None:
            self.correlation_id = str(uuid.uuid4())
    
    def _build_headers(self, include_content_type: bool = True) -> List[tuple]:
        """Build headers list (supports multiple same-name headers)."""
        headers = [
            ("Authorization", f"Bearer {self.root_biscuit}"),
            ("X-Correlation-ID", self.correlation_id),
        ]
        if include_content_type:
            headers.append(("Content-Type", "application/json"))
        for receipt in self.receipts:
            headers.append(("X-VAC-Receipt", receipt))
        return headers
    
    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
    ) -> VACResponse:
        """Make a request through the VAC sidecar.
        Provide only one of json or data per request; if both are set, json is used.
        Content-Type: application/json is sent only when the request has a body (non-GET or json/data provided).
        """
        path = path if path.startswith("/") else f"/{path}"
        url = f"{self.sidecar_url}{path}"
        has_body = json is not None or data is not None
        include_content_type = method.upper() != "GET" or has_body
        headers = self._build_headers(include_content_type=include_content_type)
        
        if USE_HTTPX:
            response = self._request_httpx(method, url, headers, params, json, data)
        else:
            response = self._request_requests(method, url, headers, params, json, data)
        
        # Store new receipt if present
        receipt = response.headers.get("X-VAC-Receipt") or response.headers.get("x-vac-receipt")
        if receipt:
            self.receipts.append(receipt)
        
        return VACResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            receipt=receipt,
        )
    
    def _request_httpx(self, method, url, headers, params, json_data, data):
        """Make request using httpx (supports multiple same-name headers)."""
        with httpx.Client(timeout=30.0) as client:
            return client.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_data if json_data is not None else None,
                content=data if json_data is None else None,
            )
    
    def _request_requests(self, method, url, headers, params, json_data, data):
        """Make request using requests library.
        Note: requests does not support multiple headers with the same name.
        The sidecar expects multiple X-VAC-Receipt headers; with requests we send
        one comma-separated value, which the sidecar may reject. Use httpx for
        multi-step workflows (search -> select -> charge).
        """
        if len(self.receipts) > 1:
            import warnings
            warnings.warn(
                "Multiple receipts with 'requests' library: sidecar expects separate "
                "X-VAC-Receipt headers. Multi-step workflows may fail. Install httpx.",
                UserWarning,
                stacklevel=2,
            )
        headers_dict = {}
        for k, v in headers:
            if k in headers_dict and k == "X-VAC-Receipt":
                headers_dict[k] = f"{headers_dict[k]}, {v}"
            else:
                headers_dict[k] = v

        return requests.request(
            method,
            url,
            headers=headers_dict,
            params=params,
            json=json_data if json_data is not None else None,
            data=data if json_data is None else None,
            timeout=30.0,
        )
    
    def get(self, path: str, **kwargs) -> VACResponse:
        """GET request through VAC sidecar."""
        return self._request("GET", path, **kwargs)
    
    def post(self, path: str, **kwargs) -> VACResponse:
        """POST request through VAC sidecar."""
        return self._request("POST", path, **kwargs)
    
    def put(self, path: str, **kwargs) -> VACResponse:
        """PUT request through VAC sidecar."""
        return self._request("PUT", path, **kwargs)
    
    def patch(self, path: str, **kwargs) -> VACResponse:
        """PATCH request through VAC sidecar."""
        return self._request("PATCH", path, **kwargs)
    
    def delete(self, path: str, **kwargs) -> VACResponse:
        """DELETE request through VAC sidecar."""
        return self._request("DELETE", path, **kwargs)
    
    def clear_receipts(self) -> None:
        """Clear stored receipts and generate new correlation ID."""
        self.receipts = []
        self.correlation_id = str(uuid.uuid4())
    
    def new_workflow(self) -> "VACClient":
        """Create a new client instance for a fresh workflow."""
        return VACClient(
            sidecar_url=self.sidecar_url,
            root_biscuit=self.root_biscuit,
        )


# Convenience function
def create_client(
    sidecar_url: str = "http://localhost:3000",
    root_biscuit: str = "",
) -> VACClient:
    """Create a new VAC client."""
    return VACClient(sidecar_url=sidecar_url, root_biscuit=root_biscuit)


if __name__ == "__main__":
    # Example usage
    print("VAC Client Example")
    print("==================")
    print()
    print("Usage:")
    print("  from vac_client import VACClient")
    print()
    print("  vac = VACClient(")
    print('      sidecar_url="http://localhost:3000",')
    print('      root_biscuit="<your-biscuit-token>"')
    print("  )")
    print()
    print("  # Search (gets receipt)")
    print('  r1 = vac.get("/search", params={"q": "flights"})')
    print()
    print("  # Charge (requires search receipt)")
    print('  r2 = vac.post("/charge", json={"amount": 100})')
    print()
    print("  # Start new workflow")
    print("  vac.clear_receipts()")
