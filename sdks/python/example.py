#!/usr/bin/env python3
"""
VAC Client Example

Demonstrates a multi-step workflow:
1. Search for flights
2. Select a flight
3. Charge the customer

Each step generates a receipt that's required for the next step.
"""

from vac_client import VACClient, VACError

# Your Root Biscuit token (get from: cargo run --example create_test_biscuit)
ROOT_BISCUIT = "<paste-your-token-here>"

def main():
    print("VAC Client Example")
    print("=" * 50)
    
    # Create client
    vac = VACClient(
        sidecar_url="http://localhost:3000",
        root_biscuit=ROOT_BISCUIT
    )
    print(f"Correlation ID: {vac.correlation_id}")
    print()
    
    # Step 1: Search
    print("[Step 1] Searching for flights...")
    try:
        response = vac.get("/search", params={"q": "flights to NYC"})
        if response.ok:
            print(f"  Status: {response.status_code}")
            print(f"  Receipt: {response.receipt[:50]}..." if response.receipt else "  No receipt")
        else:
            print(f"  Error: {response.text}")
            return
    except Exception as e:
        print(f"  Failed: {e}")
        return
    
    print()
    
    # Step 2: Select
    print("[Step 2] Selecting flight...")
    try:
        response = vac.post("/select", json={"flight_id": "AA123"})
        if response.ok:
            print(f"  Status: {response.status_code}")
            print(f"  Receipt: {response.receipt[:50]}..." if response.receipt else "  No receipt")
        else:
            print(f"  Error: {response.text}")
            return
    except Exception as e:
        print(f"  Failed: {e}")
        return
    
    print()
    
    # Step 3: Charge (use raise_for_status so VACError is raised on 403/409 for proper handling)
    print("[Step 3] Charging customer...")
    try:
        response = vac.post("/charge", json={"amount": 35000, "currency": "usd"})
        if not response.ok:
            response.raise_for_status()
        print(f"  Status: {response.status_code}")
        print(f"  Response: {response.text[:100]}...")
    except VACError as e:
        if e.is_missing_receipt:
            print(f"  Policy requires prior step: {e.message}")
        elif e.is_expired:
            print(f"  Receipt expired: {e.message}")
        else:
            print(f"  Policy denied: {e.message}")
        return
    except Exception as e:
        print(f"  Failed: {e}")
        return
    
    print()
    print("=" * 50)
    print(f"Workflow complete! Receipts collected: {len(vac.receipts)}")


if __name__ == "__main__":
    main()
