"""
LangGraph + VAC Example

Minimal LangGraph workflow where each node calls the VAC sidecar. Receipts
auto-accumulate on the client, so search -> charge enforces policy (e.g. charge
only after search). Run with sidecar + control-plane + demo-api (or demo-api-python)
and a valid ROOT_BISCUIT.
"""

import os
import sys
from typing import TypedDict

# Add sdks/python so we can import vac_client from repo root or examples/
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SDK = os.path.join(_REPO_ROOT, "sdks", "python")
if _SDK not in sys.path:
    sys.path.insert(0, _SDK)

from vac_client import VACClient, VACError


class State(TypedDict, total=False):
    """Graph state: query, amount, and response/error strings."""
    query: str
    amount: int
    search_response: str
    charge_response: str
    error: str


def make_search_node(vac: VACClient):
    def search_node(state: State) -> State:
        query = state.get("query", "flights to NYC")
        try:
            resp = vac.get("/search", params={"q": query})
            return {"search_response": resp.text, "error": "" if resp.ok else resp.text}
        except Exception as e:
            return {"error": str(e)}
    return search_node


def make_charge_node(vac: VACClient):
    def charge_node(state: State) -> State:
        amount = state.get("amount", 35000)
        try:
            resp = vac.post("/charge", json={"amount": amount, "currency": "usd"})
            return {"charge_response": resp.text, "error": "" if resp.ok else resp.text}
        except VACError as e:
            return {"error": f"VACError: {e.message}", "charge_response": ""}
        except Exception as e:
            return {"error": str(e)}
    return charge_node


def main():
    sidecar_url = os.environ.get("VAC_SIDECAR_URL", "http://localhost:3000")
    root_biscuit = os.environ.get("ROOT_BISCUIT", os.environ.get("VAC_ROOT_BISCUIT", ""))
    if not root_biscuit:
        print("Set ROOT_BISCUIT or VAC_ROOT_BISCUIT (and run sidecar + demo-api)")
        return

    try:
        from langgraph.graph import StateGraph, END
    except ImportError:
        print("Install LangGraph: pip install langgraph")
        return

    vac = VACClient(sidecar_url=sidecar_url, root_biscuit=root_biscuit)
    graph = StateGraph(State)
    graph.add_node("search", make_search_node(vac))
    graph.add_node("charge", make_charge_node(vac))
    graph.set_entry_point("search")
    graph.add_edge("search", "charge")
    graph.add_edge("charge", END)
    app = graph.compile()

    initial: State = {
        "query": "flights to NYC",
        "amount": 35000,
        "search_response": "",
        "charge_response": "",
        "error": "",
    }
    result = app.invoke(initial)
    print("Search response:", (result.get("search_response") or "")[:200])
    print("Charge response:", (result.get("charge_response") or "")[:200])
    if result.get("error"):
        print("Error:", result["error"])
    print("Receipts collected:", len(vac.receipts))


if __name__ == "__main__":
    main()
