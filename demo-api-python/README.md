# VAC Demo API (Python / FastAPI)

Python/FastAPI version of the VAC demo upstream API. Same endpoints and response shapes as the [Rust demo-api](../demo-api/), so the VAC sidecar can use this as upstream interchangeably.

## Features

- **API Key auth**: `Authorization: Bearer <key>` (sidecar injects this when forwarding)
- **Endpoints**: `GET /health`, `POST /search`, `POST /charge` (same as Rust demo-api)
- **Config**: `DEMO_API_KEY`, `DEMO_API_PORT` (default: `demo-api-key`, `8080`)

## Quick Start

```bash
cd demo-api-python
pip install -r requirements.txt
python main.py
# Or: uvicorn main:app --host 0.0.0.0 --port 8080
```

Server runs at `http://localhost:8080`. Set env if needed:

```bash
export DEMO_API_KEY="demo-api-key"
export DEMO_API_PORT=8080
python main.py
```

## Use with VAC Sidecar

1. Start this API: `python main.py` (or use the Rust demo-api).
2. In sidecar config, set `upstream_url = "http://localhost:8080"` and `api_key = "demo-api-key"`.
3. Send requests to the sidecar (e.g. `http://localhost:3000/search`) with a Root Biscuit; the sidecar forwards to this API with the API key.

## Endpoints

| Method | Path    | Auth   | Body                          |
|--------|---------|--------|-------------------------------|
| GET    | /health | No     | -                             |
| POST   | /search | Bearer | `{"query": "string"}`         |
| POST   | /charge | Bearer | `{"amount": int, "currency": "string", "description?": "string"}` |

Responses match the Rust demo-api: `{ "success": bool, "message": str, "data": ... }`.

## Docker

From repo root:

```bash
docker-compose --profile fastapi build demo-api-python
docker-compose --profile fastapi up demo-api-python
# API on host port 8082. To use as sidecar upstream:
# VAC_UPSTREAM_URL=http://demo-api-python:8080 docker-compose --profile fastapi up
```
