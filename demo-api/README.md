# V-A-C Demo API

A simple demo backend API server for testing the V-A-C sidecar. This simulates an upstream API service that the sidecar forwards requests to.

## Features

- **API Key Authentication**: Requires API key in `Authorization: Bearer <key>` header
- **Demo Endpoints**: 
  - `GET /health` - Health check (no auth required)
  - `POST /search` - Search endpoint (requires API key)
  - `POST /charge` - Payment charge endpoint (requires API key)
  - `* /*path` - Generic endpoint handler for any path
- **Configurable**: API key and port can be set via CLI args or env vars

## Quick Start

### 1. Build and Run

```bash
cd demo-api
cargo run
```

This starts the server on `http://localhost:8080` with default API key `"demo-api-key"`.

### 2. Customize Configuration

**Via CLI arguments:**
```bash
cargo run -- --api-key "my-secret-key" --port 9000
```

**Via environment variables:**
```bash
export DEMO_API_KEY="my-secret-key"
export DEMO_API_PORT=9000
cargo run
```

### 3. Test the API

**Health check (no auth):**
```bash
curl http://localhost:8080/health
```

**Search endpoint (requires API key):**
```bash
curl -X POST http://localhost:8080/search \
  -H "Authorization: Bearer demo-api-key" \
  -H "Content-Type: application/json" \
  -d '{"query": "test search"}'
```

**Charge endpoint (requires API key):**
```bash
curl -X POST http://localhost:8080/charge \
  -H "Authorization: Bearer demo-api-key" \
  -H "Content-Type: application/json" \
  -d '{"amount": 5000, "currency": "usd", "description": "Test charge"}'
```

## Using with V-A-C Sidecar

### Configuration

In your `config.toml` for the sidecar:

```toml
[sidecar]
root_public_key = "<your-root-public-key>"
api_key = "demo-api-key"  # Must match DEMO_API_KEY
upstream_url = "http://localhost:8080"  # Demo API URL
control_plane_url = "http://localhost:8081"
```

### Flow

1. **Start Demo API:**
   ```bash
   cd demo-api
   cargo run -- --api-key "demo-api-key"
   ```

2. **Start V-A-C Sidecar:**
   ```bash
   cd sidecar
   cargo run --bin vac-sidecar -- --config-file ../config.toml
   ```

3. **Send request through sidecar:**
   ```bash
   curl -X POST http://localhost:3000/charge \
     -H "Authorization: Bearer <Root-Biscuit-Token>" \
     -H "Content-Type: application/json" \
     -d '{"amount": 5000, "currency": "usd"}'
   ```

The sidecar will:
- Verify the Root Biscuit
- Check policy
- Forward to demo API at `http://localhost:8080/charge` with API key `"demo-api-key"`
- Return response with receipt

## API Endpoints

### GET /health
Health check endpoint (no authentication required).

**Response:**
```json
{
  "success": true,
  "message": "Demo API is healthy",
  "data": null
}
```

### POST /search
Search endpoint (requires API key).

**Request:**
```json
{
  "query": "search term"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Found 2 results",
  "data": {
    "results": [
      {"id": "1", "title": "Result for: search term", "score": 0.95},
      {"id": "2", "title": "Another result for: search term", "score": 0.87}
    ],
    "count": 2,
    "query": "search term"
  }
}
```

### POST /charge
Payment charge endpoint (requires API key).

**Request:**
```json
{
  "amount": 5000,
  "currency": "usd",
  "description": "Optional description"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Charge processed successfully",
  "data": {
    "id": "ch_abc123...",
    "amount": 5000,
    "currency": "usd",
    "status": "succeeded",
    "description": "Optional description"
  }
}
```

### * /*path
Generic endpoint handler for any other path.

**Response:**
```json
{
  "success": true,
  "message": "Received GET request to /custom/path",
  "data": {
    "method": "GET",
    "path": "/custom/path",
    "timestamp": "2024-01-01T12:00:00Z"
  }
}
```

## Error Responses

### 401 Unauthorized
Returned when API key is missing or invalid.

```json
{
  "success": false,
  "message": "Unauthorized",
  "data": null
}
```

## Development

### Adding New Endpoints

Edit `src/main.rs` and add new route handlers:

```rust
async fn my_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<MyRequest>,
) -> Result<Json<ApiResponse>, StatusCode> {
    verify_api_key(&headers, &state.api_key)?;
    // Your logic here
    Ok(Json(ApiResponse { ... }))
}

// Add to router:
.route("/my-endpoint", post(my_endpoint))
```

## Testing

The demo API is designed to work seamlessly with the V-A-C sidecar for end-to-end testing. It provides realistic API responses while being simple enough to understand and modify.
