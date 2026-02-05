# VAC Observability and OpenTelemetry

## Current tracing (sidecar)

The VAC sidecar uses **Rust `tracing`** with structured fields:

- **Request**: `correlation_id`, `method`, `path`
- **Policy**: `policy_decision` (allow/deny), `policy_reason`
- **Receipt**: `receipt_operation`, `receipt_correlation_id`, `receipt_timestamp`, `receipt_depth`

Configure log level via `VAC_LOG_LEVEL` or `RUST_LOG` (e.g. `info`, `debug`). Logs go to stdout in a format suitable for log aggregation (e.g. JSON with `tracing_subscriber`).

## OpenTelemetry (optional)

### Rust sidecar: OTLP export

To export traces to an OpenTelemetry collector (e.g. Jaeger, Tempo), add a tracing layer that bridges `tracing` to OpenTelemetry and an OTLP exporter. Example crates:

- `tracing-opentelemetry` — bridge from `tracing` to OpenTelemetry
- `opentelemetry` + `opentelemetry-sdk` — tracer provider
- `opentelemetry-otlp` — OTLP exporter (HTTP or gRPC)

Example (pseudo-code; add to `main.rs` when OTLP is enabled via env):

```rust
// When OTEL_EXPORTER_OTLP_ENDPOINT is set:
// 1. Build TracerProvider with OTLP exporter
// 2. Add tracing_opentelemetry::layer().with_tracer(tracer) to your Registry
// 3. Keep existing fmt layer for stdout logs
```

Spans to create: one per request (method, path, correlation_id), and child spans for policy evaluation and receipt minting.

### Python SDK: optional spans

The Python client can be used with **OpenTelemetry instrumentation** so each request is a span:

1. **Automatic**: Use `opentelemetry-instrumentation-httpx` so all httpx calls (including VAC client requests) get a span. Install and run with:

   ```bash
   pip install opentelemetry-instrumentation-httpx opentelemetry-exporter-otlp
   opentelemetry-bootstrap -a install
   # Then run your app; httpx calls will be traced
   ```

2. **Manual**: In your code, wrap VAC calls in a span:

   ```python
   from opentelemetry import trace
   tracer = trace.get_tracer("vac-client", "0.1.0")
   with tracer.start_as_current_span("vac.request", attributes={"http.method": "POST", "http.path": "/charge"}):
       resp = vac.post("/charge", json={"amount": 100})
   ```
