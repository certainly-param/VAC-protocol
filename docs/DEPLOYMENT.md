# VAC Deployment

## Prerequisites

- **Rust:** 1.78+ (for building). **Memory:** 512MB min. **Network:** Access to Control Plane and upstream API.

## Sidecar

**Build:** `cd sidecar && cargo build --release` → `target/release/vac-sidecar`

**Env (required):** `VAC_ROOT_PUBLIC_KEY` (64 hex), `VAC_API_KEY`

**Env (optional):** `VAC_UPSTREAM_URL` (default `http://localhost:8080`), `VAC_CONTROL_PLANE_URL` (default `http://localhost:8081`), `VAC_HEARTBEAT_INTERVAL_SECS`, `VAC_SESSION_KEY_ROTATION_INTERVAL_SECS`, `VAC_LOG_LEVEL`

**Run:** `./target/release/vac-sidecar` (or `--config-file config.toml`)

## Control Plane

**Build:** `cd control-plane && cargo build --release` → `target/release/vac-control-plane`

**Run:** `./target/release/vac-control-plane` (listens on 8081)

## Docker

Use the Dockerfiles in `sidecar/`, `control-plane/`, `demo-api/`. From repo root:

```bash
docker-compose build
# Set VAC_ROOT_PUBLIC_KEY (and optionally VAC_API_KEY), then:
docker-compose up
```

## Kubernetes

Manifests in `k8s/`. Create Secret `vac-secrets` with keys `root-public-key` and `api-key`. Apply `k8s/sidecar-deployment.yaml` (and optionally control-plane).

## Configuration

**Precedence:** CLI > env > config file > defaults.

**Example `config.toml`:**
```toml
[sidecar]
root_public_key = "a1b2c3d4e5f6..."  # 64 hex
api_key = "your-upstream-api-key"
upstream_url = "http://localhost:8080"
control_plane_url = "http://localhost:8081"

[logging]
level = "info"
```

**Key generation:** `cd sidecar && cargo run --example generate_test_keys`
