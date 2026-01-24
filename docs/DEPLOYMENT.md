# VAC Deployment Guide

**Production deployment guide for the VAC Sidecar and Control Plane.**

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Sidecar Deployment](#sidecar-deployment)
3. [Control Plane Deployment](#control-plane-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Configuration Management](#configuration-management)
7. [Monitoring & Observability](#monitoring--observability)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **OS**: Linux, macOS, or Windows (Linux recommended for production)
- **Rust**: 1.70+ (for building from source)
- **Memory**: 512MB minimum (1GB recommended)
- **CPU**: 1 core minimum (2+ cores recommended)
- **Network**: Access to Control Plane and upstream APIs

### Dependencies

- **Sidecar**: None (statically linked binary)
- **Control Plane**: None (statically linked binary)

---

## Sidecar Deployment

### Building from Source

```bash
cd sidecar
cargo build --release
```

Binary will be at: `target/release/vac-sidecar`

### Environment Variables

**Required:**
```bash
VAC_ROOT_PUBLIC_KEY="a1b2c3d4e5f6..."  # 64 hex characters (32 bytes)
VAC_API_KEY="sk_test_..."              # API key for upstream requests
```

**Optional:**
```bash
VAC_UPSTREAM_URL="https://api.example.com"           # Default: http://localhost:8080
VAC_CONTROL_PLANE_URL="https://control.example.com"  # Default: http://localhost:8081
VAC_HEARTBEAT_INTERVAL_SECS="60"                     # Default: 60
VAC_SESSION_KEY_ROTATION_INTERVAL_SECS="300"         # Default: 300 (5 minutes)
```

### Running the Sidecar

```bash
# Set environment variables
export VAC_ROOT_PUBLIC_KEY="..."
export VAC_API_KEY="..."

# Run
./target/release/vac-sidecar
```

The sidecar will:
- Listen on `0.0.0.0:3000`
- Start heartbeat task (pings Control Plane every 60s)
- Crash on startup if required env vars are missing

### Systemd Service

**Option 1: Using Config File (Recommended)**

Create `/etc/systemd/system/vac-sidecar.service`:

```ini
[Unit]
Description=VAC Sidecar
After=network.target

[Service]
Type=simple
User=vac
Group=vac
WorkingDirectory=/opt/vac-sidecar
ExecStart=/opt/vac-sidecar/vac-sidecar --config-file /etc/vac-sidecar/config.toml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Option 2: Using Environment Variables**

```ini
[Unit]
Description=VAC Sidecar
After=network.target

[Service]
Type=simple
User=vac
Group=vac
WorkingDirectory=/opt/vac-sidecar
Environment="VAC_ROOT_PUBLIC_KEY=..."
Environment="VAC_API_KEY=..."
Environment="VAC_UPSTREAM_URL=https://api.example.com"
Environment="VAC_CONTROL_PLANE_URL=https://control.example.com"
ExecStart=/opt/vac-sidecar/vac-sidecar
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Option 3: Using CLI Arguments**

```ini
[Unit]
Description=VAC Sidecar
After=network.target

[Service]
Type=simple
User=vac
Group=vac
WorkingDirectory=/opt/vac-sidecar
ExecStart=/opt/vac-sidecar/vac-sidecar --root-public-key "..." --api-key "..." --upstream-url "https://api.example.com"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl enable vac-sidecar
sudo systemctl start vac-sidecar
sudo systemctl status vac-sidecar
```

**Note:** For production, prefer config files or environment variables over CLI arguments for easier management.

---

## Control Plane Deployment

### Building from Source

```bash
cd control-plane
cargo build --release
```

Binary will be at: `target/release/vac-control-plane`

### Running the Control Plane

```bash
./target/release/vac-control-plane
```

The Control Plane will:
- Listen on `0.0.0.0:8081`
- Accept heartbeat requests
- Manage revocation lists
- Provide kill switch functionality

### Systemd Service

Create `/etc/systemd/system/vac-control-plane.service`:

```ini
[Unit]
Description=VAC Control Plane
After=network.target

[Service]
Type=simple
User=vac
Group=vac
WorkingDirectory=/opt/vac-control-plane
ExecStart=/opt/vac-control-plane/vac-control-plane
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## Docker Deployment

### Sidecar Dockerfile

Create `sidecar/Dockerfile`:

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY sidecar/ .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/vac-sidecar /usr/local/bin/vac-sidecar
EXPOSE 3000
ENTRYPOINT ["vac-sidecar"]
```

**Build:**
```bash
docker build -t vac-sidecar:latest -f sidecar/Dockerfile .
```

**Run:**
```bash
docker run -d \
  --name vac-sidecar \
  -p 3000:3000 \
  -e VAC_ROOT_PUBLIC_KEY="..." \
  -e VAC_API_KEY="..." \
  -e VAC_UPSTREAM_URL="https://api.example.com" \
  -e VAC_CONTROL_PLANE_URL="https://control.example.com" \
  vac-sidecar:latest
```

### Control Plane Dockerfile

Create `control-plane/Dockerfile`:

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY control-plane/ .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/vac-control-plane /usr/local/bin/vac-control-plane
EXPOSE 8081
ENTRYPOINT ["vac-control-plane"]
```

**Build and Run:**
```bash
docker build -t vac-control-plane:latest -f control-plane/Dockerfile .
docker run -d --name vac-control-plane -p 8081:8081 vac-control-plane:latest
```

---

## Kubernetes Deployment

### Sidecar Deployment

Create `k8s/sidecar-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vac-sidecar
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vac-sidecar
  template:
    metadata:
      labels:
        app: vac-sidecar
    spec:
      containers:
      - name: sidecar
        image: vac-sidecar:latest
        ports:
        - containerPort: 3000
        env:
        - name: VAC_ROOT_PUBLIC_KEY
          valueFrom:
            secretKeyRef:
              name: vac-secrets
              key: root-public-key
        - name: VAC_API_KEY
          valueFrom:
            secretKeyRef:
              name: vac-secrets
              key: api-key
        - name: VAC_UPSTREAM_URL
          value: "https://api.example.com"
        - name: VAC_CONTROL_PLANE_URL
          value: "https://control.example.com"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: vac-sidecar
spec:
  selector:
    app: vac-sidecar
  ports:
  - port: 3000
    targetPort: 3000
  type: LoadBalancer
```

**Secrets:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vac-secrets
type: Opaque
stringData:
  root-public-key: "a1b2c3d4e5f6..."  # 64 hex characters
  api-key: "sk_test_..."
```

**Deploy:**
```bash
kubectl apply -f k8s/sidecar-deployment.yaml
kubectl apply -f k8s/sidecar-secrets.yaml
```

### Control Plane Deployment

Create `k8s/control-plane-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vac-control-plane
spec:
  replicas: 2
  selector:
    matchLabels:
      app: vac-control-plane
  template:
    metadata:
      labels:
        app: vac-control-plane
    spec:
      containers:
      - name: control-plane
        image: vac-control-plane:latest
        ports:
        - containerPort: 8081
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: vac-control-plane
spec:
  selector:
    app: vac-control-plane
  ports:
  - port: 8081
    targetPort: 8081
  type: LoadBalancer
```

---

## Configuration Management

The sidecar supports **three configuration methods** with precedence: **CLI arguments > environment variables > config file > defaults**.

### Configuration Methods

#### Method 1: Config File (Recommended for Production)

Create a TOML or YAML config file:

**`config.toml`:**
```toml
[sidecar]
root_public_key = "a1b2c3d4e5f6..."  # 64 hex characters (required)
api_key = "your-upstream-api-key"      # Required
upstream_url = "http://localhost:8080"
control_plane_url = "http://localhost:8081"
heartbeat_interval_secs = 60
session_key_rotation_interval_secs = 300
adapters_dir = "/path/to/adapters"     # Optional

[logging]
level = "info"  # trace, debug, info, warn, error
```

**Run with config file:**
```bash
./vac-sidecar --config-file config.toml
```

#### Method 2: CLI Arguments

```bash
./vac-sidecar \
  --root-public-key "a1b2c3d4e5f6..." \
  --api-key "your-api-key" \
  --upstream-url "http://localhost:8080" \
  --control-plane-url "http://localhost:8081" \
  --heartbeat-interval-secs 60 \
  --session-key-rotation-interval-secs 300 \
  --log-level "info"
```

#### Method 3: Environment Variables

```bash
export VAC_ROOT_PUBLIC_KEY="a1b2c3d4e5f6..."
export VAC_API_KEY="your-api-key"
export VAC_UPSTREAM_URL="http://localhost:8080"
export VAC_CONTROL_PLANE_URL="http://localhost:8081"
export VAC_HEARTBEAT_INTERVAL_SECS="60"
export VAC_SESSION_KEY_ROTATION_INTERVAL_SECS="300"
export VAC_LOG_LEVEL="info"
export VAC_ADAPTERS_DIR="/path/to/adapters"

./vac-sidecar
```

**Best Practice**: Use secrets management system (Kubernetes Secrets, AWS Secrets Manager, HashiCorp Vault) for sensitive values like API keys.

### Key Generation

**Generate Root Key Pair:**
```bash
cd sidecar
cargo run --example generate_test_keys
```

This outputs:
- Public key (64 hex characters) - use in `root_public_key`
- Private key (keep secret) - use to sign Root Biscuits

**Or programmatically:**
```rust
use biscuit_auth::KeyPair;

let root_keypair = KeyPair::new();
let public_key_bytes = root_keypair.public().to_bytes();
let public_key_hex = hex::encode(&public_key_bytes);

println!("Public Key (hex): {}", public_key_hex);
// Store private key securely, use public key in VAC_ROOT_PUBLIC_KEY
```

### Configuration Validation

The sidecar validates configuration on startup:
- ✅ Root public key must be 32 bytes (64 hex characters)
- ✅ API key must be set
- ✅ Control Plane URL must be reachable (heartbeat will fail if not)

**Fail-Fast**: Sidecar crashes immediately if required config is missing.

### Configuration Precedence

When multiple sources provide the same setting, precedence is:
1. **CLI arguments** (highest priority)
2. **Environment variables**
3. **Config file**
4. **Defaults** (lowest priority)

Example: If `--api-key` is provided via CLI, it overrides `VAC_API_KEY` env var and config file value.

---

## Monitoring & Observability

### Structured Logging

The sidecar uses `tracing` for structured logging with correlation IDs, request spans, and detailed policy/receipt information.

**Configure Log Level:**

Via config file:
```toml
[logging]
level = "info"  # trace, debug, info, warn, error
```

Via CLI:
```bash
./vac-sidecar --log-level debug
```

Via environment variable:
```bash
export VAC_LOG_LEVEL="debug"
./vac-sidecar
```

Or via RUST_LOG:
```bash
RUST_LOG=info ./vac-sidecar
RUST_LOG=debug ./vac-sidecar  # For detailed debugging
RUST_LOG=warn ./vac-sidecar   # Only warnings and errors
```

**Log Levels:**
- `ERROR`: Critical errors (heartbeat failures, policy violations)
- `WARN`: Warnings (lockdown mode, key rotation, policy denials)
- `INFO`: Normal operation (startup, heartbeat success, policy allows, receipt minting)
- `DEBUG`: Detailed debugging (request processing, policy evaluation details)
- `TRACE`: Very detailed tracing (all operations)

### Structured Log Fields

All logs include structured fields for log aggregation tools:

**Request Logs:**
- `correlation_id` - Request correlation ID
- `method` - HTTP method
- `path` - Request path
- `policy_decision` - "allow" or "deny"
- `policy_reason` - Reason for policy decision (for denials)

**Receipt Logs:**
- `receipt_operation` - Operation from receipt
- `receipt_correlation_id` - Correlation ID from receipt
- `receipt_timestamp` - Receipt timestamp
- `receipt_depth` - Delegation depth
- `delegation_chain_length` - Number of delegation hops

**Example Log Output:**
```
INFO request{correlation_id=abc123 method=POST path=/charge}: Policy evaluation: ALLOW - Request authorized
INFO request{correlation_id=abc123 method=POST path=/charge}: Receipt minted successfully receipt_operation="POST /charge" receipt_correlation_id=abc123 receipt_timestamp=1234567890
```

### LLM-Readable Error Messages

Policy violations include actionable error messages for AI agents:
- ❌ Bad: "Access Denied"
- ✅ Good: "Missing required fact: prior_event('search') - Agent should review required facts/operations"

This helps agents understand what operation is needed next.

### Key Metrics to Monitor

**Sidecar Health:**
- Heartbeat success rate
- Heartbeat latency
- Lockdown mode activations
- Session key rotation events

**Request Metrics:**
- Request count (by status code)
- Policy violation count
- Receipt minting rate
- Average request latency

**System Metrics:**
- Memory usage
- CPU usage
- Network I/O

### Health Checks

**Sidecar Health Endpoint** (Future: Phase 4)
- `GET /health` - Returns sidecar health status
- `GET /ready` - Returns readiness status

**Current**: Monitor via logs and heartbeat status

---

## Troubleshooting

### Common Issues

#### 1. Sidecar Won't Start

**Symptom**: Sidecar crashes immediately on startup

**Causes:**
- Missing `VAC_ROOT_PUBLIC_KEY` or `VAC_API_KEY`
- Invalid root public key format (must be 64 hex characters)

**Solution:**
```bash
# Check environment variables
env | grep VAC_

# Verify root public key format
echo $VAC_ROOT_PUBLIC_KEY | wc -c  # Should be 65 (64 chars + newline)
```

#### 2. Heartbeat Failures

**Symptom**: `heartbeat_failure_count` increasing, eventually lockdown mode

**Causes:**
- Control Plane unreachable
- Network issues
- Control Plane returning unhealthy

**Solution:**
```bash
# Check Control Plane connectivity
curl http://control.example.com:8081/sidecars

# Check sidecar logs
journalctl -u vac-sidecar -f

# Verify Control Plane is running
systemctl status vac-control-plane
```

#### 3. Policy Violations

**Symptom**: Requests returning `403 Forbidden` with "Policy violation"

**Causes:**
- Missing required receipts
- Receipt correlation ID mismatch
- Receipt expired

**Solution:**
- Check request includes required `X-VAC-Receipt` headers
- Verify correlation IDs match across request chain
- Check receipt timestamps (must be < 5 minutes old)

#### 4. Lockdown Mode

**Symptom**: All non-GET requests rejected

**Causes:**
- 3 consecutive heartbeat failures
- Kill switch activated on Control Plane

**Solution:**
```bash
# Check heartbeat status
# (Check logs for heartbeat failures)

# Deactivate kill switch (if needed)
curl -X POST http://control.example.com:8081/revive

# Restart sidecar (if needed)
systemctl restart vac-sidecar
```

### Debug Mode

Enable debug logging:

```bash
RUST_LOG=debug vac-sidecar
```

This will log:
- Request processing steps
- Policy evaluation details
- Receipt extraction results
- Heartbeat request/response

### Network Debugging

**Test Sidecar Connectivity:**
```bash
# Test sidecar endpoint
curl -v http://localhost:3000/api/test \
  -H "Authorization: Bearer <biscuit>"

# Test Control Plane
curl http://localhost:8081/sidecars
```

**Check Firewall Rules:**
- Sidecar: Port 3000 (inbound)
- Control Plane: Port 8081 (inbound)
- Upstream API: Outbound access required

---

## Production Checklist

### Pre-Deployment

- [ ] Root key pair generated and stored securely
- [ ] API keys configured and tested
- [ ] Control Plane deployed and accessible
- [ ] Upstream API endpoints verified
- [ ] Environment variables set correctly
- [ ] Logging configured
- [ ] Monitoring set up

### Deployment

- [ ] Sidecar deployed with correct configuration
- [ ] Heartbeat task running (check logs)
- [ ] Test request succeeds
- [ ] Receipt minting works
- [ ] Policy enforcement verified
- [ ] Revocation tested (revoke token, verify rejection)

### Post-Deployment

- [ ] Monitor heartbeat success rate
- [ ] Monitor request metrics
- [ ] Set up alerts for:
  - Heartbeat failures
  - Lockdown mode activation
  - High error rates
  - Policy violation spikes

---

## Scaling Considerations

### Horizontal Scaling

**Sidecar**: Stateless design supports horizontal scaling
- Deploy multiple replicas behind load balancer
- No shared state database required
- Each sidecar maintains its own session key

**Control Plane**: Can be scaled for high availability
- Deploy multiple replicas
- Use shared state (database) for revocation lists
- Load balance heartbeat requests

### Vertical Scaling

**Sidecar**:
- CPU: 1-2 cores sufficient for most workloads
- Memory: 512MB-1GB (depends on revocation list size)

**Control Plane**:
- CPU: 1 core sufficient
- Memory: 256MB-512MB

---

## Backup & Recovery

### Critical Data

1. **Root Private Key**: Store securely (never in code/config)
2. **API Keys**: Store in secrets management system
3. **Revocation Lists**: Control Plane state (backup if using database)

### Recovery Procedures

**Sidecar Recovery:**
- Restart with same configuration
- Session keys regenerate (old receipts become invalid)
- Heartbeat resumes automatically

**Control Plane Recovery:**
- Restore revocation list from backup
- Restart service
- Sidecars will reconnect on next heartbeat

---

**Last Updated**: January 2026  
**Version**: 0.1.0 (Phase 3 Complete)
