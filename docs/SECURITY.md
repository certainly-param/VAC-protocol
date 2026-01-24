# VAC Security Guide

**Security considerations, threat model, and best practices for the VAC Protocol.**

---

## Table of Contents

1. [Threat Model](#threat-model)
2. [Security Guarantees](#security-guarantees)
3. [Attack Vectors & Mitigations](#attack-vectors--mitigations)
4. [Trust Boundaries](#trust-boundaries)
5. [Cryptographic Security](#cryptographic-security)
6. [Operational Security](#operational-security)
7. [Security Best Practices](#security-best-practices)
8. [Known Limitations](#known-limitations)

---

## Threat Model

### Trust Zones

```
┌─────────────────────────────────────┐
│ Green Zone (Trusted)                │
│ - Control Plane                     │
│ - User's Device                     │
│ - Root Private Key                  │
└─────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│ Orange Zone (Semi-Trusted)          │
│ - Sidecar                           │
│ - API Keys (in memory)              │
│ - Session Keys                      │
│                                     │
│ Assumption: Can be compromised      │
│ Mitigation: Short-lived keys,       │
│            heartbeat revocation     │
└─────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│ Red Zone (Untrusted)                │
│ - Agent                             │
│ - LLM Provider                      │
│ - Network (between agent/sidecar)   │
│                                     │
│ Assumption: Actively malicious      │
│ Mitigation: Never sees API keys,    │
│            policy enforcement       │
└─────────────────────────────────────┘
```

### Threat Actors

1. **Malicious Agent**
   - **Capability**: Can send arbitrary requests, attempt to forge tokens
   - **Goal**: Bypass policies, access unauthorized resources
   - **Mitigation**: Cryptographic verification, fail-closed policies

2. **Network Attacker**
   - **Capability**: Can intercept/modify network traffic
   - **Goal**: Replay attacks, token theft
   - **Mitigation**: Receipt expiry, correlation IDs, revocation

3. **Compromised Sidecar**
   - **Capability**: Attacker gains root access to sidecar container
   - **Goal**: Extract API keys, bypass policies
   - **Mitigation**: Short-lived session keys, heartbeat revocation, memory protection (Phase 4.7 - pending)

4. **Compromised Control Plane**
   - **Capability**: Attacker controls Control Plane
   - **Goal**: Issue unauthorized tokens, revoke legitimate tokens
   - **Mitigation**: Control Plane must be on trusted device, use mTLS

---

## Security Guarantees

### What VAC Guarantees

1. **Policy Enforcement**
   - ✅ Agents cannot bypass Datalog policies
   - ✅ Policies are cryptographically verified
   - ✅ Fail-closed: Deny by default

2. **Token Integrity**
   - ✅ Root Biscuits cannot be forged (Ed25519 signatures)
   - ✅ Receipts cannot be forged (session key signatures)
   - ✅ Revoked tokens are rejected

3. **State Integrity**
   - ✅ Receipts prove completed actions (cryptographic proofs)
   - ✅ Correlation IDs prevent cross-workflow attacks
   - ✅ Receipt expiry prevents stale state

4. **Revocation**
   - ✅ Instant revocation via heartbeat (60s max delay)
   - ✅ Lockdown mode after 3 heartbeat failures
   - ✅ Session key rotation invalidates old receipts

### What VAC Does NOT Guarantee

1. **Sidecar Compromise**
   - ❌ If attacker gains root on sidecar, API keys can be extracted
   - **Mitigation**: Short-lived keys, heartbeat revocation, TEE (Phase 4.7 - pending)

2. **Control Plane Compromise**
   - ❌ If Control Plane is compromised, attacker can revoke all tokens
   - **Mitigation**: Control Plane must be on trusted device

3. **Replay Attacks (Stateless)**
   - ❌ Sidecar cannot prevent time-window replay (same request within 5 minutes)
   - **Mitigation**: Rely on upstream API idempotency (Stripe, etc.)

4. **Network Attacks**
   - ❌ No TLS enforcement (assumes TLS at transport layer)
   - **Mitigation**: Always use HTTPS in production

---

## Attack Vectors & Mitigations

### 1. Token Forgery

**Attack**: Agent attempts to forge Root Biscuit or Receipt

**Mitigation**:
- ✅ Ed25519 signatures (cryptographically secure)
- ✅ Public key verification before every request
- ✅ Receipts signed with session key (agent doesn't have)

**Result**: Attack fails - signature verification rejects forged tokens

### 2. Policy Bypass

**Attack**: Agent attempts to bypass Datalog policies

**Mitigation**:
- ✅ Fail-closed enforcement (deny by default)
- ✅ All policies evaluated before request forwarding
- ✅ Receipt facts required for state gates

**Result**: Attack fails - policy engine denies unauthorized requests

### 3. Replay Attack

**Attack**: Attacker intercepts valid request and replays it

**Mitigation**:
- ✅ Receipt expiry (5 minutes)
- ✅ Correlation IDs (prevent cross-workflow attacks)
- ⚠️ **Limitation**: Stateless sidecar cannot prevent time-window replay
- **Deferred**: Rely on upstream API idempotency (Phase 4.8 - optional, can add nonce cache if needed)

**Result**: Attack partially mitigated - replay only works within 5-minute window

### 4. Token Theft

**Attack**: Attacker steals Root Biscuit from agent

**Mitigation**:
- ✅ Revocation filter (instant revocation via heartbeat)
- ✅ Short-lived session keys (5-minute rotation)
- ✅ Lockdown mode (emergency shutdown)

**Result**: Attack mitigated - stolen tokens can be revoked within 60s

### 5. Sidecar Compromise

**Attack**: Attacker gains root access to sidecar container

**Mitigation (Current)**:
- ✅ Short-lived session keys (5-minute rotation)
- ✅ Heartbeat revocation (60s max delay)
- ✅ Lockdown mode (reject non-read-only requests)

**Mitigation (Phase 4.7 - Pending)**:
- 🔜 Memory protection (mlock, zeroization)
- 🔜 TEE integration (Trusted Execution Environment)

**Current Status**: Phase 4.1-4.5 complete (WASM adapters, delegation, config, observability). Memory protection planned for Phase 4.7.

**Result**: Attack partially mitigated - API keys can be extracted, but impact is limited by key rotation

### 6. Control Plane Compromise

**Attack**: Attacker compromises Control Plane

**Mitigation**:
- ✅ Control Plane must be on trusted device (user's device)
- ✅ Use mTLS for Control Plane communication
- ✅ Monitor for unauthorized revocation

**Result**: Critical - Control Plane compromise allows full system control

### 7. Receipt Expiry Bypass

**Attack**: Agent attempts to use expired receipt

**Mitigation**:
- ✅ Receipt expiry check (5 minutes + 30s grace)
- ✅ Timestamp verification before policy evaluation

**Result**: Attack fails - expired receipts are rejected

### 8. Correlation ID Mismatch

**Attack**: Agent uses receipt from different workflow

**Mitigation**:
- ✅ Correlation ID verification
- ✅ Receipt correlation ID must match request correlation ID

**Result**: Attack fails - mismatched correlation IDs are rejected (409 Conflict)

### 9. Denial of Service

**Attack**: Attacker floods sidecar with requests

**Mitigation (Current)**:
- ⚠️ No rate limiting (Phase 3)

**Mitigation (Phase 4)**:
- 🔜 Rate limiting per sidecar_id
- 🔜 Request size limits
- 🔜 Connection limits

**Result**: Attack partially mitigated - upstream API may handle, but sidecar vulnerable

### 10. Heartbeat Spoofing

**Attack**: Attacker spoofs heartbeat to prevent revocation

**Mitigation**:
- ✅ Heartbeat includes sidecar_id and session_key_pub
- ✅ Control Plane tracks registered sidecars
- ✅ Kill switch can force all sidecars unhealthy

**Result**: Attack mitigated - spoofed heartbeats don't prevent revocation

---

## Trust Boundaries

### Green Zone (Trusted)

**Components**:
- Control Plane
- User's Device
- Root Private Key

**Assumptions**:
- ✅ Cannot be compromised
- ✅ Always acts correctly
- ✅ Single source of truth

**Security Measures**:
- Must be on trusted device
- Use mTLS for communication
- Secure key storage

### Orange Zone (Semi-Trusted)

**Components**:
- Sidecar
- API Keys (in memory)
- Session Keys

**Assumptions**:
- ⚠️ Can be compromised (attacker gains root)
- ⚠️ Keys can be extracted from memory
- ✅ Policies are enforced correctly

**Security Measures**:
- Short-lived session keys (5-minute rotation)
- Heartbeat revocation (60s max delay)
- Lockdown mode (emergency shutdown)
- Memory protection (Phase 4)

### Red Zone (Untrusted)

**Components**:
- Agent
- LLM Provider
- Network (agent ↔ sidecar)

**Assumptions**:
- ❌ Actively malicious
- ❌ Attempts to bypass policies
- ❌ Attempts to forge tokens

**Security Measures**:
- Never sees API keys
- Cryptographic verification
- Fail-closed policies
- Receipt expiry

---

## Cryptographic Security

### Ed25519 Signatures

**Algorithm**: Ed25519 (Edwards-curve Digital Signature Algorithm)

**Properties**:
- ✅ Fast (faster than ECDSA, RSA)
- ✅ Small keys (32 bytes public, 64 bytes signature)
- ✅ Side-channel resistant
- ✅ Deterministic (same message = same signature)

**Usage**:
- Root Biscuits: Signed by user's root key
- Receipts: Signed by sidecar's session key

### Token ID Generation

**Algorithm**: SHA-256

**Usage**: Generate consistent token IDs for revocation

```rust
token_id = SHA256(biscuit_base64)
```

**Properties**:
- ✅ Collision-resistant
- ✅ Deterministic
- ✅ 32-byte output (fits revocation filter)

### Key Management

**Root Key**:
- Generated by user (or Control Plane)
- Private key: Never leaves trusted device
- Public key: Configured in sidecar (via config file, CLI, or VAC_ROOT_PUBLIC_KEY env var)

**Session Key**:
- Generated by sidecar on startup
- Rotates every 5 minutes (configurable)
- Ephemeral (lost on restart)

**API Key**:
- Stored in sidecar memory
- Injected into upstream requests
- Never exposed to agent

---

## Operational Security

### Key Rotation

**Session Keys**: Rotate every 5 minutes
- Old receipts become invalid automatically
- Limits exposure if key is compromised

**Root Keys**: Manual rotation
- Generate new key pair
- Update VAC_ROOT_PUBLIC_KEY in sidecar
- Restart sidecar

**API Keys**: Rotate via upstream API provider
- Update VAC_API_KEY in sidecar
- Restart sidecar

### Revocation

**Instant Revocation**:
- Control Plane adds token ID to revocation list
- Pushed to sidecars via heartbeat (60s max delay)
- Sidecar checks revocation before signature verification

**Emergency Revocation**:
- Kill switch activates lockdown mode
- All sidecars reject non-read-only requests
- Can be activated via Control Plane `/kill` endpoint

### Monitoring

**Key Metrics**:
- Heartbeat success rate (should be > 99%)
- Heartbeat latency (should be < 1s)
- Lockdown mode activations (should be 0)
- Policy violation rate
- Request error rate

**Alerts**:
- Heartbeat failures (3+ consecutive)
- Lockdown mode activation
- High policy violation rate
- High error rate

---

## Security Best Practices

### 1. Key Management

**DO**:
- ✅ Store root private key securely (HSM, key management service)
- ✅ Use environment variables or secrets management for API keys
- ✅ Rotate keys regularly
- ✅ Use different keys for different environments

**DON'T**:
- ❌ Commit keys to version control
- ❌ Hardcode keys in source code
- ❌ Share keys across environments
- ❌ Use production keys in development

### 2. Network Security

**DO**:
- ✅ Use HTTPS/TLS for all communication
- ✅ Use mTLS for Control Plane communication
- ✅ Restrict network access (firewall rules)
- ✅ Monitor network traffic

**DON'T**:
- ❌ Use HTTP in production
- ❌ Expose Control Plane to public internet
- ❌ Allow unrestricted network access

### 3. Deployment Security

**DO**:
- ✅ Run sidecar as non-root user
- ✅ Use minimal container images
- ✅ Keep dependencies updated
- ✅ Use secrets management (Kubernetes Secrets, AWS Secrets Manager)

**DON'T**:
- ❌ Run as root user
- ❌ Include unnecessary dependencies
- ❌ Expose debug endpoints in production
- ❌ Store secrets in config files (use environment variables or secrets management instead)
- ✅ Use config files for non-sensitive settings (URLs, intervals)
- ✅ Use CLI arguments for overrides (but avoid in production scripts)

### 4. Monitoring

**DO**:
- ✅ Monitor heartbeat success rate
- ✅ Alert on lockdown mode activation
- ✅ Track policy violations
- ✅ Monitor system resources

**DON'T**:
- ❌ Ignore heartbeat failures
- ❌ Disable logging in production (structured logging is essential for security auditing)
- ✅ Use appropriate log levels (info for production, debug for troubleshooting)
- ✅ Structured logging fields enable security event correlation
- ❌ Skip security audits

### 5. Policy Design

**DO**:
- ✅ Use explicit allow rules
- ✅ Require receipts for state gates
- ✅ Use correlation IDs for workflow tracking
- ✅ Test policies thoroughly

**DON'T**:
- ❌ Use overly permissive policies (`allow if true`)
- ❌ Skip receipt verification
- ❌ Ignore correlation ID mismatches

---

## Known Limitations

### Phase 3 Limitations

1. **Stateless Replay**
   - Sidecar cannot prevent time-window replay (same request within 5 minutes)
   - **Mitigation**: Rely on upstream API idempotency
   - **Future**: Add nonce cache in Phase 4.8 (optional - only if needed)

2. **No Rate Limiting**
   - Sidecar vulnerable to DoS attacks
   - **Future**: Add rate limiting in Phase 4.7

3. **Memory Protection**
   - API keys in plain memory (can be extracted if sidecar compromised)
   - **Future**: Add mlock, zeroization in Phase 4.7

4. **HashSet Revocation**
   - Uses HashSet (3.2MB for 100k tokens) instead of Bloom Filter
   - **Future**: Upgrade to Bloom Filter in Phase 4.7 (~100KB) - currently using HashSet (Phase 3 implementation)

### General Limitations

1. **Control Plane Dependency**
   - Sidecar requires Control Plane for revocation
   - **Mitigation**: Grace period (5-minute tokens), lockdown mode

2. **Clock Synchronization**
   - Receipt expiry depends on system clock
   - **Mitigation**: 30-second grace period for clock skew

3. **WASM Adapters (Phase 4.1 - ✅ Implemented)**
   - ✅ Fact extraction from request bodies via WASM adapters
   - ✅ Hash pinning enforced (SHA-256)
   - ✅ Sandboxed execution (no network/filesystem)
   - ⚠️ **Security Note**: Ensure adapter hashes are verified and from trusted sources

---

## Security Audit Checklist

### Pre-Production

- [ ] Root key pair generated securely
- [ ] API keys stored in secrets management
- [ ] TLS/HTTPS configured
- [ ] Firewall rules configured
- [ ] Monitoring and alerts set up
- [ ] Logging configured (structured logging with appropriate level)
- [ ] Config file security reviewed (no secrets in config files)
- [ ] WASM adapter hashes verified (if using adapters)
- [ ] Delegation depth limits configured (default: max 5)
- [ ] Policies tested thoroughly
- [ ] Revocation tested
- [ ] Lockdown mode tested
- [ ] Key rotation tested

### Ongoing

- [ ] Regular key rotation
- [ ] Monitor heartbeat success rate
- [ ] Review policy violations
- [ ] Security updates applied
- [ ] Dependency updates applied
- [ ] Security audits performed

---

## Incident Response

### Sidecar Compromise

1. **Immediate**: Activate kill switch (Control Plane `/kill`)
2. **Short-term**: Rotate API keys
3. **Long-term**: Investigate, patch, redeploy

### Token Theft

1. **Immediate**: Revoke token via Control Plane
2. **Short-term**: Monitor for unauthorized usage
3. **Long-term**: Review access logs

### Control Plane Compromise

1. **Immediate**: Isolate Control Plane
2. **Short-term**: Rotate all keys
3. **Long-term**: Full security audit

---

**Last Updated**: January 2026  
**Version**: 0.1.0 (Phase 3 Complete)  
**Security Status**: Production-ready with Phase 3 limitations noted
