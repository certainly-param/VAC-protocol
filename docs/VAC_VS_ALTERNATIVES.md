# VAC vs Alternatives

**Why VAC? A comparison with existing approaches to AI agent security.**

---

## The Problem

AI agents need API access to be useful, but current approaches give them too much power:

- **Permanent credentials** — API keys that never expire
- **No context awareness** — Can't distinguish "book a flight" from "delete all data"
- **Slow revocation** — Rotating keys takes hours or days
- **No audit trail** — Hard to prove what was allowed vs. what happened

---

## Comparison Table

| Approach | Task-Scoped | Context-Aware | Instant Revoke | Cryptographic Proof | Offline Capable |
|----------|:-----------:|:-------------:|:--------------:|:------------------:|:---------------:|
| **VAC Protocol** | Yes | Yes | Yes | Yes | Yes |
| API Keys | No | No | No | No | Yes |
| OAuth 2.0 | Partial | No | Slow | No | Yes |
| Sandbox / Scoped APIs | Partial | No | N/A | No | Yes |
| Human-in-the-Loop | Yes | Yes | Yes | No | No |
| Constitutional AI | No | Partial | No | No | Yes |
| TEEs (SGX, etc.) | No | No | No | Partial | Yes |

---

## Detailed Comparisons

### VAC vs API Keys

| Aspect | API Keys | VAC |
|--------|----------|-----|
| **Scope** | Full access to everything the key allows | Task-specific: "charge up to $400 for this booking" |
| **Lifetime** | Permanent until manually rotated | Short-lived (minutes), auto-expiring receipts |
| **Revocation** | Rotate key (affects all users) | Instant per-token revocation via heartbeat |
| **Audit** | Log requests, hope they're honest | Cryptographic receipts prove what happened |
| **Leaked key impact** | Full compromise | Limited: scoped permissions + fast revocation |

**Bottom line:** API keys are "all or nothing." VAC gives "just enough, just in time."

---

### VAC vs OAuth 2.0

| Aspect | OAuth 2.0 | VAC |
|--------|-----------|-----|
| **Designed for** | Human users authorizing apps | AI agents executing tasks |
| **Token lifetime** | Hours to days (refresh tokens: months) | Minutes (receipts: ~5 min) |
| **Workflow context** | None — token is token | Receipt chain proves prior steps |
| **Revocation speed** | Token expiry or blocklist check | 60-second heartbeat, instant kill switch |
| **Delegation** | Limited (no attenuation) | Biscuit tokens with offline attenuation |
| **Policy language** | Scopes (coarse-grained) | Datalog (fine-grained, composable) |

**Bottom line:** OAuth was built for "user clicks approve." VAC was built for "agent does 50 API calls in 10 seconds."

---

### VAC vs Sandbox / Scoped APIs

| Aspect | Sandboxed APIs | VAC |
|--------|----------------|-----|
| **Granularity** | Per-endpoint (e.g., read-only mode) | Per-task, per-request (Datalog policies) |
| **State awareness** | None | Receipt-based: "charge only after search" |
| **Flexibility** | Rigid — API decides what's allowed | Dynamic — policies defined at credential time |
| **Composability** | Limited | Full: receipts chain, delegation attenuates |

**Example:** A sandbox might allow `/payments` or not. VAC can say: "allow `/payments` only if amount < $400 AND you called `/search` first AND correlation IDs match."

**Bottom line:** Sandboxes are binary. VAC is contextual.

---

### VAC vs Human-in-the-Loop

| Aspect | Human Approval | VAC |
|--------|----------------|-----|
| **Latency** | Seconds to hours (human response time) | Milliseconds (cryptographic check) |
| **Scalability** | Doesn't scale — approval fatigue | Scales infinitely — automated enforcement |
| **Consistency** | Humans make mistakes, get tired | Deterministic Datalog — same input, same result |
| **Autonomy** | Kills agent autonomy | Preserves autonomy within bounds |

**Bottom line:** Human-in-the-loop is the nuclear option. VAC lets you define the rules once and enforce them forever.

---

### VAC vs Constitutional AI

| Aspect | Constitutional AI | VAC |
|--------|-------------------|-----|
| **Enforcement** | AI self-constrains (prompt-based) | External enforcement (sidecar) |
| **Bypass risk** | Jailbreaks, hallucinations, prompt injection | Cryptographic — can't forge receipts |
| **Determinism** | Probabilistic (LLM reasoning) | Deterministic (Datalog logic) |
| **Auditability** | "The AI said it was safe" | Signed receipts prove what was checked |

**Example failure:** Constitutional AI might "reason" that deleting a database is fine because it's "helping clean up." VAC doesn't care about reasoning — no receipt for `allow_delete`, no delete.

**Bottom line:** Don't use AI to constrain AI. Use math.

---

### VAC vs TEEs (Trusted Execution Environments)

| Aspect | TEEs (SGX, TrustZone) | VAC |
|--------|----------------------|-----|
| **Trust model** | Trust the hardware | Trust the cryptography |
| **Deployment** | Requires special hardware | Runs anywhere (sidecar container) |
| **Transparency** | Opaque enclave | Open policies, auditable receipts |
| **Compromise recovery** | Hardware recall | Rotate keys, revoke tokens |
| **Cost** | Expensive (specialized chips) | Free (software-only) |

**Complementary:** VAC can run inside a TEE for defense-in-depth, but doesn't require one.

**Bottom line:** TEEs protect the runtime. VAC protects the permissions.

---

## When to Use VAC

**Use VAC when:**

- Agents make API calls on behalf of users
- You need fine-grained, task-specific permissions
- Fast revocation matters (seconds, not hours)
- You want cryptographic proof of what was allowed
- Agents delegate to other agents (multi-agent workflows)

**VAC might be overkill when:**

- Simple CRUD app with human users (use OAuth)
- Fully trusted internal service (use mTLS + service mesh)
- No autonomous agents involved

---

## Summary

| If you're using... | Consider VAC because... |
|--------------------|------------------------|
| API keys | VAC adds scoping, expiry, revocation, and proofs |
| OAuth 2.0 | VAC handles agent-speed workflows and context |
| Sandboxes | VAC adds dynamic, composable policies |
| Human approval | VAC automates enforcement without killing autonomy |
| Constitutional AI | VAC enforces deterministically, not probabilistically |
| TEEs | VAC complements with permission-layer security |

---

**VAC: The right amount of power, for the right task, with proof.**
