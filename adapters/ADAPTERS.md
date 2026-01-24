## VAC WASM Adapters (Phase 4.2)

This directory is the **local adapter registry** for the VAC sidecar.

### How pinning works

- Root Biscuits can include: `adapter_hash("<sha256-hex>")`
- The sidecar will only execute adapters whose **SHA-256 hash matches** the pin.

### Loading adapters

- **Local directory preload**: set `VAC_ADAPTERS_DIR` to this directory path (or any directory containing `.wasm` files).
  - On startup, the sidecar loads all `*.wasm` files and indexes them by SHA-256.

### Adapter ABI (Phase 4.1/4.2)

The WASM module must export:

- `memory` (linear memory)
- `extract_facts(i32 ptr, i32 len) -> i32`

Return value: pointer to a **NUL-terminated UTF-8 JSON string** in guest memory with the format:

```json
[
  {"fact": "amount", "args": ["350"]},
  {"fact": "currency", "args": ["USD"]}
]
```

### Notes

- Adapters are treated as **untrusted code**. Keep them minimal and deterministic.
- Network and filesystem access are not provided by default.

