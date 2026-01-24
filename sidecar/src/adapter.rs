use wasmtime::{Engine, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::WasiP1Ctx;
use crate::error::VacError;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::Deserialize;
use std::time::Duration;

/// Maximum size for WASM adapter modules (10MB)
const MAX_MODULE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum execution time for adapter (5 seconds)
const MAX_EXECUTION_TIME_MS: u64 = 5000;

/// Maximum bytes we'll read from adapter output.
///
/// This is a safety cap to prevent scanning unbounded memory if the adapter
/// returns an invalid pointer or forgets to NUL-terminate its output.
const MAX_ADAPTER_OUTPUT_BYTES: usize = 256 * 1024;

/// WASM Adapter Registry
/// 
/// Manages loaded WASM adapters with hash verification and caching.
/// Adapters are pinned by SHA-256 hash for security.
#[derive(Clone)]
pub struct AdapterRegistry {
    /// Loaded adapters (hash -> (module, engine))
    adapters: Arc<RwLock<HashMap<String, (Module, Engine)>>>,
}

impl AdapterRegistry {
    /// Create a new adapter registry
    pub fn new() -> Self {
        Self {
            adapters: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Load an adapter from bytes and verify its hash
    /// 
    /// # Arguments
    /// - `wasm_bytes`: The WASM module bytes
    /// - `expected_hash`: Expected SHA-256 hash (hex-encoded)
    /// 
    /// # Returns
    /// - `Ok(())` if adapter loaded and hash matches
    /// - `Err(VacError)` if hash mismatch or load fails
    pub fn load_adapter(
        &self,
        wasm_bytes: &[u8],
        expected_hash: &str,
    ) -> Result<(), VacError> {
        // Verify hash
        let computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(wasm_bytes);
            hex::encode(hasher.finalize())
        };
        
        if computed_hash != expected_hash {
            return Err(VacError::ConfigError(format!(
                "Adapter hash mismatch: expected {}, got {}",
                expected_hash, computed_hash
            )));
        }
        
        // Check size
        if wasm_bytes.len() > MAX_MODULE_SIZE {
            return Err(VacError::ConfigError(format!(
                "Adapter module too large: {} bytes (max {})",
                wasm_bytes.len(), MAX_MODULE_SIZE
            )));
        }
        
        // Create engine with limited resources
        let engine = Engine::default();
        
        // Compile module
        let module = Module::new(&engine, wasm_bytes)
            .map_err(|e| VacError::InternalError(format!("Failed to compile WASM module: {}", e)))?;
        
        // Cache adapter
        {
            let mut adapters = self.adapters.write().map_err(|_| {
                VacError::InternalError("Failed to acquire adapter registry lock".to_string())
            })?;
            adapters.insert(expected_hash.to_string(), (module, engine));
        }
        
        Ok(())
    }
    
    /// Get a cached adapter by hash
    fn get_adapter(&self, hash: &str) -> Option<(Module, Engine)> {
        let adapters = self.adapters.read().ok()?;
        adapters.get(hash).cloned()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract facts from HTTP request body using a WASM adapter
/// 
/// # Arguments
/// - `adapter_hash`: SHA-256 hash of the adapter (must be loaded first)
/// - `request_body`: Raw HTTP request body bytes
/// - `registry`: Adapter registry with loaded adapters
/// 
/// # Returns
/// - `Ok(Vec<Fact>)`: Datalog facts extracted from body
/// - `Err(VacError)`: Error if adapter not found, execution fails, or output invalid
/// 
/// # Adapter Interface
/// The WASM adapter must export a function:
/// ```wat
/// (func $extract_facts (param i32 i32) (result i32))
/// ```
/// 
/// Parameters:
/// - `i32`: Pointer to request body bytes
/// - `i32`: Length of request body
/// 
/// Returns:
/// - `i32`: Pointer to JSON-encoded facts array
/// 
/// JSON Format:
/// ```json
/// [
///   {"fact": "amount", "args": ["350"]},
///   {"fact": "currency", "args": ["USD"]}
/// ]
/// ```
pub async fn extract_facts_from_body(
    adapter_hash: &str,
    request_body: &[u8],
    registry: &AdapterRegistry,
) -> Result<Vec<AdapterFact>, VacError> {
    // Enforce a time limit on adapter execution.
    //
    // NOTE: This is a pragmatic Phase 4.1 timeout. It will cancel awaiting the result,
    // but does not preempt the underlying thread if it is stuck in guest code.
    // A stricter implementation can use epoch interruption in a future hardening step.
    let adapter_hash = adapter_hash.to_string();
    let request_body = request_body.to_vec();
    let registry = registry.clone();

    let handle = tokio::task::spawn_blocking(move || {
        extract_facts_from_body_sync(&adapter_hash, &request_body, &registry)
    });

    match tokio::time::timeout(Duration::from_millis(MAX_EXECUTION_TIME_MS), handle).await {
        Ok(join_res) => join_res.map_err(|e| {
            VacError::InternalError(format!("WASM adapter task join failed: {}", e))
        })?,
        Err(_) => Err(VacError::InternalError(format!(
            "WASM adapter exceeded {}ms execution limit",
            MAX_EXECUTION_TIME_MS
        ))),
    }
}

fn extract_facts_from_body_sync(
    adapter_hash: &str,
    request_body: &[u8],
    registry: &AdapterRegistry,
) -> Result<Vec<AdapterFact>, VacError> {
    // Get adapter from registry
    let (module, engine) = registry
        .get_adapter(adapter_hash)
        .ok_or_else(|| VacError::ConfigError(format!("Adapter not found: {}", adapter_hash)))?;

    // Create WASI context (sandboxed):
    // - no preopened dirs
    // - no inherited env/args
    let wasi_ctx: WasiP1Ctx = WasiCtxBuilder::new().build_p1();

    let mut store = Store::new(&engine, wasi_ctx);

    // Create instance with WASI
    let mut linker = wasmtime::Linker::new(&engine);
    wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |s: &mut WasiP1Ctx| s)
        .map_err(|e| VacError::InternalError(format!("Failed to create WASI linker: {}", e)))?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| VacError::InternalError(format!("Failed to instantiate WASM module: {}", e)))?;

    // Get memory
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| VacError::InternalError("WASM module must export 'memory'".to_string()))?;

    // Get extract_facts function
    let extract_facts = instance
        .get_typed_func::<(i32, i32), i32>(&mut store, "extract_facts")
        .map_err(|e| {
            VacError::InternalError(format!(
                "WASM module must export 'extract_facts' function: {}",
                e
            ))
        })?;

    // Write request body to memory
    let body_ptr = {
        let ptr_u64 = memory.data_size(&store);
        let ptr: usize = usize::try_from(ptr_u64).map_err(|_| {
            VacError::InternalError("WASM memory pointer does not fit in usize".to_string())
        })?;

        // Grow memory if needed
        let new_size: usize = ptr
            .checked_add(request_body.len())
            .and_then(|v: usize| v.checked_add(1024)) // extra space for output
            .ok_or_else(|| VacError::InternalError("WASM memory size overflow".to_string()))?;

        let page_size: usize = 64 * 1024;
        let required_pages: u64 = ((new_size + (page_size - 1)) / page_size) as u64;
        let current_pages: u64 = memory.size(&store);
        if required_pages > current_pages {
            let additional_pages = required_pages - current_pages;
            memory
                .grow(&mut store, additional_pages)
                .map_err(|e| VacError::InternalError(format!("Failed to grow memory: {}", e)))?;
        }

        let memory_view = memory.data_mut(&mut store);
        let start = ptr;
        let end = start
            .checked_add(request_body.len())
            .ok_or_else(|| VacError::InternalError("WASM body pointer overflow".to_string()))?;
        if end > memory_view.len() {
            return Err(VacError::InternalError(
                "WASM memory bounds check failed when writing request body".to_string(),
            ));
        }
        memory_view[start..end].copy_from_slice(request_body);
        ptr as i32
    };

    // Call extract_facts function
    let result_ptr = extract_facts
        .call(&mut store, (body_ptr, request_body.len() as i32))
        .map_err(|e| VacError::InternalError(format!("WASM adapter execution failed: {}", e)))?;

    // Read result from memory.
    // ABI (Phase 4.1): NUL-terminated UTF-8 JSON string pointer.
    let json =
        read_nul_terminated_utf8(&memory, &store, result_ptr as usize, MAX_ADAPTER_OUTPUT_BYTES)?;
    let parsed: Vec<AdapterFactWire> = serde_json::from_str(&json).map_err(|e| {
        VacError::InternalError(format!("WASM adapter returned invalid JSON facts: {}", e))
    })?;

    Ok(parsed
        .into_iter()
        .map(|w| AdapterFact {
            fact_name: w.fact,
            args: w.args,
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct AdapterFactWire {
    fact: String,
    args: Vec<String>,
}

fn read_nul_terminated_utf8(
    memory: &wasmtime::Memory,
    store: &Store<WasiP1Ctx>,
    start: usize,
    max_bytes: usize,
) -> Result<String, VacError> {
    let data = memory.data(store);
    if start >= data.len() {
        return Err(VacError::InternalError(
            "WASM adapter returned out-of-bounds pointer".to_string(),
        ));
    }

    let available = data.len() - start;
    let cap = available.min(max_bytes);
    let slice = &data[start..start + cap];

    let nul_pos = slice.iter().position(|b| *b == 0).ok_or_else(|| {
        VacError::InternalError(format!(
            "WASM adapter output not NUL-terminated within {} bytes",
            max_bytes
        ))
    })?;

    let bytes = &slice[..nul_pos];
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|e| VacError::InternalError(format!("WASM adapter output is not valid UTF-8: {}", e)))
}

/// Datalog fact extracted from WASM adapter
#[derive(Debug, Clone)]
pub struct AdapterFact {
    pub fact_name: String,
    pub args: Vec<String>,
}

/// Simplified adapter interface for Phase 4.1
/// 
/// For now, we'll use a placeholder that allows adapters to be loaded
/// but doesn't fully implement fact extraction yet.
/// Full implementation will require WASM memory management.
impl AdapterFact {
    /// Convert to Datalog Fact format
    pub fn to_biscuit_fact(&self) -> Result<biscuit_auth::builder::Fact, VacError> {
        use biscuit_auth::builder;
        
        let args: Vec<_> = self.args.iter()
            .map(|arg| {
                // Try to parse as integer, otherwise treat as string
                if let Ok(i) = arg.parse::<i64>() {
                    builder::int(i)
                } else {
                    builder::string(arg)
                }
            })
            .collect();
        
        Ok(biscuit_auth::builder::Fact::new(
            self.fact_name.clone(),
            args,
        ))
    }
}

/// Load adapter from local file path
pub fn load_adapter_from_file(
    registry: &AdapterRegistry,
    file_path: &str,
    expected_hash: &str,
) -> Result<(), VacError> {
    use std::fs;
    
    let wasm_bytes = fs::read(file_path)
        .map_err(|e| VacError::ConfigError(format!("Failed to read adapter file: {}", e)))?;
    
    registry.load_adapter(&wasm_bytes, expected_hash)
}

/// Load all `.wasm` files from a directory into the registry, keyed by their SHA-256 hash.
///
/// This enables policy pinning via `adapter_hash("<sha256>")` without separately configuring
/// a path per adapter.
pub fn load_adapters_from_dir(registry: &AdapterRegistry, dir_path: &str) -> Result<usize, VacError> {
    let mut loaded = 0usize;
    let entries = std::fs::read_dir(dir_path).map_err(|e| {
        VacError::ConfigError(format!("Failed to read adapters dir '{}': {}", dir_path, e))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            VacError::ConfigError(format!("Failed to read adapters dir entry: {}", e))
        })?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
            continue;
        }
        let wasm_bytes = std::fs::read(&path).map_err(|e| {
            VacError::ConfigError(format!("Failed to read adapter file '{}': {}", path.display(), e))
        })?;
        if wasm_bytes.len() > MAX_MODULE_SIZE {
            return Err(VacError::ConfigError(format!(
                "Adapter module too large: '{}' ({} bytes, max {})",
                path.display(),
                wasm_bytes.len(),
                MAX_MODULE_SIZE
            )));
        }
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(&wasm_bytes);
            hex::encode(hasher.finalize())
        };
        registry.load_adapter(&wasm_bytes, &hash)?;
        loaded += 1;
    }

    Ok(loaded)
}

/// Load adapter from URL (future: Phase 4.2)
/// 
/// For Phase 4.1, this is a placeholder. Full implementation will include:
/// - HTTP download
/// - Hash verification
/// - Caching
pub async fn load_adapter_from_url(
    registry: &AdapterRegistry,
    url: &str,
    expected_hash: &str,
) -> Result<(), VacError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| VacError::ConfigError(format!("Failed to download adapter: {}", e)))?;

    if !resp.status().is_success() {
        return Err(VacError::ConfigError(format!(
            "Failed to download adapter: HTTP {}",
            resp.status()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| VacError::ConfigError(format!("Failed to read adapter bytes: {}", e)))?;

    if bytes.len() > MAX_MODULE_SIZE {
        return Err(VacError::ConfigError(format!(
            "Adapter module too large: {} bytes (max {})",
            bytes.len(),
            MAX_MODULE_SIZE
        )));
    }

    registry.load_adapter(&bytes, expected_hash)
}
