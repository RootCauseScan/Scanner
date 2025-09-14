//! Wrapper around Open Policy Agent policies compiled to WebAssembly.
//!
//! Policies must be compiled with `opa build -t wasm`.

use anyhow::Result;
use opa_wasm::wasmtime::ResourceLimiter;
use opa_wasm::{wasmtime, DefaultContext, Policy, Runtime};
use serde_json::Value;

/// Helper to execute Rego policies compiled to WASM.
pub struct RegoWasm {
    store: wasmtime::Store<StoreLimits>,
    policy: Policy<DefaultContext>,
    input: Value,
}

/// Simple limiter enforcing a maximum amount of memory for the guest.
struct StoreLimits {
    max_memory: usize,
}

impl StoreLimits {
    fn new(max_memory: usize) -> Self {
        Self { max_memory }
    }
}

impl ResourceLimiter for StoreLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.max_memory)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }
}

impl RegoWasm {
    /// Load a policy from WASM bytecode without resource limits.
    pub async fn from_bytes(bytes: &[u8], data: Option<&Value>) -> Result<Self> {
        Self::from_bytes_with_limits(bytes, data, None, None).await
    }

    /// Load a policy from WASM bytecode enforcing CPU and memory limits.
    pub async fn from_bytes_with_limits(
        bytes: &[u8],
        data: Option<&Value>,
        fuel: Option<u64>,
        memory: Option<usize>,
    ) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.async_support(true);
        if fuel.is_some() {
            config.consume_fuel(true);
        }
        let engine = wasmtime::Engine::new(&config)?;
        let module = wasmtime::Module::new(&engine, bytes)?;
        let mut store =
            wasmtime::Store::new(&engine, StoreLimits::new(memory.unwrap_or(usize::MAX)));
        store.limiter(|lim| lim);
        if let Some(f) = fuel {
            store.set_fuel(f)?;
        }
        let runtime = Runtime::new(&mut store, &module).await?;
        let policy = runtime
            .with_data(&mut store, data.unwrap_or(&Value::Null))
            .await?;
        Ok(Self {
            store,
            policy,
            input: Value::Null,
        })
    }

    /// List available entrypoints in the policy.
    pub fn entrypoints(&self) -> Vec<String> {
        self.policy
            .entrypoints()
            .into_iter()
            .map(String::from)
            .collect()
    }

    /// Set the JSON input for evaluation.
    pub fn set_input(&mut self, input: Value) {
        self.input = input;
    }

    /// Evaluate the given entrypoint and return the result as JSON.
    ///
    /// ```no_run
    /// # async fn run() -> anyhow::Result<()> {
    /// use rego_wasm::RegoWasm;
    /// let bytes = std::fs::read("policy.wasm")?;
    /// let mut policy = RegoWasm::from_bytes(&bytes, None).await?;
    /// policy.set_input(serde_json::json!({"x": 1}));
    /// let out = policy.evaluate("deny").await?;
    /// println!("{}", out);
    /// # Ok(()) }
    /// ```
    pub async fn evaluate(&mut self, entrypoint: &str) -> Result<Value> {
        let result = self
            .policy
            .evaluate(&mut self.store, entrypoint, &self.input)
            .await?;
        Ok(result)
    }
}
