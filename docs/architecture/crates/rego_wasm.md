---
id: rego_wasm
title: Rego WASM
description: Executes Open Policy Agent policies compiled to WebAssembly
sidebar_position: 6
---

# rego_wasm

## Responsibility
Executes Open Policy Agent policies compiled to WebAssembly, applying optional resource limits.

## Key functions and structures
- `RegoWasm`: container for the policy and execution state.
- `from_bytes` / `from_bytes_with_limits`: load a WASM module.
- `evaluate`: evaluates an entrypoint with the established input.

## Usage example
```rust,no_run
use rego_wasm::RegoWasm;
let bytes = std::fs::read("policy.wasm").unwrap();
let mut policy = futures::executor::block_on(RegoWasm::from_bytes(&bytes, None)).unwrap();
policy.set_input(serde_json::json!({"x": 1}));
let out = futures::executor::block_on(policy.evaluate("deny")).unwrap();
println!("{}", out);
```
