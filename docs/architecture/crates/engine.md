---
id: engine
title: Engine
description: Analysis engine that evaluates rules on the intermediate representation
sidebar_position: 2
---

# engine

## Responsibility
Evaluates rules on the intermediate representation of files, handling parallel execution, caching and optional WASM support.

## Key functions and structures
- `analyze_files_cached`: analyzes files applying hash-based caching.
- `build_cfg`: builds control flow graphs for flow analysis.
- `Finding`: individual result with severity, location and message.

## Usage example
```rust
use engine::{analyze_files_cached, EngineConfig};
use loader::load_rules;
use parsers::parse_file;
use std::path::Path;

let rules = load_rules(Path::new("rules")).unwrap();
let file = parse_file(Path::new("a.yaml"), None, None).unwrap().unwrap();
let findings = analyze_files_cached(&[file], &rules, Path::new("cache.json"), &EngineConfig::default(), None);
assert!(findings.is_empty());
```
