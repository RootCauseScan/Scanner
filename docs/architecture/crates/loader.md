---
id: loader
title: Loader
description: Loads and transforms rules from YAML, JSON and other format files
sidebar_position: 5
---

# loader

## Responsibility
Loads rules from YAML, JSON or compatible format files and transforms them into a unified structure.

## Key functions and structures
- `load_rules`: reads a directory and returns a `RuleSet` ready to execute.
- `RuleSet`: collection of compiled rules.
- `MatcherKind`: enum with different types of matching (regex, JSONPath, AST, Rego WASM, etc.).

## Usage example
```rust
use loader::load_rules;
use std::path::Path;
let rules = load_rules(Path::new("rules")).unwrap();
assert!(!rules.rules.is_empty());
```
