---
id: dashboard
title: Dashboard
description: Parsers to convert files from different languages to intermediate representation
sidebar_position: 1
---

# Dashboard

## Key functions and structures
- `detect_type`: determines the file type from its name or extension.
- `parse_file`: reads and transforms a file into `FileIR`.

## Maturity Guide

For detailed information about parser maturity levels (L1-L8), evaluation criteria and current status of each language, see the [Maturity Guide](./maturity.md).

## Supported languages

| Language | Level | Status |
| --- | --- | --- |
| Python | L5 | Intermediate |
| Rust | L2 | Syntactic |
| Dockerfile | L1 | Prototype |
| YAML | L1 | Prototype |
| HCL (Terraform) | L1 | Prototype |
| TypeScript | L1 | Prototype |
| JavaScript | L1 | Prototype |
| Go | L1 | Prototype |
| Java | L4 | Intermediate |
| PHP | L4 | Intermediate |
| Ruby | L1 | Prototype |

*For complete details on maturity levels and evaluation criteria, see the [Maturity Guide](./maturity.md).*

## Usage example
```rust
use parsers::parse_file;
use std::fs;
use std::path::Path;
let path = std::env::temp_dir().join("ex.yaml");
fs::write(&path, "a: 1").unwrap();
let ir = parse_file(Path::new(&path), None, None).unwrap().unwrap();
assert_eq!(ir.nodes[0].path, "a");
```

## Contributing new parsers

1. Create a module in `crates/parsers/src/languages/`.
2. Export it in `crates/parsers/src/languages/mod.rs` and update `detect_type` and `parse_file` in `crates/parsers/src/lib.rs`.
3. Add fixtures in `examples/fixtures/<language>` with `good` and `bad` cases.
4. Write tests in `crates/parsers/tests` using those fixtures.
