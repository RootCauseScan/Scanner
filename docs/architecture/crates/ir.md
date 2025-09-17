---
id: ir
title: IR (Intermediate Representation)
description: Defines the intermediate representation used to describe files and nodes
sidebar_position: 4
---

# ir

## Responsibility
Defines the intermediate representation (IR) used by other crates to describe files and configuration nodes.

## Key functions and structures
- `IRNode`: individual node with type, path and value.
- `FileIR`: collection of nodes from a file.
- `Meta`: origin information (file, line and column).

## Usage example
```rust
use ir::{FileIR, IRNode, Meta};
let mut fir = FileIR::new("a.yaml".into(), "yaml".into());
fir.push(IRNode {
    kind: "yaml".into(),
    path: "a".into(),
    value: serde_json::json!(1),
    meta: Meta { file: "a.yaml".into(), line: 1, column: 1 },
});
assert_eq!(fir.nodes.len(), 1);
```
