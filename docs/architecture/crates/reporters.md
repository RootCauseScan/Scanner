---
id: reporters
title: Reporters
description: Formats and displays findings in different formats (text, JSON, SARIF)
sidebar_position: 7
---

# reporters

## Responsibility
Formats and displays findings in different formats such as text, JSON and SARIF.

## Key functions and structures
- `Format`: enum with available outputs.
- `print_findings`: prints findings to stdout.

## Usage example
```rust
use reporters::{print_findings, Format};
print_findings(&[], Format::Text).unwrap();
```
