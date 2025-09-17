---
id: rootcause
title: Rootcause CLI
description: Command line client to interact with the scanner
sidebar_position: 1
---

# Rootcause CLI

## Responsibility
Provides utilities for the command line interface, such as exclusions and glob pattern conversion.

## Key functions and structures
- `glob_to_regex`: converts a basic glob to `Regex`.
- `parse_exclude`: normalizes glob-style exclusions.
- `default_excludes`: patterns omitted by default.
- `is_excluded`: checks if a file should be ignored according to rules.

## Usage example
```rust
use rootcause::parse_exclude;
let re = parse_exclude("target/").unwrap();
assert!(re.is_match("target/debug/foo"));
```

## Advanced options

### --baseline &lt;file&gt;
Sets a reference file with accepted findings. Detections listed in it are omitted in subsequent runs.

```sh
cargo run --bin rootcause -- src --rules rules --baseline baseline.json
```

### --suppress-comment &lt;text&gt;
Ignores findings on lines containing the specified comment.

```sh
cargo run --bin rootcause -- src --rules rules --suppress-comment sast-ignore
```

### --fail-on &lt;low\|medium\|high&gt;
Defines the minimum severity that causes failure. If a finding with that severity or higher is detected, the process terminates with exit code `1`; otherwise returns `0`.

```sh
cargo run --bin rootcause -- src --rules rules --fail-on medium
```

### --metrics &lt;path\|-&gt;
Generates execution metrics in JSON format. Use `-` to send output to `stderr`.

```sh
cargo run --bin rootcause -- src --rules rules --metrics -
```

### Interactions
- `--baseline` and `--suppress-comment` filter findings before evaluating `--fail-on`.
- The final exit code is determined by `--fail-on`.
- `--metrics` only collects information and does not modify the analysis result.
