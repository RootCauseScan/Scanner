# CLI

Command line interface usage examples:

```bash
# Show version
cargo run --bin rootcause -- --version

# Scan repository with configuration rules
cargo run --bin rootcause -- scan . --rules ./rules --format text

# Use only code rules (TypeScript)
cargo run --bin rootcause -- scan examples/fixtures/typescript/ts.no-eval/bad.ts --rules examples/rules/code --format text

# SARIF example
cargo run --bin rootcause -- scan . --rules ./rules --format sarif > report.sarif

# Generate metrics in stderr
cargo run --bin rootcause -- scan . --rules ./rules --metrics -

# Enable debug mode
cargo run --bin rootcause -- scan . --rules ./rules --format text --debug

# Quiet mode
cargo run --bin rootcause -- scan . --rules ./rules --format json --quiet > report.json
```

## Logs and modes

The CLI shows `info` messages like "Scan started" in English via `stderr`.

- `--debug` adds debugging logs.
- `--quiet` suppresses them, useful for integrations that consume JSON.Example `--quiet` + `--format json`

```bash
# Verbose
cargo run --bin rootcause -- scan examples/fixtures/python/py.no-eval/bad.py --rules examples/rules/python --debug

# Quiet JSON
cargo run --bin rootcause -- scan examples/fixtures/python/py.no-eval/bad.py --rules examples/rules/python --format json --quiet > report.json
```

The `tests/quiet.rs` file demonstrates both modes.

## Default exclusions

By default, `node_modules`, `.git` directories and files larger than 5 MiB are omitted.

- Disable these patterns: `--no-default-exclude`
- Adjust maximum size: `--max-file-size <bytes>` (use `0` to disable)

## Large repositories

The CLI releases transformed content after analysing each file to reduce memory usage.
For extensive codebases you can use:

- `--stream` to analyse file by file.
- `--chunk-size <N>` to process batches of `N` files when not using streaming (default 100).

## Rules

RootCause automatically loads YAML, JSON, Semgrep, and OPA-WASM rule files—no
`--semgrep-rules` flag is needed. Advanced Semgrep features are supported:

- `pattern-regex` for regex-based matches
- `metavariable-pattern` to constrain metavariables
- Taint tracking with `pattern-sources` and `pattern-sinks`

```yaml
# pattern-regex
- id: semgrep.pattern-regex
  message: Slack token
  pattern-regex: "xox[baprs]-[0-9a-zA-Z]{10,48}"
  severity: HIGH

# metavariable-pattern
- id: semgrep.metavariable-pattern
  message: possible double free
  pattern: |
    free($BUF)
  metavariable-pattern:
    metavariable: $BUF
    pattern: |
      getbuf(...)
  severity: HIGH

# taint tracking
- id: semgrep.taint
  message: user input flows to eval
  pattern-sources:
    - pattern: input(...)
  pattern-sinks:
    - pattern: eval($X)
  severity: HIGH
```

Install, update, list, or verify rule sets:

```bash
# Verify rules in a directory
cargo run --bin rootcause -- rules verify ./rules

# Install from archive or URL
cargo run --bin rootcause -- rules install https://example.com/pkg.tar.gz

# Update all installed rulesets
cargo run --bin rootcause -- rules update

# Update a specific ruleset
cargo run --bin rootcause -- rules update community

# List installed rulesets (name, origin, path)
cargo run --bin rootcause -- rules list
```

## Plugins

### List installed plugins

Shows each plugin with name, version, capabilities, and current parameters:

```bash
cargo run --bin rootcause -- plugins list
```

### Configure a plugin

Display or set configuration parameters:

```bash
# Show current parameters
cargo run --bin rootcause -- plugins config my-plugin

# Set a parameter
cargo run --bin rootcause -- plugins config my-plugin level=high
```

## Manage rulesets

```bash
# List installed rulesets
cargo run --bin rootcause -- rules list

# Remove an installed ruleset
cargo run --bin rootcause -- rules remove <name>
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
