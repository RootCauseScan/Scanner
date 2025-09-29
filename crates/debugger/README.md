# debugger

Lightweight tool for inspecting the intermediate representation and compiled rules.

## Examples

Get the AST of a file in DOT format:

```bash
cargo run -p debugger -- ir examples/fixtures/python/py.no-eval/bad.py --kind ast --format dot
```

Get the CFG in JSON format:

```bash
cargo run -p debugger -- ir examples/fixtures/python/py.no-eval/bad.py --kind cfg --format json
```

Inspect the call graph derived from the IR:

```bash
cargo run -p debugger -- ir examples/fixtures/python/py.no-eval/bad.py --kind callgraph --format text
```

Show a compiled rule in text format:

```bash
cargo run -p debugger -- rule examples/rules/python/py.no-exec.yaml --format text
```

Visualise a compiled rule as a graph:

```bash
cargo run -p debugger -- rule examples/rules/python/py.no-exec.yaml --format dot
cargo run -p debugger -- rule examples/rules/python/py.no-exec.yaml --format mermaid
```

### Timeline Output

```bash
# Inspect which stages the engine runs through
cargo run -p debugger -- ir examples/fixtures/python/py.no-eval/bad.py --timeline text

# Generate a Mermaid diagram of the execution timeline
cargo run -p debugger -- rule examples/rules/python/py.no-exec.yaml --timeline mermaid
```

### Simplified Output

```bash
# Clean AST for presentations
cargo run -p debugger -- ir examples/fixtures/python/py.no-eval/bad.py --kind ast --format tree --simplified

# Colored DOT graphs
cargo run -p debugger -- ir examples/fixtures/python/py.no-eval/bad.py --kind ast --format dot --simplified
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
