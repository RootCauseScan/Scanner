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

Show a compiled rule in text format:

```bash
cargo run -p debugger -- rule examples/rules/python/py.no-exec.yaml --format text
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
