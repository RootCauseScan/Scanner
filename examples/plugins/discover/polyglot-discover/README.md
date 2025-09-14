# polyglot-discover (discover plugin)

A practical discover plugin that scans a workspace for multiple languages (Rust, Python, JS/TS, Docker, YAML/Terraform) and reports:

- files by extension/language
- external dependencies (npm, pip, cargo) when available
- basic metrics (files found, elapsed time)

## Capabilities
- discover

## Config Options (validated by config.schema.json)
- extensions: [".rs", ".py", ".js", ".ts", ".yaml", ".yml", ".tf", ".dockerfile"]
- max_depth: integer (optional)
- include_manifests: boolean to include package manifests and lockfiles

## Run
Handled by RootCause. The plugin communicates over JSON-RPC via stdin/stdout.


