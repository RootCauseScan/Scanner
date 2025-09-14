# Repository Guidelines

## Project Structure & Module Organization
- `crates/cli`: CLI entrypoint and flags (scan, format, fail-on, metrics).
- `crates/loader`: Loads YAML/JSON/Semgrep-like/OPA-WASM rules → `CompiledRule`.
- `crates/parsers`: Dockerfile/YAML/HCL/TypeScript/Python → `FileIR` (+ optional AST).
- `crates/engine`: Parallel rule evaluation, timeouts, baseline, suppression, WASM.
- `crates/reporters`: Output as text, JSON, or SARIF.
- `crates/ir`: IR types (IR-Doc, IR-AST).
- `examples/rules/`: Example rules (`config`, `code`, `opa`). `examples/fixtures/`: good/bad samples. `docs/`: design notes.

## Build, Test, and Development Commands
- Build workspace: `cargo build` (use `--release` for performance).
- Run all tests: `cargo test` (or `cargo test -p rootcause`).
- Scan locally: `cargo run -p rootcause -- . --rules rules --format text`.
- Emit SARIF: `cargo run -p rootcause -- . --rules rules --format sarif > report.sarif`.
- Enforce style: `cargo fmt --all`.

## Coding Style & Naming Conventions
- Rust 2021 edition; keep changes idiomatic and minimal.
- Formatting via `rustfmt` (see `rustfmt.toml`).
- Naming: modules/files `snake_case`, types/enums `UpperCamelCase`, functions/vars `snake_case`.
- Prefer small, focused functions; avoid unnecessary dependencies.

## Testing Guidelines
- Use Rust’s test harness; integration tests live in `crates/<name>/tests/*.rs`.
- Favor fixture-driven tests (see `examples/fixtures/`) with clear good/bad cases.
- Write descriptive test names asserting rule IDs and messages where applicable.
- Run specific crate tests during development: `cargo test -p engine`.

## Commit & Pull Request Guidelines
- Commits: clear, imperative subject (e.g., "Add ts.no-eval rule examples").
- PRs: include purpose, scope, sample commands (before/after), and linked issues.
- Requirements: `cargo build` and `cargo test` pass; update `README.md`/`docs` when behavior changes.
- Keep PRs small and focused; add or update fixtures when adding rules or parsers.

