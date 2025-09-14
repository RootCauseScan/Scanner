# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CLI interface with `scan`, `rules`, and `plugins` commands
- Language support:
  - Advanced support: Rust, Python
  - Medium support: PHP, Java 
  - Basic support: TypeScript, JavaScript, Go, Ruby
  - Configuration files: Dockerfile, Kubernetes YAML, Terraform HCL, JSON, YAML & Generic
- Rule engine with:
  - YAML/JSON rule definitions with regex patterns
  - Semgrep-compatible rule format
  - OPA WASM module execution
- Output formats: text, JSON, SARIF 2.1.0
- Plugin system with manifest-based discovery
- Rule set management (install, update, list, remove, verify, inspect)
- Parallel file processing
- Baseline comparison functionality
- Inline suppression comment support