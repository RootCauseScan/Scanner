<div align="center">

  ## **RootCause** <br> 
  #### **Find the root**
  
  <img src="https://raw.githubusercontent.com/RootCauseScan/Brand/refs/heads/main/dist/logo_whitemode/icon-512x512.png" alt="RootCause.sh Logo" width="128" height="128">
  
  [![Visit RootCause.sh](https://img.shields.io/badge/Visit-rootcause.sh-FFD700?style=for-the-badge&logo=web&logoColor=000000)](https://rootcause.sh) <br>
  [![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
</div>

## What is RootCause?

RootCause is a static analysis security testing (SAST) tool built in Rust. It scans configuration files, source code, and infrastructure-as-code to identify security vulnerabilities and misconfigurations.

> **⚠️ Disclaimer**: This project is in its early stages and may contain bugs or incomplete features. Please report any issues you encounter.

## Supported Languages

- **Configuration**: Dockerfile, Kubernetes YAML, Terraform
- **Source Code**: Python, Rust, TypeScript, PHP, Java
- **Infrastructure**: HCL, JSON, YAML

## Quick Start

### Installation

```bash
curl -sSL https://rootcause.sh/install.sh | bash
```

### Basic Usage

The scanner requires a `rules` directory. If the directory is missing, the CLI
will prompt to download the official rule set.

```bash
# Scan a directory
rootcause scan ./my-project --rules ./rules

# Scan with specific output format
rootcause scan ./my-project --rules ./rules --format json

# Scan with severity threshold
rootcause scan ./my-project --rules ./rules --fail-on medium
```

### Manage Rulesets

Install or update built-in or custom rules:

```bash
# Install from archive or URL
rootcause rules install https://example.com/pkg.tar.gz

# Update all installed rulesets
rootcause rules update

# List installed rulesets
rootcause rules list
```

### Rule Formats and Advanced Features

RootCause loads rules written in YAML, JSON, Semgrep, or OPA-WASM without any
extra flags—Semgrep rules are detected automatically. The engine supports
advanced Semgrep capabilities:

- **pattern-regex** – match text via regular expressions
- **metavariable-pattern** – constrain metavariables
- **taint tracking** – follow data from sources to sinks

Minimal examples:

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
To get more info check: https://github.com/rootcausescan/Rules & https://docs.rootcause.sh/en/rules

### Plugins

`plugin list` shows each plugin with its version, capabilities, and current parameters.

```bash
# List installed plugins
rootcause plugin list

# Show or set plugin configuration
rootcause plugin config my-plugin
rootcause plugin config my-plugin level=high
```
To get more info check: https://github.com/rootcausescan/Plugins & https://docs.rootcause.sh/en/plugins

## Documentation

For comprehensive documentation, examples, and advanced usage:

**📚 [Visit docs.rootcause.sh](https://docs.rootcause.sh)**

The documentation includes:
- Detailed installation guides
- Rule creation tutorials
- Plugin development
- API reference

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
---

**Need help?** Visit [docs.rootcause.sh](https://docs.rootcause.sh) or join our community discussions.
