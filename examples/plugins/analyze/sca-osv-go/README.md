# SCA OSV Go Plugin

Dependency analysis plugin that queries known vulnerabilities from OSV.dev.

## Features

- **Multi-ecosystem support**: Analyzes dependency files from Python, Go, Node.js, Rust, PHP, Ruby and Java
- **Smart caching**: Avoids repeated OSV.dev queries for the same dependency
- **Exact detection**: Only processes files with specific names (not by extension)

## Supported Files

| File | Ecosystem | Parser |
|------|-----------|--------|
| `requirements.txt` | PyPI | Python pip |
| `go.mod` | Go | Go modules |
| `package.json` | npm | Node.js |
| `package-lock.json` | npm | npm lockfile |
| `Cargo.lock` | crates.io | Rust |
| `composer.lock` | Packagist | PHP Composer |
| `Gemfile.lock` | RubyGems | Ruby Bundler |
| `pom.xml` | Maven | Java Maven |

## Installation

```bash
cargo run -p rootcause -- plugin install ./examples/plugins/analyze/sca-osv-go/
```

## Usage

```bash
# Analyze a specific file
cargo run -p rootcause -- scan path/to/requirements.txt

# Analyze entire directory
cargo run -p rootcause -- scan ./my-project/
```

## Output

The plugin generates findings with:
- **Severity**: HIGH (CVE/GHSA), MEDIUM (PYSEC), INFO (others)
- **Rule ID**: `osv.{ecosystem}` (e.g: `osv.pypi`, `osv.npm`)
- **Message**: Name, version and vulnerability ID
- **Remediation**: Instructions to update

## Example

```
HIGH /path/to/package.json:1 osv.npm
    lodash 4.17.11 vulnerable: GHSA-jf85-cpcp-j695
    ↳  lodash: 4.17.11
    • Remediation: Update to a secure version (check OSV)
```
