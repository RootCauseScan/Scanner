# File Discovery

Discover files and external dependencies in the workspace.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "discover_002",
  "method": "repo.discover",
  "params": {
    "path": "src",
    "extensions": [".js", ".ts", ".py", ".java"],
    "max_depth": 10
  }
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "discover_002",
  "result": {
    "files": [
      {
        "path": "src/main.js",
        "language": "javascript",
        "sha256": "a1b2c3d4e5f6789...",
        "size": 1024
      },
      {
        "path": "src/auth/login.py",
        "language": "python", 
        "sha256": "f6e5d4c3b2a1987...",
        "size": 2048
      }
    ],
    "external": [
      {
        "path": "node_modules/express",
        "language": "javascript"
      }
    ],
    "metrics": {
      "files_found": 127,
      "directories_scanned": 23,
      "scan_time_ms": 1250
    }
  }
}
```


## Parameters and Result Schema

- Input params
  - `path` (string): Base directory to scan. Intended to be relative to `workspace_root` provided in `plugin.init`. Hosts may send an absolute path; plugins SHOULD handle both.
  - `extensions` (string[]): Optional list of file extensions to include (e.g., [".js", ".py"]). Empty means plugin-defined defaults.
  - `max_depth` (integer, optional): Optional maximum directory depth from `path`.

- Result schema
  - `files` (FileSpec[]): Files found within the workspace boundary. At minimum, `path` must be set. `language`, `sha256`, `size` are optional.
  - `external` (FileSpec[]): External dependencies or out-of-tree artifacts. At minimum, `path` must be set; other fields are optional.
  - `metrics` (object): Optional, free-form metrics published by the plugin (e.g., `files_found`, `directories_scanned`, `scan_time_ms`).

Notes:
- The host deduplicates files returned by `repo.discover` against its own file collection.
- `repo.discover` is invoked before parsing/analysis, so discovered files can be included in the analysis pipeline.

