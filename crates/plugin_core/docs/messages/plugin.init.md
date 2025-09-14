# Plugin Initialization

This message initializes the plugin with configuration, limits, and capabilities.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "init_001",
  "method": "plugin.init",
  "params": {
    "api_version": "1.0.0",
    "session_id": "session_abc123",
    "workspace_root": "/home/user/projects/myapp",
    "rules_root": "/home/user/projects/myapp/.rootcause/rules",
    "capabilities_requested": ["discover", "transform", "analyze", "report", "rules"],
    "options": {
      "scan_modes": ["aggressive"],
      "file_patterns": ["*.js", "*.py", "*.java"],
      "report_format": "pdf",
      "severity_threshold": "medium"
    },
    "limits": {
      "cpu_ms": 60000,
      "mem_mb": 512
    },
    "env": {
      "LANG": "en_US.UTF-8",
      "PATH": "/usr/bin:/bin"
    }
  }
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "init_001",
  "result": {
    "ok": true,
    "capabilities": ["discover", "transform", "analyze", "report", "rules"],
    "plugin_version": "2.1.0"
  }
}
```

