# Plugin Shutdown

Gracefully shutdown the plugin.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "shutdown_009",
  "method": "plugin.shutdown",
  "params": {}
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "shutdown_009",
  "result": {
    "ok": true,
    "cleanup_completed": true
  }
}
```



