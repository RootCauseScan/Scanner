# Plugin Health Check

Verify that the plugin is responsive and healthy.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "ping_008",
  "method": "plugin.ping",
  "params": {}
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "ping_008", 
  "result": {
    "pong": true,
    "uptime_ms": 45000,
    "memory_usage_mb": 89
  }
}
```


