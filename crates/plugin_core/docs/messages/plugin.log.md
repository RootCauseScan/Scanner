# Plugin Logging

Send log messages from plugin to host.

## Output (Plugin → SAST) - Info Log

```json
{
  "jsonrpc": "2.0",
  "method": "plugin.log",
  "params": {
    "level": "info",
    "message": "Starting security analysis in aggressive mode"
  }
}
```

## Output (Plugin → SAST) - Error Log

```json
{
  "jsonrpc": "2.0",
  "method": "plugin.log",
  "params": {
    "level": "error", 
    "message": "Failed to process file: Permission denied"
  }
}
```


