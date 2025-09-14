# Error Handling

Standard error responses from plugins.

## Unknown Method Error

```json
{
  "jsonrpc": "2.0",
  "id": "invalid_001",
  "error": {
    "code": 1002,
    "message": "unknown method",
    "data": {
      "method": "invalid.method"
    }
  }
}
```

## Invalid Parameters Error

```json
{
  "jsonrpc": "2.0",
  "id": "param_error_002",
  "error": {
    "code": 1003,
    "message": "invalid parameters",
    "data": {
      "missing": ["files"],
      "received": ["path", "options"]
    }
  }
}
```


