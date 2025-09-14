# List Rules

Get available rules from the plugin.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "rules_006",
  "method": "rules.list",
  "params": {
    "language": "python",
    "category": "security"
  }
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "rules_006",
  "result": {
    "rules": [
      {
        "id": "py.sql-injection",
        "name": "SQL Injection Detection",
        "severity": "high",
        "language": ["python"],
        "category": "security"
      },
      {
        "id": "py.xss-prevention",
        "name": "XSS Prevention Check",
        "severity": "medium", 
        "language": ["python"],
        "category": "security"
      }
    ],
    "total": 2
  }
}
```


