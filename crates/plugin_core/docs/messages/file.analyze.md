# File Analysis

Perform security analysis on file content.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "analyze_004",
  "method": "file.analyze",
  "params": {
    "files": [
      {
        "path": "src/api/users.py",
        "sha256": "fedcba0987654321...",
        "language": "python",
        "content_b64": "aW1wb3J0IG9zCmRlZiBnZXRfdXNlcihpZCk6CiAgICBxdWVyeSA9IGYiU0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IHtpZH0iCiAgICByZXR1cm4gZGIuZXhlY3V0ZShxdWVyeSk=",
        "size": 512
      }
    ]
  }
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "analyze_004",
  "result": {
    "findings": [
      {
        "rule_id": "sql-injection-risk",
        "message": "Potential SQL injection vulnerability detected",
        "severity": "high",
        "file": "src/api/users.py",
        "line": 3,
        "column": 15,
        "evidence": "f\"SELECT * FROM users WHERE id = {id}\"",
        "confidence": 0.9,
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021"]
      }
    ],
    "metrics": {
      "rules_executed": 47,
      "files_analyzed": 1,
      "vulnerabilities_found": 1,
      "analysis_time_ms": 890
    }
  }
}
```



