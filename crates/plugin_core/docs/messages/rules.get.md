# Get Specific Rule

Retrieve the full definition of a specific rule.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "rules_007",
  "method": "rules.get",
  "params": {
    "rule_id": "py.sql-injection"
  }
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "rules_007",
  "result": {
    "rule": {
      "id": "py.sql-injection",
      "name": "SQL Injection Detection",
      "description": "Detects potential SQL injection vulnerabilities in Python code",
      "severity": "high",
      "languages": ["python"],
      "pattern": "patterns:\n  - pattern: f\"SELECT * FROM {$TABLE} WHERE {$CONDITION}\"\n  - pattern: f\"INSERT INTO {$TABLE} VALUES ({$VALUES})\"\nmetavar-regex:\n  $TABLE: \"[a-zA-Z_][a-zA-Z0-9_]*\"\nmessage: \"Potential SQL injection vulnerability\"\nowasp: [\"A03:2021\"]\ncwe: [\"CWE-89\"]"
    }
  }
}
```


