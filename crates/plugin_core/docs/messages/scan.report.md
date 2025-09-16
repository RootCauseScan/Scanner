# Report Generation

Generate custom reports from analysis findings.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "report_005",
  "method": "scan.report", 
  "params": {
    "format": "pdf",
    "findings": [
      {
        "rule_id": "sql-injection-risk",
        "message": "Potential SQL injection vulnerability detected",
        "severity": "high",
        "file": "src/api/users.py",
        "line": 3,
        "evidence": "f\"SELECT * FROM users WHERE id = {id}\""
      }
    ],
    "metadata": {
      "scan_id": "scan_20240315_143021",
      "project_name": "MyApp",
      "scan_duration_ms": 12500,
      "files_scanned": 127
    }
  }
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "report_005",
  "result": {
    "output_files": [
      {
        "path": "reports/security_report_20240315.pdf",
        "type": "application/pdf",
        "size": 524288
      }
    ],
    "summary": {
      "critical": 0,
      "high": 1,
      "medium": 3,
      "low": 7,
      "total": 11
    },
    "generation_time_ms": 2340
  }
}
```



