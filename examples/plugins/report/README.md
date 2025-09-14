# Report Plugins

Report plugins implement the `report` capability to generate custom reports from analysis results.

## Example Plugin

### [PDF Report Plugin](pdf_report/)

A Python-based report plugin that generates professional PDF reports from SAST findings.

**Usage:**
```bash
rootcause scan ./my-project --rules ./rules --plugin ./examples/plugins/report/pdf_report
```

## Common Use Cases

- **PDF reports**: Generate professional PDF security reports
- **HTML reports**: Create web-based interactive reports
- **JSON exports**: Export findings in custom JSON formats
- **CSV exports**: Generate spreadsheet-compatible reports
- **Dashboard integration**: Send data to monitoring dashboards

## Plugin Development

Your report plugin must implement:
- `plugin.init`: Initialize with workspace information
- `report.generate`: Generate report from findings
- `plugin.shutdown`: Clean up resources

Report generation should include:
- **`report_path`**: Path to generated report file
- **`format`**: Report format (PDF, HTML, JSON, etc.)
- **`metadata`**: Optional report metadata

## Debugging

- Write diagnostic messages to `stderr`
- Test with various finding types and volumes
- Verify report generation and formatting
