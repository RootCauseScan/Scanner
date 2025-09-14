# PDF Report Plugin

This plugin generates professional PDF reports from SAST (Static Application Security Testing) findings.

## Features

- **Professional Layout**: Clean, modern PDF design with bone-white and graphite colour scheme
- **Executive Summary**: High-level overview with severity breakdown and metrics
- **Detailed Findings**: Comprehensive listing of all security issues with full context
- **Enhanced Information**: Includes file paths, line numbers, columns, code excerpts, and remediation steps
- **Smart Path Display**: Shows relative paths from workspace root for better readability
- **Severity Analysis**: Visual breakdown of findings by severity level with professional tables
- **Metadata**: Report generation timestamp and workspace information
- **Responsive Design**: Proper page breaks and formatting for readability
- **Improved Error Handling**: Comprehensive logging and error reporting

## Installation

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Make the plugin executable:
   ```bash
   chmod +x plugin.py
   ```

## Usage

The plugin implements the `report` capability and can be used with RootCause to generate PDF reports from SAST analysis results.

### Input Format

The plugin expects findings in the following JSON format:

```json
{
  "findings": [
    {
      "id": "unique-finding-id",
      "rule_id": "security.sql-injection",
      "severity": "high",
      "file": "/workspace/src/api/users.py",
      "line": 42,
      "column": 15,
      "excerpt": "SELECT * FROM users WHERE id = " + user_input",
      "message": "Potential SQL injection vulnerability",
      "remediation": "Use parameterised queries to prevent SQL injection"
    }
  ],
  "metrics": {
    "issues": 15,
    "files": 8,
    "ms": 1250
  }
}
```

### Output

The plugin generates:
- A PDF file saved to the workspace root with timestamp
- Base64-encoded PDF content for programmatic access
- Report metadata including file size and processing metrics

## Configuration

The plugin supports the following options in `plugin.toml`:

- `timeout_ms`: Maximum execution time (default: 30000ms)
- `mem_mb`: Memory limit (default: 256MB)
- `needs_content`: Set to false as the plugin works with findings data
- `reads_fs`: Set to true to write PDF files to filesystem

## Report Structure

1. **Title Page**: Report title, generation date, and workspace information
2. **Executive Summary**: Total findings count and severity distribution with professional tables
3. **Analysis Metrics**: Processing statistics and performance data
4. **Detailed Findings**: Individual security issues with:
   - Rule ID and severity level
   - File path (relative to workspace root)
   - Line and column numbers
   - Code excerpt showing the problematic code
   - Detailed message explaining the issue
   - Remediation steps (when available)
5. **Footer**: Report generation information

## Recent Improvements

- **Fixed Path Display**: Corrected field mapping from `path` to `file` to properly display file paths
- **Enhanced Information**: Added support for column numbers, code excerpts, and remediation steps
- **Smart Path Handling**: Automatically converts absolute paths to relative paths from workspace root
- **Brand Integration**: Updated to use official RootCause brand colors and logo
- **Professional Cover Page**: Added logo and improved title page design
- **Better Error Handling**: Added comprehensive logging and improved error reporting
- **Professional Tables**: Enhanced table styling with brand colors and better formatting

## Dependencies

- `reportlab`: Professional PDF generation library
- Standard Python libraries: `json`, `sys`, `os`, `base64`, `datetime`

## Example Output

The generated PDF includes:
- Professional header with RootCause branding
- Colour-coded severity indicators
- Tabular data presentation
- Code context highlighting
- Proper page breaks and formatting
- Executive summary with key metrics

## Error Handling

The plugin includes comprehensive error handling for:
- PDF generation failures
- File system access issues
- Invalid input data
- Memory and timeout constraints

## License

This plugin is part of the RootCause SAST toolkit and follows the same licensing terms.
