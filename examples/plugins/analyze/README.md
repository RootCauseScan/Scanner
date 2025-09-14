# Analyze Plugins

Analyze plugins implement the `analyze` capability to perform custom analysis on files or findings.

## Example Plugin

### [Dependency Vulnerability Plugin](sca-osv-go/main.go)

A Go-based analyze plugin that checks dependency files against OSV.dev.

**Usage:**
```bash
rootcause scan ./my-project --rules ./rules --plugin ./examples/plugins/analyze/sca-osv-go
```

## Common Use Cases

- **Custom vulnerability detection**: Implement specialized security checks
- **Code quality analysis**: Perform custom code quality assessments
- **Dependency analysis**: Analyze dependencies for security issues
- **Performance analysis**: Identify performance bottlenecks
- **Compliance checking**: Verify compliance with specific standards

## Plugin Development

Your analyze plugin must implement:
- `plugin.init`: Initialize with workspace information
- `file.analyze`: Analyze a file for issues
- `plugin.shutdown`: Clean up resources

Analysis results should include:
- **`findings`**: Array of security issues found
- **`metadata`**: Optional analysis metadata

## Debugging

- Write diagnostic messages to `stderr`
- Test with various file types and scenarios
- Verify analysis accuracy and performance
