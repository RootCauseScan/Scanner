# Rules Plugins

Rules plugins implement the `rules` capability to provide additional security rules to RootCause.

## Example Plugin

### [Dynamic Rules Demo Plugin](dynamic-rules-demo/)

A Python-based rules plugin that exposes additional security rules to the host.

**Usage:**
```bash
rootcause scan ./my-project --rules ./rules --plugin ./examples/plugins/rules/dynamic-rules-demo
```

## Common Use Cases

- **Custom security rules**: Add domain-specific security checks
- **Dynamic rule generation**: Generate rules based on configuration
- **Rule updates**: Provide rules that can be updated dynamically
- **Specialized checks**: Implement checks for specific frameworks or libraries
- **Compliance rules**: Add rules for specific compliance standards

## Plugin Development

Your rules plugin must implement:
- `plugin.init`: Initialize with workspace information
- `rules.list`: List available rules
- `rules.get`: Get specific rule details
- `plugin.shutdown`: Clean up resources

Rules should be provided in RootCause's rule format:
- **YAML/JSON rule definitions**
- **Proper rule metadata**
- **Severity levels and categories**

## Debugging

- Write diagnostic messages to `stderr`
- Test rule loading and execution
- Verify rule syntax and metadata
