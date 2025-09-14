# Discover Plugins

Discover plugins implement the `discover` capability to find and identify files or resources in your workspace.

## Example Plugin

### [Python Discover Plugin](polyglot-discover/)

A Python-based discover plugin that recursively finds source files with extensions like `.rs`, `.py`, `.js`, `.ts`, and more within the workspace.

**Usage:**
```bash
rootcause scan ./my-project --rules ./rules --plugin ./examples/plugins/discover/polyglot-discover
```

## Common Use Cases

- **Language-specific discovery**: Find files for languages not natively supported
- **Configuration discovery**: Locate config files in non-standard locations
- **Asset discovery**: Find images, documentation, or other resources
- **Custom filtering**: Implement complex file selection logic

## Plugin Development

Your discover plugin must implement:
- `plugin.init`: Initialize with workspace information
- `repo.discover`: Discover files in the specified path
- `plugin.shutdown`: Clean up resources

Discovered files should include:
- **`path`**: Relative path from workspace root
- **`size`**: File size in bytes (optional)
- **`modified`**: Last modification timestamp (optional)

## Debugging

- Write diagnostic messages to `stderr`
- Test with various directory structures
- Verify path handling for different operating systems
