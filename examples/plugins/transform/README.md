# Transform Plugins

Transform plugins implement the `transform` capability to modify or process files before analysis.

## Example Plugin

### [Base64 Decode Plugin](decodebase64/)

A Python-based transform plugin that decodes embedded Base64 blocks from incoming files.

**Usage:**
```bash
rootcause scan ./my-project --rules ./rules --plugin ./examples/plugins/transform/decodebase64

# With configuration options
rootcause scan ./my-project --rules ./rules --plugin ./examples/plugins/transform/decodebase64 --plugin-opt decodebase64.mode=aggressive
```

## Common Use Cases

- **Encoding Decoding**: Base64, URL encoding, hex encoding
- **Compression**: Decompress gzip, zip, or other compressed content
- **Format Conversion**: Convert between different file formats
- **Content Extraction**: Extract embedded content from files
- **Normalization**: Standardize file formats for analysis
- **Sanitization**: Remove or mask sensitive information

## Plugin Development

Your transform plugin must implement:
- `plugin.init`: Initialize with workspace information and configuration
- `file.transform`: Transform a file's content
- `plugin.shutdown`: Clean up resources

Transform responses should include:
- **`content`**: Transformed file content
- **`transformed`**: Boolean indicating if transformation occurred
- **`metadata`**: Optional transformation metadata

## Debugging

- Write diagnostic messages to `stderr`
- Log transformation statistics and metadata
- Test with various file types and sizes
- Verify content integrity after transformation
