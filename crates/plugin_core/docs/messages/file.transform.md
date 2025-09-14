# File Transformation

Transform or decode file content before analysis.

## Input (SAST → Plugin)

```json
{
  "jsonrpc": "2.0",
  "id": "transform_003",
  "method": "file.transform",
  "params": {
    "files": [
      {
        "path": "src/encoded.js",
        "sha256": "1234567890abcdef...",
        "language": "javascript",
        "content_b64": "dmFyIGVuY29kZWQgPSAiSGVsbG8gV29ybGQi",
        "size": 256
      }
    ]
  }
}
```

## Output (Plugin → SAST)

```json
{
  "jsonrpc": "2.0",
  "id": "transform_003",
  "result": {
    "files": [
      {
        "path": "src/encoded.js",
        "actions": ["decoded:base64", "deobfuscated:javascript"],
        "content_b64": "dmFyIGRlY29kZWQgPSAiSGVsbG8gV29ybGQi",
        "notes": ["base64_blocks:3", "obfuscation_level:medium"]
      }
    ],
    "metrics": {
      "decoded": 1,
      "deobfuscated": 1,
      "ms": 320
    }
  }
}
```


