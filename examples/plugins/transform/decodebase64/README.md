# decodebase64 Python plugin

This example plugin decodes embedded Base64 blocks from incoming files.

## Build

No build step is required; ensure Python 3 is available.

## Run

```bash
rootcause <target> --rules <rules-dir> --plugin $(pwd)
```

You can provide options such as `--plugin-opt decodebase64.mode=aggressive`.

For debugging, send structured messages via `plugin.log` or write to `stderr`; `stdout` is reserved for JSON-RPC.
