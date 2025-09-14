# Dynamic Rules Demo (rules plugin)

This example plugin exposes additional rules to the host and can also generate rules dynamically from a URL.

## Structure

```
examples/plugins/rules/dynamic-rules-demo/
├── plugin.toml
├── plugin.py
└── rules/
    └── rule.yaml
```

No compilation required. The host automatically loads rules from `rules/`.

## Execution

```bash
rootcause scan <target> --rules <rules-dir> --plugin $(pwd)
```

For debugging, write messages with `plugin.log` or to `stderr`; avoid using `stdout`.

## Dynamic rule via environment variables

Set environment variables before running the plugin to inject a rule at runtime:

```bash
export DYNAMIC_RULE_ID=sample.dynamic
export DYNAMIC_RULE_PATTERN="TODO"
# Optional overrides
# export DYNAMIC_RULE_MESSAGE="Custom message"
# export DYNAMIC_RULE_SEVERITY="MEDIUM"

rootcause scan <target> --rules <rules-dir> --plugin $(pwd)
```

When set, the plugin creates a rule with the given pattern and exposes it via `rules.list`/`rules.get`.

## Dynamic rules from a URL

The plugin can fetch JSON from a URL and generate rules automatically:

Accepted JSON response shapes:

- `{ "rules": [ { "id": "x", "message": "...", "severity": "LOW|MEDIUM|HIGH", "patterns": [{"pattern": "..."}] } ] }`
- `["TODO", "FIXME"]` → generates LOW rules per token
- `{ "banned_tokens": ["eval(", "exec("] }` → generates MEDIUM rules per token

Usage (plugin option or environment variable):

```bash
# via environment variable (simplest)
export RULES_URL="https://raw.githubusercontent.com/rootcausescan/datasets/main/dynamic_rules.json"
rootcause scan <target> --rules <rules-dir> --plugin $(pwd)

# or pass options by plugin name (manifest name is "extra-rules")
rootcause scan <target> --rules <rules-dir> \
  --plugin $(pwd) \
  --plugin-opt extra-rules.rules_url=https://example.com/my-rules.json
```

The plugin writes generated rules to `rules/generated.from_url.yaml` so the host loads them automatically, in addition to exposing them via RPC.

### Requirements

- Python 3.8+
- PyYAML installed: `pip install pyyaml`
