#!/usr/bin/env python3
"""Simple rules plugin using JSON-RPC."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict
from urllib import request, error

import yaml


# Load all rule definitions once at startup.
RULES: Dict[str, Dict[str, Any]] = {}
rules_dir = os.path.join(os.path.dirname(__file__), "rules")
for name in os.listdir(rules_dir):
    if not name.endswith((".yaml", ".yml")):
        continue
    with open(os.path.join(rules_dir, name), "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
        for rule in data.get("rules", []):
            rid = rule.get("id")
            if rid:
                RULES[rid] = rule


def send(mid: Any, result: Any | None = None, error: Dict[str, Any] | None = None) -> None:
    """Send a JSON-RPC message to stdout."""

    msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": mid}
    if error is None:
        msg["result"] = result
    else:
        msg["error"] = error
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _write_yaml_rules(filename: str, rules: list[dict[str, Any]]) -> None:
    try:
        os.makedirs(rules_dir, exist_ok=True)
        path = os.path.join(rules_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump({"rules": rules}, fh, sort_keys=False)
        print(f"[dynamic-rules-demo] Wrote {len(rules)} rules to {path}", file=sys.stderr)
    except Exception as e:
        print(f"[dynamic-rules-demo] Failed to write rules file: {e}", file=sys.stderr)


def _fetch_json(url: str) -> Any | None:
    try:
        with request.urlopen(url, timeout=5) as resp:
            if resp.status != 200:
                print(f"[dynamic-rules-demo] HTTP {resp.status} fetching {url}", file=sys.stderr)
                return None
            data = resp.read().decode("utf-8", errors="replace")
            return json.loads(data)
    except error.URLError as e:
        print(f"[dynamic-rules-demo] URL error fetching {url}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[dynamic-rules-demo] Error fetching {url}: {e}", file=sys.stderr)
    return None


def _rules_from_payload(payload: Any) -> list[dict[str, Any]]:
    # Accepted shapes:
    # 1) {"rules": [{id,message,severity,pattern(s)}]}
    # 2) ["PATTERN_A", "PATTERN_B"] -> generate trivial LOW rules per pattern
    # 3) {"banned_tokens": ["eval(", "exec("]}
    rules: list[dict[str, Any]] = []
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        for r in payload["rules"]:
            if not isinstance(r, dict):
                continue
            rid = r.get("id")
            pats = r.get("patterns") or r.get("pattern")
            if rid and pats:
                pat_list = pats if isinstance(pats, list) else [{"pattern": str(pats)}]
                rules.append(
                    {
                        "id": rid,
                        "message": r.get("message", f"Dynamic rule {rid}"),
                        "severity": str(r.get("severity", "LOW")).upper(),
                        "patterns": [p if isinstance(p, dict) else {"pattern": str(p)} for p in pat_list],
                    }
                )
    elif isinstance(payload, list):
        for idx, item in enumerate(payload):
            s = str(item)
            if not s:
                continue
            rules.append(
                {
                    "id": f"dynamic.list.{idx}",
                    "message": f"Match dynamic token '{s}'",
                    "severity": "LOW",
                    "patterns": [{"pattern": s}],
                }
            )
    elif isinstance(payload, dict) and isinstance(payload.get("banned_tokens"), list):
        for idx, token in enumerate(payload["banned_tokens"]):
            s = str(token)
            rules.append(
                {
                    "id": f"dynamic.banned.{idx}",
                    "message": f"Banned token '{s}' detected",
                    "severity": "MEDIUM",
                    "patterns": [{"pattern": s}],
                }
            )
    return rules


for line in sys.stdin:
    try:
        req = json.loads(line)
    except Exception:
        continue

    mid = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "plugin.init":
        # Allow runtime injection of a rule via environment variables.
        dynamic_id = os.getenv("DYNAMIC_RULE_ID")
        dynamic_pattern = os.getenv("DYNAMIC_RULE_PATTERN")
        if dynamic_id and dynamic_pattern:
            RULES[dynamic_id] = {
                "id": dynamic_id,
                "message": os.getenv(
                    "DYNAMIC_RULE_MESSAGE",
                    f"Dynamic rule for pattern '{dynamic_pattern}'",
                ),
                "severity": os.getenv("DYNAMIC_RULE_SEVERITY", "LOW").upper(),
                "patterns": [{"pattern": dynamic_pattern}],
            }

        # Optional: fetch external rules from URL provided via options or env var
        # Priority: init.params.options.rules_url > env RULES_URL
        opts = params.get("options", {}) if isinstance(params, dict) else {}
        rules_url = None
        if isinstance(opts, dict):
            rules_url = opts.get("rules_url") or opts.get("url")
        rules_url = rules_url or os.getenv("RULES_URL")
        generated_count = 0
        if isinstance(rules_url, str) and rules_url:
            payload = _fetch_json(rules_url)
            if payload is not None:
                dyn_rules = _rules_from_payload(payload)
                if dyn_rules:
                    # Merge into in-memory RULES and persist to file for host-side loading
                    for r in dyn_rules:
                        rid = r.get("id")
                        if rid:
                            RULES[rid] = r
                            generated_count += 1
                    _write_yaml_rules("generated.from_url.yaml", dyn_rules)
            else:
                print("[dynamic-rules-demo] No payload fetched, skipping generation", file=sys.stderr)

        send(mid, {"ok": True, "capabilities": ["rules", "discover"], "plugin_version": "1.1.0"})
    elif method == "plugin.ping":
        send(mid, {})
    elif method == "rules.list":
        send(mid, {"ids": list(RULES.keys())})
    elif method == "rules.get":
        rid = params.get("id")
        rule = RULES.get(rid)
        if rule is None:
            send(mid, None, {"code": -32602, "message": f"Rule '{rid}' not found"})
        else:
            send(mid, {"rule": rule})
    elif method == "repo.discover":
        # No-op discover; report metrics about generated rules so far
        try:
            send(
                mid,
                {
                    "files": [],
                    "external": [],
                    "metrics": {
                        "plugin": "dynamic-rules-demo",
                        "rules_count": len(RULES),
                    },
                },
            )
        except Exception:
            send(mid, {"files": [], "external": [], "metrics": {}},)
    elif method == "plugin.shutdown":
        send(mid, {})
        break
    else:
        send(mid, None, {"code": -32601, "message": "Method not found"})

