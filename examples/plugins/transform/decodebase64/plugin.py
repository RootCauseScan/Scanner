#!/usr/bin/env python3
"""Decode base64 blocks in incoming files.

This plugin implements the transform capability for RootCause.
"""
import base64
import json
import re
import sys
import os
import signal


def send(msg_id, result=None, error=None):
    """Send a JSON-RPC message to stdout."""
    payload = {"jsonrpc": "2.0", "id": msg_id}
    if error is None:
        payload["result"] = result
    else:
        payload["error"] = error
    try:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        # Parent process ended; exit quietly
        sys.exit(0)


def handle_init(params):
    opts.update(params.get("options") or {})
    opts["workspace_root"] = params.get("workspace_root", "")
    return {"ok": True, "capabilities": ["transform"], "plugin_version": "1.0.0"}


def handle_transform(params):
    out, decoded = [], 0
    for f in params.get("files", []):
        path = f.get("path")
        if f.get("content_b64"):
            try:
                raw = base64.b64decode(f["content_b64"], validate=True)
            except Exception:
                out.append({"path": path, "actions": []})
                continue
        else:
            try:
                full = os.path.join(opts.get("workspace_root", ""), path)
                with open(full, "rb") as fh:
                    raw = fh.read()
            except Exception:
                out.append({"path": path, "actions": []})
                continue
        found = re.findall(rb"[A-Za-z0-9+/]{%d,}={0,2}" % int(opts["min_len"]), raw)
        if not found:
            out.append({"path": path, "actions": []})
            continue
        try:
            joined = b"".join(base64.b64decode(b) for b in found)
            out.append(
                {
                    "path": path,
                    "actions": ["decoded:base64"],
                    "content_b64": base64.b64encode(joined).decode(),
                    "notes": [f"blocks:{len(found)}"],
                }
            )
            decoded += 1
        except Exception:
            out.append({"path": path, "actions": []})
    return {"files": out, "metrics": {"decoded": decoded, "ms": 0}}


def signal_handler(signum, frame):
    """Signal handler to exit quietly."""
    sys.exit(0)

# Set up signal handlers
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

opts = {"mode": "safe", "min_len": 64}
try:
    for line in sys.stdin:
        msg = json.loads(line)
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})
        if method == "plugin.init":
            send(mid, handle_init(params))
        elif method == "file.transform":
            send(mid, handle_transform(params))
        elif method == "plugin.ping":
            send(mid, {"pong": True})
        elif method == "plugin.shutdown":
            send(mid, {"ok": True})
            break
        else:
            send(mid, None, {"code": 1002, "message": "unknown method", "data": {"method": method}})
except (BrokenPipeError, KeyboardInterrupt, OSError):
    # Parent process ended or was interrupted; exit quietly
    sys.exit(0)

