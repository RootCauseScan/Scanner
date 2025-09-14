#!/usr/bin/env python3
"""polyglot-discover: multi-language workspace discover plugin.

Features:
- Scans a workspace for common language files (configurable via extensions)
- Optionally includes package manifests/lockfiles (npm/pip/cargo)
- Reports external dependencies (package names) when possible
- Emits basic metrics
"""
import json
import os
import sys
import time
from typing import Dict, Any, List

workspace_root = "."
capabilities = ["discover"]


def send(mid: str, result: Any = None, error: Dict[str, Any] | None = None) -> None:
    msg = {"jsonrpc": "2.0", "id": mid}
    if error is None:
        msg["result"] = result
    else:
        msg["error"] = error
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def log(level: str, message: str) -> None:
    call = {
        "jsonrpc": "2.0",
        "method": "plugin.log",
        "params": {"level": level, "message": message},
    }
    sys.stdout.write(json.dumps(call) + "\n")
    sys.stdout.flush()


def gather_external_deps(root: str, include_manifests: bool) -> List[Dict[str, Any]]:
    external = []
    # npm
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg):
        try:
            with open(pkg, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for name in data.get(section, {}).keys():
                    external.append({"path": f"npm:{name}", "language": "javascript"})
        except Exception:
            pass
    # pip
    req = os.path.join(root, "requirements.txt")
    if os.path.isfile(req):
        try:
            with open(req, "r", encoding="utf-8") as fh:
                for line in fh:
                    name = line.strip().split("==")[0]
                    if name:
                        external.append({"path": f"pip:{name}", "language": "python"})
        except Exception:
            pass
    # cargo
    lock = os.path.join(root, "Cargo.lock")
    if os.path.isfile(lock):
        try:
            with open(lock, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("name = "):
                        name = line.split("=", 1)[1].strip().strip('"')
                        external.append({"path": f"cargo:{name}", "language": "rust"})
        except Exception:
            pass

    if include_manifests:
        for p in (pkg, req, lock):
            if os.path.isfile(p):
                rel = os.path.relpath(p, root)
                external.append({"path": rel})
    return external


def discover_files(root: str, base: str, extensions: List[str], max_depth: int | None) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    # Normalize base: allow absolute or relative; compute rel paths against root
    start = base if os.path.isabs(base) else os.path.join(root, base)
    start = os.path.abspath(start)
    root_abs = os.path.abspath(root)
    start_depth = len(os.path.abspath(start).split(os.sep))
    for dirpath, _, filenames in os.walk(start):
        if max_depth is not None:
            depth = len(os.path.abspath(dirpath).split(os.sep)) - start_depth
            if depth > max_depth:
                continue
        for name in filenames:
            if not extensions or any(name.lower().endswith(ext.lower()) for ext in extensions):
                full = os.path.abspath(os.path.join(dirpath, name))
                # If file is inside workspace, return relative to workspace; otherwise absolute
                try:
                    common = os.path.commonpath([root_abs, full])
                except Exception:
                    common = None
                if common == root_abs:
                    rel = os.path.relpath(full, root_abs)
                else:
                    rel = full
                files.append({"path": rel})
    return files


def main() -> None:
    global workspace_root
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except Exception:
            continue
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})

        if method == "plugin.init":
            workspace_root = params.get("workspace_root", ".")
            send(mid, {"ok": True, "capabilities": capabilities, "plugin_version": "0.1.0"})
        elif method == "plugin.ping":
            send(mid, {"pong": True})
        elif method == "repo.discover":
            t0 = time.time()
            base = params.get("path", ".")
            extensions = params.get("extensions", [])
            max_depth = params.get("max_depth")
            include_manifests = params.get("include_manifests", True)

            files = discover_files(workspace_root, base, extensions, max_depth)
            external = gather_external_deps(workspace_root, include_manifests)
            elapsed = int((time.time() - t0) * 1000)
            send(
                mid,
                {
                    "files": files,
                    "external": external,
                    "metrics": {
                        "files_found": len(files),
                        "scan_time_ms": elapsed,
                    },
                },
            )
        elif method == "plugin.shutdown":
            send(mid, {"ok": True})
            break
        else:
            send(mid, None, {"code": 1002, "message": "unknown method"})


if __name__ == "__main__":
    main()


