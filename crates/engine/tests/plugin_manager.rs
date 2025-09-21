use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose, Engine as _};
use engine::plugin::PluginManager;
use plugin_core::FileSpec;
use serde_json::Value;
use tempfile::TempDir;

const ANALYZE_PY: &str = r#"#!/usr/bin/env python3
import sys, json, base64

def send(i, r=None, e=None):
    msg={"jsonrpc":"2.0","id":i}
    if e is None:
        msg["result"] = r
    else:
        msg["error"] = e
    print(json.dumps(msg))
    sys.stdout.flush()

for line in sys.stdin:
    req=json.loads(line)
    mid=req.get("id")
    method=req.get("method")
    params=req.get("params",{})
    if method=="plugin.init":
        send(mid,{"ok":True,"capabilities":["analyze"],"plugin_version":"1.0.0"})
    elif method=="file.analyze":
        files=params.get("files",[])
        findings=[]
        for f in files:
            content=base64.b64decode(f.get("content_b64",""))
            findings.append({"message":content.decode(),"file":f.get("path")})
        send(mid,{"findings":findings})
    elif method=="plugin.ping":
        send(mid,{"pong":True})
    elif method=="plugin.shutdown":
        send(mid,{"ok":True})
        break
    else:
        send(mid,None,{"code":1002,"message":"unknown method","data":{"method":method}})
"#;

const REPORT_PY: &str = r#"#!/usr/bin/env python3
import sys, json

def send(i, r=None, e=None):
    msg={"jsonrpc":"2.0","id":i}
    if e is None:
        msg["result"] = r
    else:
        msg["error"] = e
    print(json.dumps(msg))
    sys.stdout.flush()

for line in sys.stdin:
    req=json.loads(line)
    mid=req.get("id")
    method=req.get("method")
    if method=="plugin.init":
        send(mid,{"ok":True,"capabilities":["report"],"plugin_version":"1.0.0"})
    elif method=="plugin.ping":
        send(mid,{"pong":True})
    elif method=="plugin.shutdown":
        send(mid,{"ok":True})
        break
    else:
        send(mid,None,{"code":1002,"message":"unknown method","data":{"method":method}})
"#;

const BAD_INIT_PY: &str = r#"#!/usr/bin/env python3
import sys, json

def send(i, r=None, e=None):
    msg={"jsonrpc":"2.0","id":i}
    if e is None:
        msg["result"] = r
    else:
        msg["error"] = e
    print(json.dumps(msg))
    sys.stdout.flush()

for line in sys.stdin:
    req=json.loads(line)
    mid=req.get("id")
    method=req.get("method")
    if method=="plugin.init":
        send(mid,{"ok":False,"capabilities":[],"plugin_version":"1.0.0"})
    elif method=="plugin.shutdown":
        send(mid,{"ok":True})
        break
    else:
        send(mid,None,{"code":1002,"message":"unknown method","data":{"method":method}})
"#;

const MISSING_CAP_PY: &str = r#"#!/usr/bin/env python3
import sys, json

def send(i, r=None, e=None):
    msg={"jsonrpc":"2.0","id":i}
    if e is None:
        msg["result"] = r
    else:
        msg["error"] = e
    print(json.dumps(msg))
    sys.stdout.flush()

for line in sys.stdin:
    req=json.loads(line)
    mid=req.get("id")
    method=req.get("method")
    if method=="plugin.init":
        send(mid,{"ok":True,"capabilities":[],"plugin_version":"1.0.0"})
    elif method=="plugin.ping":
        send(mid,{"pong":True})
    elif method=="plugin.shutdown":
        send(mid,{"ok":True})
        break
    else:
        send(mid,None,{"code":1002,"message":"unknown method","data":{"method":method}})
"#;

const NO_PING_PY: &str = r#"#!/usr/bin/env python3
import sys, json

def send(i, r=None, e=None):
    msg={"jsonrpc":"2.0","id":i}
    if e is None:
        msg["result"] = r
    else:
        msg["error"] = e
    print(json.dumps(msg))
    sys.stdout.flush()

for line in sys.stdin:
    req=json.loads(line)
    mid=req.get("id")
    method=req.get("method")
    if method=="plugin.init":
        send(mid,{"ok":True,"capabilities":["transform"],"plugin_version":"1.0.0"})
    elif method=="plugin.ping":
        # Don't respond to ping - this should cause the plugin to fail
        # Just continue to the next iteration without sending anything
        continue
    elif method=="plugin.shutdown":
        send(mid,{"ok":True})
        break
    else:
        send(mid,None,{"code":1002,"message":"unknown method","data":{"method":method}})
"#;

const ISOLATION_PY: &str = r#"#!/usr/bin/env python3
import sys, json

def send(i, r=None, e=None):
    msg={"jsonrpc":"2.0","id":i}
    if e is None:
        msg["result"] = r
    else:
        msg["error"] = e
    print(json.dumps(msg))
    sys.stdout.flush()

for line in sys.stdin:
    req=json.loads(line)
    mid=req.get("id")
    method=req.get("method")
    params=req.get("params",{})
    if method=="plugin.init":
        send(mid,{"ok":True,"capabilities":["analyze"],"plugin_version":"1.0.0"})
    elif method=="file.analyze":
        f=params.get("files",[{"path":""}])[0]
        p=f.get("path")
        try:
            open(p).read()
            msg="read"
        except Exception:
            msg="missing"
        send(mid,{"findings":[{"message":msg,"file":p}]})
    elif method=="plugin.ping":
        send(mid,{"pong":True})
    elif method=="plugin.shutdown":
        send(mid,{"ok":True})
        break
    else:
        send(mid,None,{"code":1002,"message":"unknown method","data":{"method":method}})
"#;

#[test]
fn plugin_content_and_path_handling() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

    // Setup transform plugin (reads_fs=true, needs_content=false)
    let py_src = root.join("examples/plugins/transform/decodebase64");
    let fs_tmp = TempDir::new().unwrap();
    fs::copy(py_src.join("plugin.py"), fs_tmp.path().join("plugin.py")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(fs_tmp.path().join("plugin.py"))
            .unwrap()
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(fs_tmp.path().join("plugin.py"), perm).unwrap();
    }
    fs::write(
        fs_tmp.path().join("plugin.toml"),
        r#"name = "decodebase64"
version = "1.0.0"
api_version = "1.x"
entry = "python3 plugin.py"
capabilities = ["transform"]
needs_content = false
reads_fs = true
timeout_ms = 5000
"#,
    )
    .unwrap();

    // Setup analyzer plugin requiring content
    let analyze_tmp = TempDir::new().unwrap();
    fs::write(analyze_tmp.path().join("plugin.py"), ANALYZE_PY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(analyze_tmp.path().join("plugin.py"))
            .unwrap()
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(analyze_tmp.path().join("plugin.py"), perm).unwrap();
    }
    fs::write(
        analyze_tmp.path().join("plugin.toml"),
        r#"name = "echo"
version = "1.0.0"
api_version = "1.x"
entry = "python3 plugin.py"
capabilities = ["analyze"]
needs_content = true
reads_fs = false
timeout_ms = 5000
"#,
    )
    .unwrap();

    // Setup reporter plugin
    let report_tmp = TempDir::new().unwrap();
    fs::write(report_tmp.path().join("plugin.py"), REPORT_PY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(report_tmp.path().join("plugin.py"))
            .unwrap()
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(report_tmp.path().join("plugin.py"), perm).unwrap();
    }
    fs::write(
        report_tmp.path().join("plugin.toml"),
        r#"name = "reporter"
version = "1.0.0"
api_version = "1.x"
entry = "python3 plugin.py"
capabilities = ["report"]
needs_content = false
reads_fs = false
timeout_ms = 5000
"#,
    )
    .unwrap();

    let pm = PluginManager::load(
        &[
            fs_tmp.path().to_path_buf(),
            analyze_tmp.path().to_path_buf(),
            report_tmp.path().to_path_buf(),
        ],
        &HashMap::new(),
        &root,
        &root,
    )
    .unwrap();

    assert_eq!(pm.transformers().len(), 1);
    assert_eq!(pm.analyzers().len(), 1);
    assert_eq!(pm.reporters().len(), 1);
    assert!(!pm.transformers()[0].needs_content());
    assert!(pm.analyzers()[0].needs_content());

    // Transform plugin should read from filesystem
    const INNER_B64: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
    let file_path = root.join("sample.txt");
    fs::write(&file_path, INNER_B64).unwrap();
    let file = FileSpec {
        path: file_path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let out: Value = pm.transformers()[0].transform(vec![file]).unwrap();
    assert_eq!(out["files"][0]["content_b64"], INNER_B64);

    // Analyzer plugin should receive content
    let file_path2 = root.join("content.txt");
    fs::write(&file_path2, b"hello").unwrap();
    let mut spec2 = FileSpec {
        path: file_path2.to_string_lossy().into_owned(),
        ..Default::default()
    };
    if pm.analyzers()[0].needs_content() {
        let bytes = fs::read(&file_path2).unwrap();
        spec2.content_b64 = Some(general_purpose::STANDARD.encode(bytes));
    }
    let res: Value = pm.analyzers()[0].analyze(vec![spec2]).unwrap();
    assert_eq!(res["findings"][0]["message"], "hello");
    let virtual_path = res["findings"][0]["file"].as_str().unwrap();
    assert!(virtual_path.starts_with("/virtual/content.txt-"));

    // Analyzer plugin should produce unique and stable virtual paths
    let duplicate_tmp = TempDir::new().unwrap();
    let left_dir = duplicate_tmp.path().join("left");
    let right_dir = duplicate_tmp.path().join("right");
    fs::create_dir_all(&left_dir).unwrap();
    fs::create_dir_all(&right_dir).unwrap();

    let dup_a_path = left_dir.join("duplicate.txt");
    let dup_b_path = right_dir.join("duplicate.txt");
    fs::write(&dup_a_path, b"alpha").unwrap();
    fs::write(&dup_b_path, b"bravo").unwrap();

    let mut dup_a = FileSpec {
        path: dup_a_path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let mut dup_b = FileSpec {
        path: dup_b_path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    dup_a.content_b64 = Some(general_purpose::STANDARD.encode(fs::read(&dup_a_path).unwrap()));
    dup_b.content_b64 = Some(general_purpose::STANDARD.encode(fs::read(&dup_b_path).unwrap()));

    let first: Value = pm.analyzers()[0]
        .analyze(vec![dup_a.clone(), dup_b.clone()])
        .unwrap();
    let first_a = first["findings"][0]["file"].as_str().unwrap().to_owned();
    let first_b = first["findings"][1]["file"].as_str().unwrap().to_owned();
    assert!(first_a.starts_with("/virtual/duplicate.txt-"));
    assert!(first_b.starts_with("/virtual/duplicate.txt-"));
    assert_ne!(first_a, first_b);

    let second: Value = pm.analyzers()[0].analyze(vec![dup_a, dup_b]).unwrap();
    assert_eq!(second["findings"][0]["file"].as_str().unwrap(), first_a);
    assert_eq!(second["findings"][1]["file"].as_str().unwrap(), first_b);

    let _ = fs::remove_file(file_path);
    let _ = fs::remove_file(file_path2);
}

#[test]
fn plugin_init_not_ok_fails() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("plugin.py"), BAD_INIT_PY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(tmp.path().join("plugin.py"))
            .unwrap()
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(tmp.path().join("plugin.py"), perm).unwrap();
    }
    fs::write(
        tmp.path().join("plugin.toml"),
        r#"name = "bad_init"
version = "1.0.0"
api_version = "1.x"
entry = "python3 plugin.py"
capabilities = ["transform"]
needs_content = false
reads_fs = false
timeout_ms = 5000
"#,
    )
    .unwrap();

    let res = PluginManager::load(&[tmp.path().to_path_buf()], &HashMap::new(), &root, &root);
    assert!(res.is_err());
}

#[test]
fn plugin_missing_capability_fails() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("plugin.py"), MISSING_CAP_PY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(tmp.path().join("plugin.py"))
            .unwrap()
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(tmp.path().join("plugin.py"), perm).unwrap();
    }
    fs::write(
        tmp.path().join("plugin.toml"),
        r#"name = "no_cap"
version = "1.0.0"
api_version = "1.x"
entry = "python3 plugin.py"
capabilities = ["transform"]
needs_content = false
reads_fs = false
timeout_ms = 5000
"#,
    )
    .unwrap();

    let res = PluginManager::load(&[tmp.path().to_path_buf()], &HashMap::new(), &root, &root);
    assert!(res.is_err());
}

#[test]
#[ignore] // TODO: Fix timeout issue with ping test
fn plugin_missing_ping_fails() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("plugin.py"), NO_PING_PY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(tmp.path().join("plugin.py"))
            .unwrap()
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(tmp.path().join("plugin.py"), perm).unwrap();
    }
    fs::write(
        tmp.path().join("plugin.toml"),
        r#"name = "no_ping"
version = "1.0.0"
api_version = "1.x"
entry = "python3 plugin.py"
capabilities = ["transform"]
needs_content = false
reads_fs = false
timeout_ms = 1000
"#,
    )
    .unwrap();

    let res = PluginManager::load(&[tmp.path().to_path_buf()], &HashMap::new(), &root, &root);
    assert!(res.is_err());
}

#[test]
fn plugin_isolated_when_reads_fs_false() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let file_path = root.join("isolation.txt");
    fs::write(&file_path, b"secret").unwrap();

    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("plugin.py"), ISOLATION_PY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(tmp.path().join("plugin.py"))
            .unwrap()
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(tmp.path().join("plugin.py"), perm).unwrap();
    }
    fs::write(
        tmp.path().join("plugin.toml"),
        r#"name = "iso"
version = "1.0.0"
api_version = "1.x"
entry = "python3 plugin.py"
capabilities = ["analyze"]
needs_content = true
reads_fs = false
timeout_ms = 5000
"#,
    )
    .unwrap();

    let pm =
        PluginManager::load(&[tmp.path().to_path_buf()], &HashMap::new(), &root, &root).unwrap();

    let mut spec = FileSpec {
        path: file_path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let bytes = fs::read(&file_path).unwrap();
    spec.content_b64 = Some(general_purpose::STANDARD.encode(bytes));

    let res: serde_json::Value = pm.analyzers()[0].analyze(vec![spec]).unwrap();
    assert_eq!(res["findings"][0]["message"], "missing");
    assert_ne!(
        res["findings"][0]["file"].as_str().unwrap(),
        file_path.to_string_lossy()
    );

    let _ = fs::remove_file(file_path);
}
