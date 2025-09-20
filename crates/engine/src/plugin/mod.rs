//! Componentes relacionados con el sistema de plugins.

mod managed;
pub mod manager;
mod proc_plugin;
mod worker;

pub use managed::ManagedPlugin;
pub use manager::PluginManager;
pub use proc_plugin::ProcPlugin;

#[cfg(test)]
mod tests {
    use super::worker::Worker;
    use plugin_core::Limits;
    use serde_json::{json, Value};
    use std::fs;
    use tempfile::TempDir;

    const ECHO_PY: &str = r#"#!/usr/bin/env python3
import sys, json

def send(i, result=None):
    msg = {"jsonrpc": "2.0", "id": i, "result": result or {}}
    print(json.dumps(msg))
    sys.stdout.flush()

for line in sys.stdin:
    req = json.loads(line)
    mid = req.get("id")
    method = req.get("method")
    if method == "plugin.shutdown":
        send(mid, {"ok": True})
        break
    else:
        send(mid, {"method": method, "params": req.get("params")})
"#;

    #[test]
    fn reuses_stdout_thread_across_calls() {
        let tmp = TempDir::new().unwrap();
        let script = tmp.path().join("plugin.py");
        fs::write(&script, ECHO_PY).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script, perms).unwrap();
        }

        let limits = Limits::default();
        let mut worker = Worker::spawn(&script, &[], tmp.path(), &limits, "echo").unwrap();
        let reader_thread = worker.reader_thread_id().expect("reader thread");

        for iteration in 0..3 {
            let response: Value = worker
                .call("echo", json!({"iteration": iteration}))
                .unwrap();
            assert_eq!(response["method"], "echo");
            assert_eq!(worker.reader_thread_id().unwrap(), reader_thread);
        }

        let _: Value = worker
            .call("plugin.shutdown", Value::Null)
            .expect("shutdown response");
    }
}
