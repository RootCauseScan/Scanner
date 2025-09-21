use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use anyhow::{anyhow, Result};
use plugin_core::{
    FileSpec, Limits, PluginInit, PluginInitResponse, RepoDiscoverParams, RepoDiscoverResult,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tracing::debug;

use super::worker::Worker;

/// Plugin that runs an external process and communicates via JSON-RPC over
/// `stdin`/`stdout`.
pub struct ProcPlugin {
    workers: Vec<Mutex<Worker>>,
    next: AtomicUsize,
}

impl ProcPlugin {
    /// Creates a new instance from the `cmd` command and its arguments.
    /// When `concurrency == "multi"` multiple processes are launched.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cmd_path: &Path,
        args: &[String],
        concurrency: &str,
        limits: Limits,
        options: Value,
        workspace_root: &Path,
        rules_root: &Path,
        capabilities: &[String],
        workdir: &Path,
        plugin_name: &str,
    ) -> Result<(Self, String)> {
        let count = if concurrency == "multi" {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            1
        };

        let mut workers = Vec::with_capacity(count);
        let mut plugin_version = String::new();
        for idx in 0..count {
            debug!(worker = idx, program = %cmd_path.display(), "Starting plugin process");
            let mut worker = Worker::spawn(cmd_path, args, workdir, &limits, plugin_name)?;
            debug!(worker = idx, program = %cmd_path.display(), "Worker spawned");
            let init = PluginInit {
                api_version: "1.0.0".into(),
                session_id: format!("{}", std::process::id()),
                workspace_root: workspace_root.to_string_lossy().into_owned(),
                rules_root: rules_root.to_string_lossy().into_owned(),
                capabilities_requested: capabilities.to_vec(),
                options: options.clone(),
                limits: Some(limits.clone()),
                env: HashMap::new(),
                cwd: std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .to_string_lossy()
                    .into_owned(),
            };
            let init_res: PluginInitResponse = worker.call("plugin.init", json!(init))?;
            if !init_res.ok {
                return Err(anyhow!("plugin init failed"));
            }
            if idx == 0 {
                plugin_version = init_res.plugin_version.clone();
            }
            for cap in capabilities {
                if !init_res.capabilities.iter().any(|c| c == cap) {
                    return Err(anyhow!(format!("missing capability: {}", cap)));
                }
            }
            worker.call::<Value>("plugin.ping", Value::Null)?;
            debug!(worker = idx, program = %cmd_path.display(), "plugin.init completed");
            workers.push(Mutex::new(worker));
        }

        Ok((
            Self {
                workers,
                next: AtomicUsize::new(0),
            },
            plugin_version,
        ))
    }

    fn next_worker(&self) -> &Mutex<Worker> {
        let idx = self.next.fetch_add(1, Ordering::SeqCst) % self.workers.len();
        &self.workers[idx]
    }

    fn call<R: DeserializeOwned>(&self, method: &str, params: Value) -> Result<R> {
        let worker = self.next_worker();
        let mut worker = worker.lock().map_err(|err| {
            debug!(error = %err, "worker mutex poisoned");
            anyhow!("worker unavailable: worker mutex poisoned by a previous panic")
        })?;
        worker.call(method, params)
    }

    /// Invokes `repo.discover` on the plugin.
    pub fn discover(&self, params: RepoDiscoverParams) -> Result<RepoDiscoverResult> {
        self.call("repo.discover", json!(params))
    }

    /// Invokes `file.transform` on the plugin.
    pub fn transform<R: DeserializeOwned>(&self, files: Vec<FileSpec>) -> Result<R> {
        self.call("file.transform", json!({ "files": files }))
    }

    /// Invokes `file.analyze` on the plugin.
    pub fn analyze<R: DeserializeOwned>(&self, files: Vec<FileSpec>) -> Result<R> {
        self.call("file.analyze", json!({ "files": files }))
    }

    /// Invokes `scan.report` on the plugin.
    pub fn report<R: DeserializeOwned>(&self, findings: Value, metrics: Value) -> Result<R> {
        self.call(
            "scan.report",
            json!({ "findings": findings, "metrics": metrics }),
        )
    }

    /// Verifies plugin availability.
    pub fn ping(&self) -> Result<()> {
        self.call::<Value>("plugin.ping", Value::Null).map(|_| ())
    }
}

impl Drop for ProcPlugin {
    fn drop(&mut self) {
        for worker in &self.workers {
            match worker.lock() {
                Ok(mut w) => {
                    let _ = w.call::<Value>("plugin.shutdown", Value::Null);
                }
                Err(err) => {
                    debug!(error = %err, "worker unavailable during shutdown");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::worker::Worker;
    use super::*;
    use plugin_core::Limits;
    use serde_json::Value;
    use std::fs;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{atomic::AtomicUsize, Mutex};
    use tempfile::TempDir;

    const NOOP_PY: &str = r#"#!/usr/bin/env python3
import sys

for _line in sys.stdin:
    pass
"#;

    #[test]
    fn call_returns_error_when_worker_mutex_poisoned() {
        let tmp = TempDir::new().expect("tempdir");
        let script = tmp.path().join("noop_plugin.py");
        fs::write(&script, NOOP_PY).expect("write script");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script).expect("metadata").permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script, perms).expect("set permissions");
        }

        let limits = Limits::default();
        let worker =
            Worker::spawn(&script, &[], tmp.path(), &limits, "noop").expect("spawn worker");

        let plugin = ProcPlugin {
            workers: vec![Mutex::new(worker)],
            next: AtomicUsize::new(0),
        };

        {
            let worker_mutex = &plugin.workers[0];
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let _guard = worker_mutex.lock().expect("lock worker");
                panic!("poison worker mutex");
            }));
        }

        let error = plugin
            .call::<Value>("plugin.ping", Value::Null)
            .expect_err("expected poisoned worker error");
        assert!(
            error.to_string().contains("worker unavailable"),
            "unexpected error message: {}",
            error
        );

        drop(plugin);
    }
}
