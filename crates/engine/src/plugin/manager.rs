use anyhow::{anyhow, Context, Result};
use plugin_core::discover_plugins;
use plugin_core::{
    apply_limits, FileSpec, Limits, PluginError, PluginInit, PluginInitResponse, PluginLogCall,
    PluginResult, RepoDiscoverParams, RepoDiscoverResult,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use shlex::Shlex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Mutex,
};
use std::thread::{self, JoinHandle};
use tracing::{debug, error, info, trace, warn};

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
        let mut worker = worker.lock().expect("worker poisoned");
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
            if let Ok(mut w) = worker.lock() {
                let _ = w.call::<Value>("plugin.shutdown", Value::Null);
            }
        }
    }
}

/// Plugin administrado con metadatos adicionales.
pub struct ManagedPlugin {
    plugin: ProcPlugin,
    needs_content: bool,
    reads_fs: bool,
    /// Plugin name, useful for logging.
    name: String,
    /// Version reported by the plugin.
    plugin_version: String,
}

impl std::ops::Deref for ManagedPlugin {
    type Target = ProcPlugin;
    fn deref(&self) -> &Self::Target {
        &self.plugin
    }
}

impl ManagedPlugin {
    /// Indicates if the plugin requires file content.
    pub fn needs_content(&self) -> bool {
        self.needs_content
    }

    /// Indicates if the plugin needs filesystem access.
    pub fn reads_fs(&self) -> bool {
        self.reads_fs
    }

    /// Version of the loaded plugin.
    pub fn version(&self) -> &str {
        &self.plugin_version
    }

    fn sanitize_files(&self, files: Vec<FileSpec>) -> Vec<FileSpec> {
        if self.reads_fs {
            files
        } else {
            files
                .into_iter()
                .map(|mut f| {
                    let name = Path::new(&f.path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("file");
                    f.path = format!("/virtual/{name}");
                    f
                })
                .collect()
        }
    }

    pub fn transform<R: DeserializeOwned>(&self, files: Vec<FileSpec>) -> Result<R> {
        self.plugin
            .transform(self.sanitize_files(files))
            .with_context(|| format!("plugin {}", self.name))
    }

    pub fn analyze<R: DeserializeOwned>(&self, files: Vec<FileSpec>) -> Result<R> {
        self.plugin
            .analyze(self.sanitize_files(files))
            .with_context(|| format!("plugin {}", self.name))
    }

    /// Name of the loaded plugin.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Executes `repo.discover` on the managed plugin.
    pub fn discover(&self, params: RepoDiscoverParams) -> Result<RepoDiscoverResult> {
        self.plugin
            .discover(params)
            .with_context(|| format!("plugin {}", self.name))
    }
}

/// Coordinates loaded plugins and exposes collections by type.
#[derive(Default)]
pub struct PluginManager {
    transformers: Vec<ManagedPlugin>,
    analyzers: Vec<ManagedPlugin>,
    reporters: Vec<ManagedPlugin>,
    discoverers: Vec<ManagedPlugin>,
}

impl PluginManager {
    /// Transformation plugins that run before parsing.
    pub fn transformers(&self) -> &[ManagedPlugin] {
        &self.transformers
    }

    /// Analysis plugins that run after generating the IR.
    pub fn analyzers(&self) -> &[ManagedPlugin] {
        &self.analyzers
    }

    /// Plugins that run after analysis to report findings.
    pub fn reporters(&self) -> &[ManagedPlugin] {
        &self.reporters
    }

    /// Repository discovery plugins.
    pub fn discoverers(&self) -> &[ManagedPlugin] {
        &self.discoverers
    }

    /// Loads plugins from the specified directories.
    pub fn load(
        explicit: &[PathBuf],
        opts: &HashMap<String, Value>,
        workspace_root: &Path,
        rules_root: &Path,
    ) -> Result<Self> {
        let infos = discover_plugins(explicit)?;
        let mut transformers = Vec::new();
        let mut analyzers = Vec::new();
        let mut reporters = Vec::new();
        let mut discoverers = Vec::new();

        for info in infos {
            let plugin_name = info.manifest.name.as_deref().unwrap_or("<unnamed>");
            info!(
                name = plugin_name,
                capabilities = ?info.manifest.capabilities,
                path = %info.path.display(),
                "Loading plugin"
            );
            let parts: Vec<String> = Shlex::new(&info.manifest.entry).collect();
            let (cmd, args) = parts.split_first().ok_or_else(|| anyhow!("empty entry"))?;
            let cmd_path = if Path::new(cmd).is_absolute() {
                PathBuf::from(cmd)
            } else if cmd.contains('/') || cmd.contains('\\') {
                info.path.join(cmd)
            } else {
                PathBuf::from(cmd)
            };
            let concurrency = info.manifest.concurrency.as_deref().unwrap_or("single");

            // Use empty object as default plugin options to satisfy schemas expecting an object.
            let options = info
                .manifest
                .name
                .as_ref()
                .and_then(|n| opts.get(n).cloned())
                .unwrap_or(Value::Object(serde_json::Map::new()));
            info.validate_config(&options)?;

            let needs_content = info.manifest.needs_content.unwrap_or(false);
            let reads_fs = info.manifest.reads_fs.unwrap_or(false);

            // Helper to spawn a plugin for a given capability.
            let create_plugin = |cap: &str| -> Result<Option<ManagedPlugin>> {
                if info.manifest.capabilities.iter().any(|c| c == cap) {
                    let limits = Limits {
                        cpu_ms: info.manifest.timeout_ms,
                        mem_mb: info.manifest.mem_mb,
                    };
                    // Canonicalize roots to ensure plugins receive absolute, stable paths.
                    let ws_root_abs = if reads_fs {
                        workspace_root
                            .canonicalize()
                            .unwrap_or_else(|_| workspace_root.to_path_buf())
                    } else {
                        PathBuf::from("/")
                    };
                    let rules_root_abs = if reads_fs {
                        rules_root
                            .canonicalize()
                            .unwrap_or_else(|_| rules_root.to_path_buf())
                    } else {
                        PathBuf::from("/")
                    };

                    let (plugin, plugin_version) = ProcPlugin::new(
                        &cmd_path,
                        args,
                        concurrency,
                        limits,
                        options.clone(),
                        &ws_root_abs,
                        &rules_root_abs,
                        &info.manifest.capabilities,
                        &info.path,
                        plugin_name,
                    )?;
                    info!(name = plugin_name, capability = cap, version = %plugin_version, "Plugin initialized");
                    Ok(Some(ManagedPlugin {
                        plugin,
                        needs_content,
                        reads_fs,
                        name: plugin_name.to_string(),
                        plugin_version,
                    }))
                } else {
                    Ok(None)
                }
            };

            if let Some(plugin) = create_plugin("transform")? {
                transformers.push(plugin);
            }
            if let Some(plugin) = create_plugin("analyze")? {
                analyzers.push(plugin);
            }
            if let Some(plugin) = create_plugin("report")? {
                reporters.push(plugin);
            }
            if let Some(plugin) = create_plugin("discover")? {
                discoverers.push(plugin);
            }
        }

        Ok(Self {
            transformers,
            analyzers,
            reporters,
            discoverers,
        })
    }
}

type LineMessage = Result<Option<String>, anyhow::Error>;

struct Worker {
    child: Child,
    stdin: BufWriter<std::process::ChildStdin>,
    stdout_rx: mpsc::Receiver<LineMessage>,
    reader_handle: Option<JoinHandle<()>>,
    limits: Limits,
    plugin_name: String,
}

impl Worker {
    fn spawn(
        cmd_path: &Path,
        args: &[String],
        workdir: &Path,
        limits: &Limits,
        plugin_name: &str,
    ) -> Result<Self> {
        debug!(program = %cmd_path.display(), "Spawning worker process");
        let mut command = if cmd_path.extension().is_some_and(|ext| ext == "sh") {
            // For shell scripts, execute with bash explicitly
            let mut cmd = Command::new("bash");
            cmd.arg(cmd_path);
            cmd
        } else {
            // For other executables, run directly
            Command::new(cmd_path)
        };
        command
            .args(args)
            .current_dir(workdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        apply_limits(&mut command, limits);
        let mut child = command
            .spawn()
            .with_context(|| format!("spawn {}", cmd_path.display()))?;
        debug!(pid = child.id(), program = %cmd_path.display(), "Worker process started");
        let stdin = child.stdin.take().context("open stdin")?;
        let stdout = child.stdout.take().context("open stdout")?;
        let (tx, rx) = mpsc::channel::<LineMessage>();
        let thread_name = format!("plugin-stdout-{}", plugin_name);
        let reader_handle = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let mut lines = BufReader::new(stdout).lines();
                loop {
                    let message = match lines.next() {
                        Some(Ok(line)) => Ok(Some(line)),
                        Some(Err(err)) => Err(anyhow!(err)),
                        None => Ok(None),
                    };
                    let should_break = matches!(&message, Ok(None) | Err(_));
                    if tx.send(message).is_err() {
                        break;
                    }
                    if should_break {
                        break;
                    }
                }
            })
            .with_context(|| format!("spawn stdout reader thread for {}", plugin_name))?;
        Ok(Self {
            child,
            stdin: BufWriter::new(stdin),
            stdout_rx: rx,
            reader_handle: Some(reader_handle),
            limits: limits.clone(),
            plugin_name: plugin_name.to_string(),
        })
    }

    fn call<R: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<R> {
        use std::time::{Duration, Instant};

        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst).to_string();
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        serde_json::to_writer(&mut self.stdin, &req)?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;

        let start = Instant::now();
        loop {
            let line_res = match self.limits.cpu_ms {
                Some(ms) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    if elapsed >= ms {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        return Err(anyhow!(format!("plugin timed out after {} ms", ms)));
                    }
                    match self
                        .stdout_rx
                        .recv_timeout(Duration::from_millis(ms - elapsed))
                    {
                        Ok(res) => res,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            let _ = self.child.kill();
                            let _ = self.child.wait();
                            return Err(anyhow!(format!("plugin timed out after {} ms", ms)));
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(anyhow!("plugin closed"));
                        }
                    }
                }
                None => self
                    .stdout_rx
                    .recv()
                    .map_err(|_| anyhow!("plugin closed"))?,
            };

            let line = match line_res {
                Ok(Some(line)) => line,
                Ok(None) => return Err(anyhow!("plugin closed")),
                Err(e) => return Err(e),
            };

            if let Ok(log_call) = serde_json::from_str::<PluginLogCall>(&line) {
                if log_call.method == "plugin.log" {
                    let level = log_call.params.level.unwrap_or_else(|| "info".to_string());
                    match level.as_str() {
                        "trace" => trace!("[{}] {}", self.plugin_name, log_call.params.message),
                        "debug" => debug!("[{}] {}", self.plugin_name, log_call.params.message),
                        "warn" => warn!("[{}] {}", self.plugin_name, log_call.params.message),
                        "error" => error!("[{}] {}", self.plugin_name, log_call.params.message),
                        _ => info!("[{}] {}", self.plugin_name, log_call.params.message),
                    }
                    continue;
                }
            }

            if let Ok(res) = serde_json::from_str::<PluginResult<R>>(&line) {
                return Ok(res.result);
            }
            // Fallback: tolerate plugins that wrap results, e.g. {"result": {"findings": [...]}}
            // or send null where an empty list is expected.
            if let Ok(res_any) = serde_json::from_str::<PluginResult<Value>>(&line) {
                let mut value = res_any.result;
                // If the result is an object with a single "findings" field, unwrap it
                if let Some(findings) = value.get("findings").cloned() {
                    value = findings;
                }
                // Treat explicit null as an empty array to avoid hangs and simplify plugin contracts
                if value.is_null() {
                    value = json!([]);
                }
                if let Ok(mapped) = serde_json::from_value::<R>(value) {
                    return Ok(mapped);
                }
            }
            if let Ok(err) = serde_json::from_str::<PluginError>(&line) {
                return Err(anyhow!(err.message));
            }
            warn!(%line, "unexpected plugin message");
        }
    }

    #[cfg(test)]
    fn reader_thread_id(&self) -> Option<std::thread::ThreadId> {
        self.reader_handle
            .as_ref()
            .map(|handle| handle.thread().id())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Err(err) = self.child.kill() {
            warn!(error = %err, "failed to kill plugin process");
        }
        if let Err(err) = self.child.wait() {
            warn!(error = %err, "failed to reap plugin process");
        }
        if let Some(handle) = self.reader_handle.take() {
            if let Err(err) = handle.join() {
                warn!("failed to join plugin stdout reader thread: {:?}", err);
            }
        }
    }
}

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

#[cfg(test)]
mod tests {
    use super::*;
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
