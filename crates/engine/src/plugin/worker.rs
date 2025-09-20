use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};

use anyhow::{anyhow, Context, Result};
use plugin_core::{apply_limits, Limits, PluginError, PluginLogCall, PluginResult};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tracing::{debug, error, info, trace, warn};

pub(crate) struct Worker {
    child: Child,
    stdin: BufWriter<std::process::ChildStdin>,
    stdout_rx: mpsc::Receiver<LineMessage>,
    reader_handle: Option<JoinHandle<()>>,
    limits: Limits,
    plugin_name: String,
}

type LineMessage = Result<Option<String>, anyhow::Error>;

impl Worker {
    pub(crate) fn spawn(
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

    pub(crate) fn call<R: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<R> {
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
    pub(crate) fn reader_thread_id(&self) -> Option<std::thread::ThreadId> {
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
