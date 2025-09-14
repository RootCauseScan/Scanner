#![allow(clippy::uninlined_format_args, clippy::collapsible_else_if)]

use anyhow::Context;
use colored::*;
use serde_json::json;
use shlex::Shlex;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::args::PluginCmd;
use crate::config::{config_dir, load_config, save_config};
use plugin_core::{
    apply_limits, discover_plugins, FileSpec, Limits, PluginInfo, PluginInit, PluginInitResponse,
    PluginManifest, RepoDiscoverParams,
};
use serde_json::Value;

/// Check if colored output should be used
fn use_colored_output() -> bool {
    // Check if NO_COLOR is set (standard environment variable to disable colors)
    if env::var("NO_COLOR").is_ok() {
        return false;
    }

    // Check if TERM indicates a basic terminal
    if let Ok(term) = env::var("TERM") {
        if term == "dumb" || term == "unknown" {
            return false;
        }
    }

    // Check if we're in a CI environment
    if env::var("CI").is_ok() || env::var("CONTINUOUS_INTEGRATION").is_ok() {
        return false;
    }

    // Default to true for modern terminals
    true
}

/// Print a status message with appropriate formatting
fn print_status(tag: &str, message: &str) {
    println!("[{tag}] {message}");
}

/// Print a colored message with fallback for basic terminals
fn print_colored(tag: &str, message: &str) {
    if use_colored_output() {
        println!("[{}] {message}", tag.bright_blue().bold());
    } else {
        println!("[{tag}] {message}");
    }
}

/// Print an error message with appropriate formatting
fn print_error(tag: &str, message: &str) {
    if use_colored_output() {
        println!("[{}] {message}", tag.bright_red().bold());
    } else {
        println!("[{tag}] {message}");
    }
}

/// Print a success message with appropriate formatting
fn print_success(tag: &str, message: &str) {
    if use_colored_output() {
        println!("[{}] {message}", tag.bright_green().bold());
    } else {
        println!("[{tag}] {message}");
    }
}

/// Print an info message with appropriate formatting
fn print_info(tag: &str, message: &str) {
    if use_colored_output() {
        println!("[{}] {message}", tag.bright_yellow());
    } else {
        println!("[{tag}] {message}");
    }
}

fn copy_dir_all(src: &Path, dst: &Path, follow_symlinks: bool) -> anyhow::Result<()> {
    fn inner(
        src: &Path,
        dst: &Path,
        follow_symlinks: bool,
        visited: &mut HashSet<PathBuf>,
    ) -> anyhow::Result<()> {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let path = entry.path();
            let new_path = dst.join(entry.file_name());
            if ty.is_symlink() {
                // Symlinks are ignored by default to avoid accidentally copying
                // files outside the plugin directory and to prevent infinite
                // recursion. Users may opt in via `follow_symlinks` if they know
                // the links are safe.
                if !follow_symlinks {
                    continue;
                }
                let target = fs::read_link(&path)?;
                let target = if target.is_absolute() {
                    target
                } else {
                    path.parent().unwrap_or(Path::new(".")).join(target)
                };
                let canonical = match fs::canonicalize(&target) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if !visited.insert(canonical.clone()) {
                    // Skip already-visited paths to avoid cycles.
                    continue;
                }
                if canonical.is_dir() {
                    inner(&canonical, &new_path, follow_symlinks, visited)?;
                } else if canonical.is_file() {
                    fs::copy(&canonical, &new_path)?;
                }
            } else if ty.is_dir() {
                inner(&path, &new_path, follow_symlinks, visited)?;
            } else if ty.is_file() {
                fs::copy(&path, &new_path)?;
            }
        }
        Ok(())
    }

    let mut visited = HashSet::new();
    if let Ok(p) = fs::canonicalize(src) {
        visited.insert(p);
    }
    inner(src, dst, follow_symlinks, &mut visited)
}

fn run_install_steps(dir: &Path) -> anyhow::Result<()> {
    let manifest_path = dir.join("plugin.toml");
    if !manifest_path.exists() {
        return Ok(());
    }
    let data = fs::read_to_string(&manifest_path)?;
    let v: toml::Value = toml::from_str(&data)?;
    if let Some(steps) = v
        .get("install")
        .and_then(|i| i.get("steps"))
        .and_then(|s| s.as_array())
    {
        for step in steps {
            if let Some(cmd) = step.as_str() {
                let parts: Vec<String> = Shlex::new(cmd).collect();
                if let Some((prog, args)) = parts.split_first() {
                    // Run the command and capture its output so we can surface
                    // useful diagnostics if it fails.
                    let output = Command::new(prog)
                        .args(args)
                        .current_dir(dir)
                        .output()
                        .with_context(|| format!("failed to run install step: {cmd}"))?;
                    if !output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        anyhow::bail!(
                            "install step failed: {cmd}\nstdout: {}\nstderr: {}",
                            stdout.trim(),
                            stderr.trim()
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn resolve_plugin_dir(spec: &str) -> anyhow::Result<PathBuf> {
    if let Ok(infos) = discover_plugins(&[]) {
        if let Some(info) = infos.into_iter().find(|info| {
            info.manifest
                .name
                .as_deref()
                .map(|n| n == spec)
                .unwrap_or(false)
                || info.path.file_name().and_then(|n| n.to_str()) == Some(spec)
        }) {
            return Ok(info.path);
        }
    }
    let path = PathBuf::from(spec);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .context("failed to get current dir")?
            .join(&path)
    };
    let dir = if path.is_file() {
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        path
    };
    if dir.join("plugin.toml").is_file() {
        Ok(dir)
    } else {
        anyhow::bail!("plugin not found: {spec}");
    }
}

fn handshake_plugin(path: &Path) -> anyhow::Result<Option<String>> {
    let manifest = PluginManifest::load(path)?;
    let parts: Vec<String> = Shlex::new(&manifest.entry).collect();
    let (cmd, args) = parts
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty entry"))?;
    // Resolve command path:
    // - absolute path: use as-is
    // - contains path separator: resolve relative to plugin dir
    // - otherwise: treat as program on PATH
    let cmd_path = if Path::new(cmd).is_absolute() {
        PathBuf::from(cmd)
    } else if cmd.contains('/') || cmd.contains('\\') {
        path.join(cmd)
    } else {
        PathBuf::from(cmd)
    };
    let limits = if manifest.timeout_ms.is_some() || manifest.mem_mb.is_some() {
        Some(Limits {
            cpu_ms: manifest.timeout_ms,
            mem_mb: manifest.mem_mb,
        })
    } else {
        None
    };
    let mut command = if cmd_path.extension().is_some_and(|ext| ext == "sh") {
        let mut cmd = Command::new("bash");
        cmd.arg(&cmd_path);
        cmd
    } else {
        Command::new(&cmd_path)
    };
    command
        .args(args)
        .current_dir(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(ref l) = limits {
        apply_limits(&mut command, l);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", cmd_path.display()))?;
    let mut stdin = child.stdin.take().context("open stdin")?;
    let stdout = child.stdout.take().context("open stdout")?;
    let reader = BufReader::new(stdout);
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for line in reader.lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let init = PluginInit {
        api_version: "1.0.0".into(),
        session_id: "verify".into(),
        workspace_root: String::new(),
        rules_root: String::new(),
        capabilities_requested: manifest.capabilities.clone(),
        options: serde_json::Value::Null,
        limits,
        env: HashMap::new(),
        cwd: std::env::current_dir()
            .context("failed to get current dir")?
            .to_string_lossy()
            .into_owned(),
    };
    let req = json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "plugin.init",
        "params": init,
    });
    serde_json::to_writer(&mut stdin, &req)?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    let line = match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(line) => line?,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("plugin did not respond");
        }
    };
    if serde_json::from_str::<serde_json::Value>(&line)?
        .get("error")
        .is_some()
    {
        anyhow::bail!("plugin.init failed");
    }
    let ping = json!({"jsonrpc":"2.0","id":"2","method":"plugin.ping"});
    serde_json::to_writer(&mut stdin, &ping)?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    let line = match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(line) => line?,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("plugin did not respond");
        }
    };
    let value: serde_json::Value = serde_json::from_str(&line)?;
    if value.get("error").is_some() {
        anyhow::bail!("plugin.ping failed");
    }
    let pong = value
        .get("result")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let shutdown = json!({"jsonrpc":"2.0","id":"3","method":"plugin.shutdown"});
    let _ = serde_json::to_writer(&mut stdin, &shutdown);
    let _ = stdin.write_all(b"\n");
    let _ = stdin.flush();
    child.wait().context("failed to wait for plugin process")?;
    handle.join().ok();
    Ok(pong)
}

fn verify_plugin(path: &Path) -> anyhow::Result<()> {
    let manifest = PluginManifest::load(path)?;
    let parts: Vec<String> = Shlex::new(&manifest.entry).collect();
    let (cmd, args) = parts
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty entry"))?;

    let cmd_path = if Path::new(cmd).is_absolute() {
        PathBuf::from(cmd)
    } else if cmd.contains('/') || cmd.contains('\\') {
        path.join(cmd)
    } else {
        PathBuf::from(cmd)
    };

    let limits = if manifest.timeout_ms.is_some() || manifest.mem_mb.is_some() {
        Some(Limits {
            cpu_ms: manifest.timeout_ms,
            mem_mb: manifest.mem_mb,
        })
    } else {
        None
    };

    let mut command = if cmd_path.extension().is_some_and(|ext| ext == "sh") {
        let mut cmd = Command::new("bash");
        cmd.arg(&cmd_path);
        cmd
    } else {
        Command::new(&cmd_path)
    };
    command
        .args(args)
        .current_dir(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(ref l) = limits {
        apply_limits(&mut command, l);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {}", cmd_path.display()))?;
    let mut stdin = child.stdin.take().context("open stdin")?;
    let stdout = child.stdout.take().context("open stdout")?;
    let reader = BufReader::new(stdout);
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        for line in reader.lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let init = PluginInit {
        api_version: "1.0.0".into(),
        session_id: "verify".into(),
        workspace_root: String::new(),
        rules_root: String::new(),
        capabilities_requested: manifest.capabilities.clone(),
        options: serde_json::Value::Null,
        limits,
        env: HashMap::new(),
        cwd: std::env::current_dir()
            .context("failed to get current dir")?
            .to_string_lossy()
            .into_owned(),
    };
    let req = json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": "plugin.init",
        "params": init,
    });
    serde_json::to_writer(&mut stdin, &req)?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    let line = match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(line) => line?,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("plugin did not respond");
        }
    };
    if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&line) {
        if resp.get("error").is_some() {
            anyhow::bail!("plugin.init failed");
        }
    }
    let init_resp: plugin_core::PluginResult<PluginInitResponse> = serde_json::from_str(&line)?;
    if !init_resp.result.ok {
        anyhow::bail!("plugin.init failed");
    }
    let caps = init_resp.result.capabilities;

    let ping = json!({"jsonrpc":"2.0","id":"2","method":"plugin.ping"});
    serde_json::to_writer(&mut stdin, &ping)?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    let line = match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(line) => line?,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("plugin did not respond");
        }
    };
    let value: serde_json::Value = serde_json::from_str(&line)?;
    if value.get("error").is_some() {
        anyhow::bail!("plugin.ping failed");
    }

    let tests = [
        // Basic protocol tests
        ("ping", "plugin.ping", json!({})),
        ("invalid_method", "plugin.invalid_method", json!({})),
        // Capability tests
        (
            "discover",
            "repo.discover",
            json!(RepoDiscoverParams::default()),
        ),
        (
            "transform",
            "file.transform",
            json!({"files": [FileSpec { path: "verify.txt".into(), ..FileSpec::default() }]}),
        ),
        (
            "analyze",
            "file.analyze",
            json!({"files": [FileSpec { path: "verify.txt".into(), ..FileSpec::default() }]}),
        ),
        (
            "report",
            "scan.report",
            json!({"findings": [], "metrics": Value::Object(Default::default())}),
        ),
        ("rules", "rules.list", json!({})),
    ];

    let mut errors = Vec::new();
    let mut test_results = Vec::new();

    for (idx, (cap, method, params)) in tests.iter().enumerate() {
        let id = (idx + 3).to_string();
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});

        // Show what test we're running
        let (supported, test_desc) = match *cap {
            "ping" => (true, "Testing plugin.ping (should succeed)".to_string()),
            "invalid_method" => (false, "Testing invalid method (should reject)".to_string()),
            _ => {
                let supported = caps.iter().any(|c| c == cap);
                if supported {
                    (true, format!("Testing {} capability (should succeed)", cap))
                } else {
                    (false, format!("Testing {} capability (should reject)", cap))
                }
            }
        };
        print_colored("TEST", &test_desc);

        serde_json::to_writer(&mut stdin, &req)?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        let mut line = match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(line) => line?,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let error_msg = format!(
                    "Plugin did not respond to {} capability test (timeout after 5s)",
                    cap
                );
                errors.push(error_msg.clone());
                test_results.push((cap, "TIMEOUT", error_msg));
                continue;
            }
        };

        // Skip plugin.log messages during verification
        while let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
            if let Some(method) = value.get("method") {
                if method == "plugin.log" {
                    // This is a log message, skip it and read the next line
                    line = match rx.recv_timeout(Duration::from_secs(5)) {
                        Ok(line) => line?,
                        Err(_) => {
                            let _ = child.kill();
                            let _ = child.wait();
                            let error_msg = format!(
                                "Plugin did not respond to {} capability test (timeout after 5s)",
                                cap
                            );
                            errors.push(error_msg.clone());
                            test_results.push((cap, "TIMEOUT", error_msg));
                            break;
                        }
                    };
                    continue;
                }
            }
            break; // Not a log message, process normally
        }

        let value: serde_json::Value = serde_json::from_str(&line)?;

        // Special handling for different test types
        match *cap {
            "ping" => {
                if value.get("error").is_some() {
                    let error_code = value
                        .get("error")
                        .and_then(|e| e.get("code"))
                        .and_then(|c| c.as_i64())
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    let error_msg = value
                        .get("error")
                        .and_then(|e| e.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown error");
                    let detailed_error = format!(
                        "Plugin.ping failed: error code {}, message: \"{}\"",
                        error_code, error_msg
                    );
                    errors.push(detailed_error.clone());
                    test_results.push((cap, "FAILED", detailed_error));
                } else if value
                    .get("result")
                    .and_then(|r| r.get("pong"))
                    .and_then(|p| p.as_bool())
                    .unwrap_or(false)
                {
                    test_results.push((
                        cap,
                        "PASSED",
                        "Plugin.ping responded correctly with pong: true".to_string(),
                    ));
                } else {
                    let detailed_error = format!(
                        "Plugin.ping failed: expected result with pong: true, but got: {}",
                        serde_json::to_string(&value)
                            .unwrap_or_else(|_| "invalid JSON".to_string())
                    );
                    errors.push(detailed_error.clone());
                    test_results.push((cap, "FAILED", detailed_error));
                }
            }
            "invalid_method" => {
                match value
                    .get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_i64())
                {
                    Some(-32601) => {
                        test_results.push((cap, "PASSED", "Invalid method correctly rejected with standard JSON-RPC error code -32601".to_string()));
                    }
                    Some(other_code) => {
                        let detailed_error = format!("Invalid method incorrectly handled: expected rejection with error code -32601, but got error code {}", 
                            other_code);
                        errors.push(detailed_error.clone());
                        test_results.push((cap, "FAILED", detailed_error));
                    }
                    None => {
                        // No error, which means plugin handled it when it shouldn't
                        let response_preview = if line.len() > 100 {
                            format!("{}...", &line[..97])
                        } else {
                            line.clone()
                        };
                        let detailed_error = format!("Invalid method incorrectly handled: expected rejection with error code -32601, but got success response: {}", 
                            response_preview);
                        errors.push(detailed_error.clone());
                        test_results.push((cap, "FAILED", detailed_error));
                    }
                }
            }
            _ => {
                // Regular capability tests
                if supported {
                    if value.get("error").is_some() {
                        let error_code = value
                            .get("error")
                            .and_then(|e| e.get("code"))
                            .and_then(|c| c.as_i64())
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        let error_msg = value
                            .get("error")
                            .and_then(|e| e.get("message"))
                            .and_then(|m| m.as_str())
                            .unwrap_or("unknown error");
                        let detailed_error = format!(
                            "Plugin failed {} capability test: error code {}, message: \"{}\"",
                            cap, error_code, error_msg
                        );
                        errors.push(detailed_error.clone());
                        test_results.push((cap, "FAILED", detailed_error));
                    } else {
                        test_results.push((
                            cap,
                            "PASSED",
                            format!("{} capability works correctly", cap),
                        ));
                    }
                } else {
                    match value
                        .get("error")
                        .and_then(|e| e.get("code"))
                        .and_then(|c| c.as_i64())
                    {
                        Some(-32601) => {
                            test_results.push((cap, "PASSED", format!("{} capability correctly rejected with standard JSON-RPC error code -32601", cap)));
                        }
                        Some(other_code) => {
                            let detailed_error = format!("Plugin incorrectly handled {} capability: expected rejection with error code -32601, but got error code {}", 
                                cap, other_code);
                            errors.push(detailed_error.clone());
                            test_results.push((cap, "FAILED", detailed_error));
                        }
                        None => {
                            // No error, which means plugin handled it when it shouldn't
                            let response_preview = if line.len() > 100 {
                                format!("{}...", &line[..97])
                            } else {
                                line.clone()
                            };
                            let detailed_error = format!("Plugin incorrectly handled {} capability: expected rejection with error code -32601, but got success response: {}", 
                                cap, response_preview);
                            errors.push(detailed_error.clone());
                            test_results.push((cap, "FAILED", detailed_error));
                        }
                    }
                }
            }
        }
    }

    // Print test results summary
    println!();
    print_colored("RESULTS", "Test Results Summary:");
    for (cap, status, message) in &test_results {
        match *status {
            "PASSED" => {
                print!("  ✓ {}: ", cap);
                print_colored("PASS", message);
            }
            "FAILED" => {
                print!("  ✗ {}: ", cap);
                print_colored("FAIL", message);
            }
            "TIMEOUT" => {
                print!("  ⏱ {}: ", cap);
                print_colored("TIMEOUT", message);
            }
            _ => {
                print!("  ? {}: ", cap);
                println!("{}", message);
            }
        }
    }

    if !errors.is_empty() {
        println!();
        print_colored(
            "ERRORS",
            &format!("Verification failed with {} error(s):", errors.len()),
        );
        for error in &errors {
            println!("  • {}", error);
        }
        println!();
        anyhow::bail!("Plugin verification failed with {} error(s)", errors.len());
    }

    let shutdown = json!({"jsonrpc":"2.0","id":"99","method":"plugin.shutdown"});
    let _ = serde_json::to_writer(&mut stdin, &shutdown);
    let _ = stdin.write_all(b"\n");
    let _ = stdin.flush();
    child.wait().context("failed to wait for plugin process")?;
    handle.join().ok();

    println!();
    Ok(())
}

fn list_installed_plugins() -> anyhow::Result<()> {
    print_colored("LIST", "Listing installed plugins...");

    let base = config_dir().join("plugins");

    let cfg = load_config().context("failed to load configuration")?;
    let mut plugins = Vec::new();

    if let Ok(entries) = fs::read_dir(&base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join("plugin.toml").exists() {
                if let Ok(manifest) = PluginManifest::load(&path) {
                    let name = manifest.name.unwrap_or_else(|| path.display().to_string());
                    let version = manifest.version.unwrap_or_else(|| "no version".to_string());
                    let capabilities = manifest.capabilities.join(", ");
                    let plugin_cfg = cfg.plugins.get(&name);
                    let enabled = plugin_cfg.map(|p| p.enabled).unwrap_or(true);

                    // Load configuration schema, parse properties, and merge with current config
                    let mut params = Vec::new();
                    let mut seen = HashSet::new();
                    if let Some(schema_file) = &manifest.config_schema {
                        let schema_path = path.join(schema_file);
                        if let Ok(data) = fs::read_to_string(&schema_path) {
                            if let Ok(schema_json) =
                                serde_json::from_str::<serde_json::Value>(&data)
                            {
                                if let Some(props) =
                                    schema_json.get("properties").and_then(|p| p.as_object())
                                {
                                    for (key, prop) in props {
                                        seen.insert(key.clone());
                                        let default = prop
                                            .get("default")
                                            .map(|v| match v {
                                                serde_json::Value::String(s) => s.clone(),
                                                _ => v.to_string(),
                                            })
                                            .unwrap_or_else(|| "null".into());
                                        let current = plugin_cfg
                                            .and_then(|p| p.params.get(key))
                                            .map(|v| match v {
                                                toml::Value::String(s) => s.clone(),
                                                _ => v.to_string(),
                                            })
                                            .unwrap_or_else(|| default.clone());
                                        params.push((key.clone(), default, current));
                                    }
                                }
                            }
                        }
                    }

                    // Include any configured parameters not described in the schema
                    if let Some(cfg_params) = plugin_cfg.map(|p| &p.params) {
                        for (key, value) in cfg_params {
                            if seen.contains(key) {
                                continue;
                            }
                            let current = match value {
                                toml::Value::String(s) => s.clone(),
                                _ => value.to_string(),
                            };
                            params.push((key.clone(), "null".into(), current));
                        }
                    }

                    plugins.push((name, version, capabilities, enabled, params));
                }
            }
        }
    }

    if plugins.is_empty() {
        println!();
        print_info("INFO", "No plugins installed");
        print_status(
            "TIP",
            "Use 'rootcause plugin install <plugin>' to install one",
        );
        println!();
        print_status("EXAMPLES", "Examples:");
        println!("   • rootcause plugin install ./my-plugin");
        println!("   • rootcause plugin install https://github.com/user/plugin.git");
    } else {
        println!();
        print_success("SUCCESS", &format!("{} plugin(s) found:", plugins.len()));
        println!();
        for (i, (name, version, capabilities, enabled, params)) in plugins.iter().enumerate() {
            let num = format!("{}.", i + 1);
            let display = if *enabled {
                name.clone()
            } else {
                format!("{name} (disabled)")
            };

            if use_colored_output() {
                println!(
                    "{} {} {}",
                    num.bright_cyan().bold(),
                    display.bright_white().bold(),
                    format!("v{version}").bright_green()
                );
            } else {
                println!("{num} {display} v{version}");
            }

            if !capabilities.is_empty() {
                if use_colored_output() {
                    println!(
                        "   {} {}",
                        "Capabilities:".bright_blue(),
                        capabilities.bright_white()
                    );
                } else {
                    println!("   Capabilities: {capabilities}");
                }
            }
            if !params.is_empty() {
                if use_colored_output() {
                    println!("   {}", "Parameters:".bright_blue());
                    for (key, default, current) in params {
                        println!(
                            "      {} (default: {}, current: {})",
                            key.bright_white(),
                            default.bright_green(),
                            current.bright_white()
                        );
                    }
                } else {
                    println!("   Parameters:");
                    for (key, default, current) in params {
                        println!("      {key} (default: {default}, current: {current})");
                    }
                }
            }
            println!();
        }
    }

    Ok(())
}

pub fn handle_plugin(cmd: PluginCmd) -> anyhow::Result<()> {
    match cmd {
        PluginCmd::Verify { path } => {
            print_colored("VERIFY", "Verifying plugin...");
            print_status("PATH", &format!("Path: {}", path.display()));

            let resolved = resolve_plugin_dir(path.to_str().context("invalid UTF-8 path")?)?;
            match verify_plugin(&resolved) {
                Ok(_) => {
                    println!();
                    print_success("SUCCESS", "Plugin verified successfully");
                }
                Err(e) => {
                    println!();
                    print_error("ERROR", "Error verifying plugin");
                    print_error("ERROR", &format!("Error: {e}"));
                    return Err(e);
                }
            }
            Ok(())
        }
        PluginCmd::Ping { path } => {
            print_colored("PING", "Pinging plugin...");
            print_status("PATH", &format!("Path: {}", path.display()));

            let resolved = resolve_plugin_dir(path.to_str().context("invalid UTF-8 path")?)?;
            println!();

            if use_colored_output() {
                println!("{}", "[rootcause] ping".bright_cyan());
            } else {
                println!("[rootcause] ping");
            }

            let pong = handshake_plugin(&resolved)
                .map_err(|e| anyhow::anyhow!("failed to ping plugin '{}': {e}", path.display()))?;
            let msg = pong.unwrap_or_else(|| "pong".to_string());

            if use_colored_output() {
                println!("{}", format!("[plugin-rc] {msg}").bright_green());
            } else {
                println!("[plugin-rc] {msg}");
            }
            println!();
            print_success("SUCCESS", "Plugin is working correctly");
            Ok(())
        }
        PluginCmd::Init { dir } => {
            print_colored("INIT", "Initialising new plugin...");
            print_status("DIRECTORY", &format!("Directory: {}", dir.display()));

            let dir = if dir.is_absolute() {
                dir
            } else {
                std::env::current_dir()?.join(dir)
            };
            fs::create_dir_all(&dir)?;
            let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("plugin");

            println!();
            print_status("CREATE", "Creating plugin files...");

            let manifest = format!(
                "name = \"{name}\"\nversion = \"0.1.0\"\napi_version = \"1.0.0\"\nentry = \"run.sh\"\ncapabilities = []\n",
            );
            fs::write(dir.join("plugin.toml"), manifest)?;
            let run_sh = "#!/bin/bash\ncd \"$(dirname \"$0\")\"\nexec python3 plugin.py\n";
            fs::write(dir.join("run.sh"), run_sh)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(dir.join("run.sh"))?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(dir.join("run.sh"), perms)?;
            }
            let plugin_py = r"#!/usr/bin/env python3
import json, sys

for line in sys.stdin:
    req = json.loads(line)
    m = req.get('method')
    resp = {'jsonrpc': '2.0', 'id': req.get('id')}
    if m == 'plugin.init':
        resp['result'] = {}
    elif m == 'plugin.ping':
        resp['result'] = 'pong'
    elif m == 'plugin.shutdown':
        resp['result'] = {}
        print(json.dumps(resp))
        sys.stdout.flush()
        break
    else:
        resp['error'] = {'code': -32601, 'message': 'method not found'}
    print(json.dumps(resp))
    sys.stdout.flush()
";
            fs::write(dir.join("plugin.py"), plugin_py)?;

            println!();
            print_success("SUCCESS", "Plugin initialised successfully");
            print_status("LOCATION", &format!("Location: {}", dir.display()));
            println!();
            print_status("NEXT", "Next steps:");
            println!("   • rootcause plugin verify {}", dir.display());
            println!("   • rootcause plugin ping {}", dir.display());
            Ok(())
        }
        PluginCmd::Install { src } => {
            print_colored("INSTALL", "Installing plugin...");
            print_status("SOURCE", &format!("Source: {}", src));

            let base = config_dir().join("plugins");
            fs::create_dir_all(&base)?;
            let src_path = Path::new(&src);
            let dest;

            if src_path.exists() {
                print_status("LOCAL", "Installing from local directory...");
                let manifest_name = src_path
                    .join("plugin.toml")
                    .is_file()
                    .then(|| {
                        fs::read_to_string(src_path.join("plugin.toml"))
                            .ok()
                            .and_then(|d| {
                                toml::from_str::<toml::Value>(&d).ok().and_then(|v| {
                                    v.get("name")
                                        .and_then(|n| n.as_str())
                                        .map(|s| s.to_string())
                                })
                            })
                    })
                    .flatten();
                let name = manifest_name
                    .or_else(|| {
                        src_path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| "plugin".into());
                dest = base.join(name);
                if dest.exists() {
                    print_info("WARN", "Replacing existing installation...");
                    fs::remove_dir_all(&dest)?;
                }
                copy_dir_all(src_path, &dest, false)?;
                run_install_steps(&dest)?;
            } else {
                print_status("GIT", "Cloning from remote repository...");
                let mut name = src.rsplit('/').next().unwrap_or("plugin").to_string();
                if let Some(stripped) = name.strip_suffix(".git") {
                    name = stripped.to_string();
                }
                dest = base.join(&name);
                let status = Command::new("git")
                    .arg("clone")
                    .arg(&src)
                    .arg(&dest)
                    .status()
                    .with_context(|| "failed to run git")?;
                if !status.success() {
                    anyhow::bail!("git clone failed");
                }
                run_install_steps(&dest)?;
            }

            println!();
            print_success("SUCCESS", "Plugin installed successfully");
            print_status("LOCATION", &format!("Location: {}", dest.display()));
            println!();
            print_status("NEXT", "Next steps:");
            println!("   • rootcause plugin verify {}", dest.display());
            println!("   • rootcause plugin ping {}", dest.display());
            Ok(())
        }
        PluginCmd::List => list_installed_plugins(),
        PluginCmd::Remove { name } => {
            print_colored("REMOVE", "Removing plugin...");
            print_status("PLUGIN", &format!("Plugin: {}", name));

            let dir = config_dir().join("plugins").join(&name);

            if dir.exists() {
                println!();
                print_info("WARN", "Removing plugin files...");
                fs::remove_dir_all(&dir)
                    .with_context(|| format!("failed to remove {}", dir.display()))?;

                println!();
                print_info("WARN", "Removing plugin configuration...");
                let mut cfg = load_config().context("failed to load configuration")?;
                if cfg.plugins.remove(&name).is_some() {
                    save_config(&cfg)?;
                }

                println!();
                print_success("SUCCESS", "Plugin removed successfully");
                print_status("LOCATION", &format!("Removed location: {}", dir.display()));
            } else {
                println!();
                print_error("ERROR", "Plugin not found");
                print_error("ERROR", &format!("Plugin '{}' not found", name));
                println!();
                list_installed_plugins()?;
                anyhow::bail!("plugin not found: {name}");
            }
            Ok(())
        }
        PluginCmd::Disable { name } => {
            print_colored("DISABLE", "Disabling plugin...");
            print_status("PLUGIN", &format!("Plugin: {}", name));

            let mut cfg = load_config().context("failed to load configuration")?;
            let entry = cfg.plugins.entry(name.clone()).or_default();
            if entry.enabled {
                entry.enabled = false;
                save_config(&cfg)?;
                println!();
                print_success("SUCCESS", "Plugin disabled successfully");
            } else {
                println!();
                print_info("INFO", "Plugin is already disabled");
            }
            Ok(())
        }
        PluginCmd::Enable { name } => {
            print_colored("ENABLE", "Enabling plugin...");
            print_status("PLUGIN", &format!("Plugin: {}", name));

            let mut cfg = load_config().context("failed to load configuration")?;
            let entry = cfg.plugins.entry(name.clone()).or_default();
            if !entry.enabled {
                entry.enabled = true;
                save_config(&cfg)?;
                println!();
                print_success("SUCCESS", "Plugin enabled successfully");
            } else {
                println!();
                print_info("INFO", "Plugin is already enabled");
            }
            Ok(())
        }
        PluginCmd::Config { name, params } => {
            let mut cfg = load_config().context("failed to load configuration")?;
            if params.is_empty() {
                let dir = config_dir().join("plugins").join(&name);
                if !dir.join("plugin.toml").exists() {
                    anyhow::bail!("plugin not found: {name}");
                }
                let manifest = PluginManifest::load(&dir)?;
                print_colored("CONFIG", "Plugin configuration");
                print_status("PLUGIN", &format!("Plugin: {}", name));
                println!();
                let plugin_cfg = cfg.plugins.get(&name);
                let mut seen = HashSet::new();
                if let Some(schema_file) = &manifest.config_schema {
                    let schema_path = dir.join(schema_file);
                    if let Ok(data) = fs::read_to_string(&schema_path) {
                        if let Ok(schema_json) = serde_json::from_str::<serde_json::Value>(&data) {
                            if let Some(props) =
                                schema_json.get("properties").and_then(|p| p.as_object())
                            {
                                for (key, prop) in props {
                                    seen.insert(key.clone());
                                    let default = prop
                                        .get("default")
                                        .map(|v| match v {
                                            serde_json::Value::String(s) => s.clone(),
                                            _ => v.to_string(),
                                        })
                                        .unwrap_or_else(|| "null".into());
                                    let current = plugin_cfg
                                        .and_then(|p| p.params.get(key))
                                        .map(|v| match v {
                                            toml::Value::String(s) => s.clone(),
                                            _ => v.to_string(),
                                        })
                                        .unwrap_or_else(|| default.clone());
                                    let allowed =
                                        prop.get("enum").and_then(|e| e.as_array()).map(|arr| {
                                            arr.iter()
                                                .map(|v| match v {
                                                    serde_json::Value::String(s) => s.clone(),
                                                    _ => v.to_string(),
                                                })
                                                .collect::<Vec<_>>()
                                                .join(", ")
                                        });
                                    if let Some(a) = allowed {
                                        if use_colored_output() {
                                            println!(
                                                "  {} = {} (allowed: {})",
                                                key.bright_white(),
                                                current.bright_green(),
                                                a.bright_white()
                                            );
                                        } else {
                                            println!("  {} = {} (allowed: {})", key, current, a);
                                        }
                                    } else {
                                        if use_colored_output() {
                                            println!(
                                                "  {} = {}",
                                                key.bright_white(),
                                                current.bright_green()
                                            );
                                        } else {
                                            println!("  {} = {}", key, current);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(cfg_params) = plugin_cfg.map(|p| &p.params) {
                    for (key, value) in cfg_params {
                        if seen.contains(key) {
                            continue;
                        }
                        let current = match value {
                            toml::Value::String(s) => s.clone(),
                            _ => value.to_string(),
                        };
                        if use_colored_output() {
                            println!("  {} = {}", key.bright_white(), current.bright_green());
                        } else {
                            println!("  {} = {}", key, current);
                        }
                    }
                }
                return Ok(());
            }
            let dir = config_dir().join("plugins").join(&name);
            if !dir.join("plugin.toml").exists() {
                anyhow::bail!("plugin not found: {name}");
            }
            let manifest = PluginManifest::load(&dir)?;
            let schema_props = if let Some(schema_file) = &manifest.config_schema {
                let schema_path = dir.join(schema_file);
                let data = fs::read_to_string(&schema_path).with_context(|| {
                    format!("failed to read config schema: {}", schema_path.display())
                })?;
                let schema_json: serde_json::Value = serde_json::from_str(&data)
                    .with_context(|| format!("invalid config schema: {}", schema_path.display()))?;
                schema_json
                    .get("properties")
                    .and_then(|p| p.as_object())
                    .cloned()
            } else {
                None
            };
            let info = PluginInfo {
                path: dir.clone(),
                manifest: manifest.clone(),
            };
            let entry = cfg.plugins.entry(name.clone()).or_default();
            for p in params {
                let (k, v) = p
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("invalid param '{p}', expected key=value"))?;
                let value = toml::from_str::<toml::Value>(v)
                    .unwrap_or_else(|_| toml::Value::String(v.into()));
                if let Some(props) = schema_props.as_ref() {
                    if !props.contains_key(k) {
                        anyhow::bail!("unknown option '{k}'");
                    }
                }
                let mut temp = entry.params.clone();
                temp.insert(k.to_string(), value.clone());
                if schema_props.is_some() {
                    let json_cfg = serde_json::to_value(&temp)?;
                    info.validate_config(&json_cfg)?;
                }
                entry.params = temp;
            }
            save_config(&cfg)?;
            if use_colored_output() {
                println!("Plugin '{}' configuration updated", name.bright_white());
            } else {
                println!("Plugin '{}' configuration updated", name);
            }
            Ok(())
        }
    }
}
