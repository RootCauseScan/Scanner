use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Parameters sent to the plugin during `plugin.init`.
/// Includes session information and execution limits.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginInit {
    /// API version expected by the host.
    pub api_version: String,
    /// Unique session identifier.
    pub session_id: String,
    /// Root of the analysed workspace.
    pub workspace_root: String,
    /// Root of the rules directory.
    pub rules_root: String,
    /// Capabilities requested from the plugin.
    pub capabilities_requested: Vec<String>,
    /// Plugin-specific options.
    #[serde(default)]
    pub options: Value,
    /// Granted resource limits.
    #[serde(default)]
    pub limits: Option<Limits>,
    /// Provided environment variables.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Current working directory
    #[serde(default)]
    pub cwd: String,
}

/// Response received after invoking `plugin.init`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginInitResponse {
    /// Indicates whether the initialisation was successful.
    pub ok: bool,
    /// Capabilities reported by the plugin.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Declared plugin version.
    #[serde(default)]
    pub plugin_version: String,
}

/// Time and memory limits for the plugin.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Limits {
    /// Maximum CPU time in milliseconds.
    #[serde(default)]
    pub cpu_ms: Option<u64>,
    /// Maximum memory in megabytes.
    #[serde(default)]
    pub mem_mb: Option<u64>,
}

/// Representation of a file handled by the plugin.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct FileSpec {
    /// Relative path within the workspace.
    pub path: String,
    /// SHA-256 hash of the content.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Detected or assumed language.
    #[serde(default)]
    pub language: Option<String>,
    /// Content in base64 when it needs to be transmitted.
    ///
    /// If omitted, the plugin can read the file directly from
    /// [`path`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_b64: Option<String>,
    /// Size in bytes of the original file.
    #[serde(default)]
    pub size: Option<u64>,
}

/// File transformation request (`file.transform`).
#[derive(Debug, Serialize, Deserialize)]
pub struct FileTransform {
    /// Set of files to be processed by the plugin.
    pub files: Vec<FileSpec>,
}

/// File analysis request (`file.analyze`).
#[derive(Debug, Serialize, Deserialize)]
pub struct FileAnalyze {
    /// Set of files to evaluate.
    pub files: Vec<FileSpec>,
}

/// Parameters for repository discovery (`repo.discover`).
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct RepoDiscoverParams {
    /// Base path to start scanning from (relative to workspace_root).
    #[serde(default)]
    pub path: String,
    /// File extensions to include (e.g., [".js", ".py"]).
    /// Empty means implementation-defined defaults.
    #[serde(default)]
    pub extensions: Vec<String>,
    /// Optional maximum directory depth to traverse.
    #[serde(default)]
    pub max_depth: Option<u32>,
}

/// Result for repository discovery (`repo.discover`).
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct RepoDiscoverResult {
    /// Files found within the workspace.
    #[serde(default)]
    pub files: Vec<FileSpec>,
    /// External dependencies or files outside the workspace boundary.
    /// Represented using FileSpec for uniformity (path/language/size optional).
    #[serde(default)]
    pub external: Vec<FileSpec>,
    /// Optional metrics or additional information provided by the plugin.
    #[serde(default)]
    pub metrics: Value,
}

/// Generic successfully processed response.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginResult<T> {
    /// JSON-RPC version used.
    #[serde(default = "jsonrpc_version")]
    pub jsonrpc: String,
    /// Correlative message identifier.
    pub id: String,
    /// Specific result of the invoked method.
    pub result: T,
}

fn jsonrpc_version() -> String {
    "2.0".to_string()
}

/// Error emitted by the plugin following JSON-RPC.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginError {
    /// Numeric code that identifies the error condition.
    pub code: i64,
    /// Readable message associated with the error.
    pub message: String,
    /// Optional additional data.
    #[serde(default)]
    pub data: Option<Value>,
}

/// Log message emitted by the plugin to the host.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginLog {
    /// Optional message level (`trace`, `debug`, `info`, `warn`, `error`).
    #[serde(default)]
    pub level: Option<String>,
    /// Text to log.
    pub message: String,
}

/// `plugin.log` call sent by the plugin.
#[derive(Debug, Serialize, Deserialize)]
pub struct PluginLogCall {
    /// Protocol version (ignored).
    #[serde(default)]
    pub jsonrpc: Option<String>,
    /// Method name, must be `plugin.log`.
    pub method: String,
    /// Log parameters.
    pub params: PluginLog,
}
