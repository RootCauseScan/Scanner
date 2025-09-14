use shlex::Shlex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use jsonschema::JSONSchema;
use serde::Deserialize;
use serde_json::Value;

const VALID_CAPABILITIES: &[&str] = &["discover", "transform", "analyze", "report", "rules"];

#[cfg(windows)]
fn config_dir() -> Option<PathBuf> {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .ok()
        .map(|p| p.join("rootcause"))
}

#[cfg(not(windows))]
fn config_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .ok()
        .map(|p| p.join(".config").join("rootcause"))
}

fn disabled_plugins() -> HashSet<String> {
    #[derive(Deserialize)]
    struct PluginCfg {
        enabled: Option<bool>,
    }
    #[derive(Deserialize, Default)]
    struct Cfg {
        #[serde(default)]
        plugins: HashMap<String, PluginCfg>,
    }
    let mut set = HashSet::new();
    if let Some(dir) = config_dir() {
        let path = dir.join("config.toml");
        if let Ok(data) = fs::read_to_string(path) {
            if let Ok(cfg) = toml::from_str::<Cfg>(&data) {
                for (name, pc) in cfg.plugins {
                    if !pc.enabled.unwrap_or(true) {
                        set.insert(name);
                    }
                }
            }
        }
    }
    set
}

#[derive(Debug, Deserialize, Clone)]
pub struct PluginManifest {
    pub name: Option<String>,
    pub version: Option<String>,
    pub api_version: String,
    pub entry: String,
    pub capabilities: Vec<String>,
    pub concurrency: Option<String>,
    pub timeout_ms: Option<u64>,
    pub mem_mb: Option<u64>,
    pub reads_fs: Option<bool>,
    pub needs_content: Option<bool>,
    pub config_schema: Option<String>,
}

impl PluginManifest {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("plugin.toml");
        let data = fs::read_to_string(&path)
            .with_context(|| format!("failed to read manifest: {}", path.display()))?;
        let manifest: PluginManifest = toml::from_str(&data)
            .with_context(|| format!("failed to parse manifest: {}", path.display()))?;
        manifest.validate(dir)?;
        Ok(manifest)
    }

    fn validate(&self, dir: &Path) -> Result<()> {
        let major = self.api_version.split(['.', '-']).next().unwrap_or("");
        if major != "1" {
            anyhow::bail!("unsupported api_version {}", self.api_version);
        }
        if self.entry.trim().is_empty() {
            anyhow::bail!("missing entry");
        }
        let parts: Vec<String> = Shlex::new(&self.entry).collect();
        if parts.is_empty() {
            anyhow::bail!("missing entry");
        }
        let found = parts.iter().any(|p| dir.join(p).exists());
        if !found {
            anyhow::bail!("entry path not found: {}", self.entry);
        }
        if self.capabilities.is_empty()
            || self
                .capabilities
                .iter()
                .any(|c| !VALID_CAPABILITIES.contains(&c.as_str()))
        {
            anyhow::bail!("invalid capabilities");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub path: PathBuf,
    pub manifest: PluginManifest,
}

impl PluginInfo {
    fn from_dir(dir: &Path) -> Result<Self> {
        Ok(Self {
            path: dir.to_path_buf(),
            manifest: PluginManifest::load(dir)?,
        })
    }

    pub fn validate_config(&self, cfg: &Value) -> Result<()> {
        if let Some(schema) = &self.manifest.config_schema {
            let schema_path = self.path.join(schema);
            let data = fs::read_to_string(&schema_path).with_context(|| {
                format!("failed to read config schema: {}", schema_path.display())
            })?;
            let schema_json: Value = serde_json::from_str(&data)
                .with_context(|| format!("invalid config schema: {}", schema_path.display()))?;
            let schema_ref: &'static Value = Box::leak(Box::new(schema_json));
            let compiled = JSONSchema::compile(schema_ref).context("invalid config schema")?;
            let result = compiled.validate(cfg);
            if let Err(errors) = result {
                let msg = errors.map(|e| e.to_string()).collect::<Vec<_>>().join(", ");
                anyhow::bail!("invalid config: {msg}");
            }
        }
        Ok(())
    }
}

pub fn discover_plugins(explicit: &[PathBuf]) -> Result<Vec<PluginInfo>> {
    let disabled = disabled_plugins();
    let base = std::env::current_exe()?
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut roots: Vec<PathBuf> = explicit.to_vec();
    roots.push(base.join("plugins"));
    roots.push(PathBuf::from(".rootcause/plugins"));
    if let Some(dir) = config_dir() {
        roots.push(dir.join("plugins"));
    }
    roots.push(PathBuf::from("/usr/local/lib/rootcause/plugins"));

    let mut candidates = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        if root.is_file() {
            let dir = root.parent().unwrap_or(&root).to_path_buf();
            if dir.join("plugin.toml").is_file() {
                candidates.push(dir);
            }
            continue;
        }
        if root.join("plugin.toml").is_file() {
            candidates.push(root);
            continue;
        }
        for entry in fs::read_dir(root)? {
            let path = entry?.path();
            if path.is_dir() && path.join("plugin.toml").is_file() {
                candidates.push(path);
            }
        }
    }

    // Deduplicate by plugin name so the same plugin found in multiple roots is not loaded twice.
    // Later candidates take precedence to respect the search order above.
    let mut by_name: std::collections::HashMap<String, PluginInfo> =
        std::collections::HashMap::new();
    for dir in candidates {
        let info = PluginInfo::from_dir(&dir)?;
        let name = info
            .manifest
            .name
            .clone()
            .or_else(|| {
                dir.file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        if disabled.contains(&name) {
            continue;
        }
        by_name.insert(name, info);
    }

    Ok(by_name.into_values().collect())
}
