use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use plugin_core::discover_plugins;
use plugin_core::Limits;
use serde_json::Value;
use shlex::Shlex;
use tracing::info;

use super::managed::ManagedPlugin;
use super::proc_plugin::ProcPlugin;

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
                    Ok(Some(ManagedPlugin::new(
                        plugin,
                        needs_content,
                        reads_fs,
                        plugin_name.to_string(),
                        plugin_version,
                    )))
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
