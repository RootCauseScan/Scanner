use std::ops::Deref;
use std::path::{Component, Path};

use anyhow::{Context, Result};
use plugin_core::{FileSpec, RepoDiscoverParams, RepoDiscoverResult};
use serde::de::DeserializeOwned;

use super::proc_plugin::ProcPlugin;

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

impl Deref for ManagedPlugin {
    type Target = ProcPlugin;

    fn deref(&self) -> &Self::Target {
        &self.plugin
    }
}

impl ManagedPlugin {
    pub(crate) fn new(
        plugin: ProcPlugin,
        needs_content: bool,
        reads_fs: bool,
        name: String,
        plugin_version: String,
    ) -> Self {
        Self {
            plugin,
            needs_content,
            reads_fs,
            name,
            plugin_version,
        }
    }

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
                    let normalized = Self::normalize_virtual_path(&f.path);
                    let hash = blake3::hash(normalized.as_bytes());
                    let hash_hex = hash.to_hex();
                    let short_hash = &hash_hex.as_str()[..12];
                    f.path = format!("/virtual/{name}-{short_hash}");
                    f
                })
                .collect()
        }
    }

    fn normalize_virtual_path(path: &str) -> String {
        let mut normalized: Vec<String> = Vec::new();
        for component in Path::new(path).components() {
            match component {
                Component::Prefix(prefix) => {
                    normalized.push(prefix.as_os_str().to_string_lossy().replace("\\", "/"))
                }
                Component::RootDir => normalized.push(String::new()),
                Component::CurDir => {}
                Component::ParentDir => normalized.push(String::from("..")),
                Component::Normal(part) => normalized.push(part.to_string_lossy().into_owned()),
            }
        }

        if normalized.is_empty() {
            path.replace("\\", "/")
        } else {
            normalized.join("/")
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
