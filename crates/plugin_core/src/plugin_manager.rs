//! Simple plugin manager.
//!
//! Provides a [`PluginManager`] capable of registering, initializing, and executing [`Plugin`]s.
//! Emits structured logs at each lifecycle stage to aid debugging
//! and observability.
//!
//! # Extensión
//!
//! The manager can be extended by adding new loading strategies or
//! custom validations. For example, a manifest could be parsed
//! before registering each plugin or support different discovery mechanisms
//! (TOML files, dynamic binaries, etc.). These strategies
//! can be implemented by extending [`load_plugins_from_dir`] or adding
//! similar functions that ultimately invoke [`register_plugin`].

use std::fs;
use std::path::Path;

use tracing::{error, info};

use crate::{Context, Plugin, PluginInfo, PluginManifest};
use serde_json::Value;

/// Coordina la vida útil de los plugins cargados.
pub struct PluginManager {
    plugins: Vec<(PluginManifest, Box<dyn Plugin + Send + Sync>)>,
}

struct ManifestPlugin {
    manifest: PluginManifest,
}

impl ManifestPlugin {
    fn new(manifest: PluginManifest) -> Self {
        Self { manifest }
    }
}

impl Plugin for ManifestPlugin {
    fn init(&self) {
        info!(
            etapa = "init",
            plugin = self.manifest.name.as_deref().unwrap_or("anon")
        );
    }

    fn execute(&self, _ctx: &Context) {
        info!(
            etapa = "ejecucion",
            plugin = self.manifest.name.as_deref().unwrap_or("anon")
        );
        #[cfg(test)]
        EXEC_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
static EXEC_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn reset_exec_count() {
    EXEC_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn exec_count() -> usize {
    EXEC_COUNT.load(std::sync::atomic::Ordering::SeqCst)
}

impl PluginManager {
    /// Crea un administrador vacío.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Registra e inicializa un plugin en el administrador.
    pub fn register_plugin<P>(
        &mut self,
        info: PluginInfo,
        cfg: &Value,
        plugin: P,
    ) -> anyhow::Result<()>
    where
        P: Plugin + Send + Sync + 'static,
    {
        let ty = std::any::type_name::<P>();
        info!(etapa = "registro", plugin = ty);
        info.validate_config(cfg)?;
        plugin.init();
        info!(etapa = "inicializacion", plugin = ty);
        self.plugins.push((info.manifest, Box::new(plugin)));
        Ok(())
    }

    /// Loads plugins from a directory.
    ///
    /// The current implementation only traverses the folder to illustrate how
    /// it could be extended in the future. More complex strategies can validate
    /// manifests or load dynamic libraries before invoking
    /// [`register_plugin`].
    pub fn load_plugins_from_dir(&mut self, dir: &Path) -> std::io::Result<()> {
        info!(etapa = "carga", ruta = %dir.display());
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            info!(etapa = "descubrimiento", plugin = %path.display());
            match PluginManifest::load(&path) {
                Ok(manifest) => {
                    let info = PluginInfo {
                        path: path.clone(),
                        manifest: manifest.clone(),
                    };
                    let plugin = ManifestPlugin::new(manifest);
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.register_plugin(info, &Value::Null, plugin)
                    })) {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            error!(
                                etapa = "inicializacion",
                                plugin = %path.display(),
                                error = %e
                            );
                        }
                        Err(_) => error!(
                            etapa = "inicializacion",
                            plugin = %path.display(),
                            "fallo al registrar plugin"
                        ),
                    }
                }
                Err(e) => error!(
                    etapa = "manifiesto",
                    plugin = %path.display(),
                    error = %e
                ),
            }
        }
        Ok(())
    }

    /// Executes an event over all registered plugins.
    ///
    /// Returns the indices of plugins that failed during execution so
    /// the consumer can react or report the detected problems.
    pub fn dispatch_event(&self, evento: &str, ctx: &Context) -> Vec<usize> {
        info!(etapa = "ejecucion", evento, total = self.plugins.len());
        let mut fallos = Vec::new();
        for (idx, (_, plugin)) in self.plugins.iter().enumerate() {
            info!(etapa = "ejecucion", plugin = idx, evento);
            if let Err(err) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                plugin.execute(ctx);
            })) {
                let msg = if let Some(s) = err.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "panic sin mensaje".to_string()
                };
                error!(etapa = "ejecucion", plugin = idx, evento, error = %msg);
                fallos.push(idx);
            }
        }
        fallos
    }

    /// Lists basic information about registered plugins.
    pub fn list_plugins(&self) -> Vec<(Option<String>, Option<String>, Vec<String>)> {
        self.plugins
            .iter()
            .map(|(m, _)| (m.name.clone(), m.version.clone(), m.capabilities.clone()))
            .collect()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PluginInfo;
    use crate::API_VERSION;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct Dummy {
        count: Arc<Mutex<u32>>,
    }

    impl Plugin for Dummy {
        fn execute(&self, _ctx: &Context) {
            let mut c = self.count.lock().unwrap();
            *c += 1;
        }
    }

    #[test]
    fn register_and_dispatch() {
        let counter = Arc::new(Mutex::new(0));
        let dummy = Dummy {
            count: counter.clone(),
        };

        let mut manager = PluginManager::new();
        let info = PluginInfo {
            path: PathBuf::from("."),
            manifest: test_manifest("dummy"),
        };
        manager.register_plugin(info, &Value::Null, dummy).unwrap();

        let ctx = Context;
        let fallos = manager.dispatch_event("ping", &ctx);

        assert!(fallos.is_empty());
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[test]
    fn load_and_execute_valid_plugin() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("demo");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("plugin.toml"),
            format!("name=\"demo\"\nversion=\"0.1.0\"\napi_version=\"{API_VERSION}\"\nentry=\"run.sh\"\ncapabilities=[\"transform\"]\n"),
        )
        .unwrap();
        fs::write(dir.join("run.sh"), "#!/bin/sh\n").unwrap();

        let mut manager = PluginManager::new();
        super::reset_exec_count();
        manager.load_plugins_from_dir(tmp.path()).unwrap();
        assert_eq!(manager.plugins.len(), 1);

        let ctx = Context;
        let fallos = manager.dispatch_event("ping", &ctx);
        assert!(fallos.is_empty());
        assert_eq!(super::exec_count(), 1);
    }

    #[test]
    fn continues_after_panic() {
        struct PanicPlugin;

        impl Plugin for PanicPlugin {
            fn execute(&self, _ctx: &Context) {
                panic!("boom");
            }
        }

        let counter = Arc::new(Mutex::new(0));
        let dummy = Dummy {
            count: counter.clone(),
        };

        let mut manager = PluginManager::new();
        let info1 = PluginInfo {
            path: PathBuf::from("."),
            manifest: test_manifest("panic"),
        };
        manager
            .register_plugin(info1, &Value::Null, PanicPlugin)
            .unwrap();
        let info2 = PluginInfo {
            path: PathBuf::from("."),
            manifest: test_manifest("dummy"),
        };
        manager.register_plugin(info2, &Value::Null, dummy).unwrap();

        let ctx = Context;
        let fallos = manager.dispatch_event("ping", &ctx);

        assert_eq!(fallos, vec![0]);
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    fn test_manifest(name: &str) -> PluginManifest {
        PluginManifest {
            name: Some(name.to_string()),
            version: Some("0.1.0".into()),
            api_version: API_VERSION.into(),
            entry: "run.sh".into(),
            capabilities: vec!["transform".into()],
            concurrency: None,
            timeout_ms: None,
            mem_mb: None,
            reads_fs: None,
            needs_content: None,
            config_schema: None,
        }
    }
}
