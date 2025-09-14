use plugin_core::{Context, Plugin, PluginInfo, PluginManager, PluginManifest, API_VERSION};
use serde_json::Value;

struct Dummy;

impl Plugin for Dummy {
    fn execute(&self, _ctx: &Context) {}
}

fn manifest() -> PluginManifest {
    PluginManifest {
        name: Some("dummy".into()),
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

#[test]
fn lists_registered_plugins() {
    let mut manager = PluginManager::new();
    let info = PluginInfo {
        path: std::path::PathBuf::from("."),
        manifest: manifest(),
    };
    manager.register_plugin(info, &Value::Null, Dummy).unwrap();

    let listado = manager.list_plugins();
    assert_eq!(listado.len(), 1);
    assert_eq!(listado[0].0.as_deref(), Some("dummy"));
    assert_eq!(listado[0].1.as_deref(), Some("0.1.0"));
    assert_eq!(listado[0].2, vec!["transform".to_string()]);
}
