use std::fs;

use plugin_core::{discover_plugins, API_VERSION};
use tempfile::TempDir;

#[test]
fn supported_api_version_loads() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("plugin.toml"),
        format!(
            "name = \"demo\"\nversion = \"0.1.0\"\napi_version = \"{API_VERSION}\"\nentry = \"run.sh\"\ncapabilities = [\"transform\"]\n"
        ),
    )
    .unwrap();
    fs::write(tmp.path().join("run.sh"), "#!/bin/sh\n").unwrap();

    let plugins = discover_plugins(&[tmp.path().to_path_buf()]).unwrap();
    assert_eq!(plugins.len(), 1);
    assert_eq!(
        plugins[0].manifest.capabilities,
        vec!["transform".to_string()]
    );
}

#[test]
fn unsupported_api_version_fails() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("plugin.toml"),
        "api_version = \"2.0.0\"\nentry = \"run.sh\"\ncapabilities = [\"transform\"]\n",
    )
    .unwrap();
    fs::write(tmp.path().join("run.sh"), "").unwrap();
    let err = discover_plugins(&[tmp.path().to_path_buf()]).unwrap_err();
    assert!(err.to_string().contains("unsupported api_version"));
}

#[test]
fn disabled_plugins_are_skipped() {
    let tmp = TempDir::new().unwrap();
    fs::write(
        tmp.path().join("plugin.toml"),
        format!(
            "name = \"demo\"\nversion = \"0.1.0\"\napi_version = \"{API_VERSION}\"\nentry = \"run.sh\"\ncapabilities = [\"transform\"]\n"
        ),
    )
    .unwrap();
    fs::write(tmp.path().join("run.sh"), "#!/bin/sh\n").unwrap();

    let home = TempDir::new().unwrap();
    let old_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", home.path());
    let config_dir = home.path().join(".config/rootcause");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[plugins.demo]\nenabled = false\n",
    )
    .unwrap();

    let plugins = discover_plugins(&[tmp.path().to_path_buf()]).unwrap();
    assert!(plugins.is_empty());

    if let Some(h) = old_home {
        std::env::set_var("HOME", h);
    }
}
