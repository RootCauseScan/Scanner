//! User interface functions for the CLI.
//! Contains helpers for displaying headers, help, and other visual elements.

use tracing::info;

pub fn print_header() {
    let version = env!("CARGO_PKG_VERSION");
    // Avoid panics when the version exceeds the expected width
    let spaces = " ".repeat(24usize.saturating_sub(version.len()));
    eprintln!(
        r#"
    ╭──────────────────────────────────────╮
    │                                      │
    │     🐾  ROOTCAUSE  SAST  TOOL  🐾    │
    │                                      │
    │     Static Analysis Security         │
    │     Testing for Multi-lang           │
    │     Version: {version}{spaces}│
    │                                      │
    ╰──────────────────────────────────────╯
"#
    );
}

pub fn print_plugin_status(plugins: &[String]) {
    if !plugins.is_empty() {
        for plugin in plugins {
            info!("Plugin '{}' loaded successfully", plugin);
        }
    }
}
