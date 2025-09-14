use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf};
use toml::Value as TomlValue;

#[cfg(windows)]
pub fn config_dir() -> PathBuf {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("rootcause")
}

#[cfg(not(windows))]
pub fn config_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".config")
        .join("rootcause")
}

fn config_file_path() -> PathBuf {
    config_dir().join("config.toml")
}

fn default_enabled() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
pub struct PluginConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(flatten)]
    #[serde(default)]
    pub params: HashMap<String, TomlValue>,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            params: HashMap::new(),
        }
    }
}

fn default_rule_dirs() -> Vec<PathBuf> {
    vec![config_dir().join("rules")]
}

#[derive(Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default = "default_rule_dirs")]
    pub rule_dirs: Vec<PathBuf>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            rule_dirs: default_rule_dirs(),
        }
    }
}

fn default_cache_dir() -> PathBuf {
    PathBuf::from("./cache")
}

#[derive(Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: default_cache_dir(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub plugins: HashMap<String, PluginConfig>,
    #[serde(default)]
    pub rules: RuleConfig,
    #[serde(default)]
    pub cache: CacheConfig,
}

pub fn load_config() -> Result<Config> {
    let path = config_file_path();
    if path.exists() {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&content).context("failed to parse config")
    } else {
        Ok(Config::default())
    }
}

pub fn save_config(config: &Config) -> Result<()> {
    let path = config_file_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    let data = toml::to_string_pretty(config).context("failed to serialize config")?;
    fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))
}
