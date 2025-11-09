pub mod rule_cache;

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::Finding;
use ir::FileIR;

#[derive(Default, Serialize, Deserialize)]
pub struct AnalysisCache {
    entries: HashMap<String, Vec<Finding>>,
    #[serde(default)]
    rules_hash: Option<String>,
}

impl AnalysisCache {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) {
        if let Ok(s) = serde_json::to_string(self) {
            let _ = fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")));
            let _ = fs::write(path, s);
        }
    }

    pub fn get(&self, key: &str) -> Option<&Vec<Finding>> {
        self.entries.get(key)
    }

    pub fn insert(&mut self, key: String, findings: Vec<Finding>, rules_hash: &str) {
        self.rules_hash = Some(rules_hash.to_owned());
        self.entries.insert(key, findings);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn rules_hash(&self) -> Option<&str> {
        self.rules_hash.as_deref()
    }

    pub fn set_rules_hash(&mut self, hash: String) {
        self.rules_hash = Some(hash);
    }
}

pub fn hash_file(file: &FileIR) -> String {
    let mut hasher = Hasher::new();
    hasher.update(file.file_type.as_bytes());
    hasher.update(b"\0");
    hasher.update(file.file_path.as_bytes());
    hasher.update(b"\0");
    if let Some(source) = &file.source {
        hasher.update(source.as_bytes());
    } else {
        let bytes = serde_json::to_vec(&file.nodes).unwrap_or_default();
        hasher.update(&bytes);
    }
    hasher.finalize().to_hex().to_string()
}
