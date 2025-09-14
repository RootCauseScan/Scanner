use blake3::hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::Finding;
use ir::FileIR;

#[derive(Default, Serialize, Deserialize)]
pub struct AnalysisCache {
    entries: HashMap<String, Vec<Finding>>,
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

    pub fn insert(&mut self, key: String, findings: Vec<Finding>) {
        self.entries.insert(key, findings);
    }
}

pub fn hash_file(file: &FileIR) -> String {
    let bytes = serde_json::to_vec(file).unwrap_or_default();
    hash(&bytes).to_hex().to_string()
}
