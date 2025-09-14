use blake3::hash;
use ir::FileIR;
use loader::{CompiledRule, RuleSet};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{analyze_files_with_config, EngineConfig, EngineMetrics, Finding};

#[derive(Default, Serialize, Deserialize)]
struct CacheData {
    files: HashMap<String, String>,
    rules: HashMap<String, String>,
}

/// Stores hashes of files and rules to avoid analysing unchanged entries.
///
/// Entries are invalidated when the file content or rule definition
/// differs from the stored hash.
pub struct HashCache {
    path: PathBuf,
    data: CacheData,
}

impl HashCache {
    /// Loads the cache from disk; if the file doesn't exist or is corrupted,
    /// returns an empty cache.
    pub fn load(path: &Path) -> Self {
        let data = fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<CacheData>(&s).ok())
            .unwrap_or_default();
        Self {
            path: path.to_path_buf(),
            data,
        }
    }

    /// Indicates whether the file hash changed or doesn't exist in the cache.
    ///
    /// `true` means the entry is invalidated and must be re-analysed.
    pub fn file_changed(&self, file: &FileIR) -> bool {
        let h = hash_file(file);
        self.data
            .files
            .get(&file.file_path)
            .map(|old| old != &h)
            .unwrap_or(true)
    }

    /// Updates the hash of a file after analysing it.
    pub fn update_file(&mut self, file: &FileIR) {
        let h = hash_file(file);
        self.data.files.insert(file.file_path.clone(), h);
    }

    /// Checks if the rule set differs from the stored cache.
    ///
    /// Changes in rules invalidate all previously analysed files.
    pub fn rules_changed(&self, rules: &RuleSet) -> bool {
        if rules.rules.len() != self.data.rules.len() {
            return true;
        }
        for r in &rules.rules {
            let h = hash_rule(r);
            if self.data.rules.get(&r.id) != Some(&h) {
                return true;
            }
        }
        false
    }

    /// Replaces the stored rule hashes with those from the current set.
    pub fn update_rules(&mut self, rules: &RuleSet) {
        self.data.rules.clear();
        for r in &rules.rules {
            let h = hash_rule(r);
            self.data.rules.insert(r.id.clone(), h);
        }
    }

    /// Persists the cache state to disk.
    pub fn save(&self) {
        if let Ok(s) = serde_json::to_string(&self.data) {
            let _ = fs::write(&self.path, s);
        }
    }
}

fn hash_file(file: &FileIR) -> String {
    let bytes = serde_json::to_vec(file).unwrap_or_default();
    hash(&bytes).to_hex().to_string()
}

fn hash_rule(rule: &CompiledRule) -> String {
    hash(format!("{rule:?}").as_bytes()).to_hex().to_string()
}

/// Analyses files using a hash-based cache.
///
/// If rules don't change, only files whose content differs from the stored hash
/// are reprocessed. Any change in rules invalidates all files.
pub fn analyze_files_cached(
    files: &[FileIR],
    rules: &RuleSet,
    cache_path: &Path,
    cfg: &EngineConfig,
    mut metrics: Option<&mut EngineMetrics>,
) -> Vec<Finding> {
    let mut cache = HashCache::load(cache_path);
    let rules_changed = cache.rules_changed(rules);
    if rules_changed {
        cache.update_rules(rules);
    }
    let analyze_files: Vec<FileIR> = if rules_changed {
        files.to_vec()
    } else {
        files
            .iter()
            .filter(|f| cache.file_changed(f))
            .cloned()
            .collect()
    };
    for f in &analyze_files {
        cache.update_file(f);
    }
    let findings = analyze_files_with_config(&analyze_files, rules, cfg, None, metrics.take());
    cache.save();
    findings
}
