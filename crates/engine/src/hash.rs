use blake3::hash;
use ir::FileIR;
use loader::{CompiledRule, RuleSet};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{analyze_files_with_config, cache::hash_file, EngineConfig, EngineMetrics, Finding};

#[derive(Default, Serialize, Deserialize)]
struct CacheData {
    files: HashMap<String, String>,
    rules: HashMap<String, String>,
    #[serde(default)]
    file_results: HashMap<String, Vec<Finding>>,
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

    /// Retrieves cached findings for a file, if available.
    pub fn get_file_results(&self, file: &FileIR) -> Option<&Vec<Finding>> {
        self.data.file_results.get(&file.file_path)
    }

    /// Stores the findings associated with a file.
    pub fn update_file_results(&mut self, file_path: String, findings: Vec<Finding>) {
        self.data.file_results.insert(file_path, findings);
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
        self.data.files.clear();
        self.data.file_results.clear();
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
    let mut cached_findings = Vec::new();
    let mut analyze_files: Vec<FileIR> = Vec::new();
    if rules_changed {
        analyze_files = files.to_vec();
    } else {
        for file in files {
            if cache.file_changed(file) {
                analyze_files.push(file.clone());
            } else if let Some(results) = cache.get_file_results(file) {
                cached_findings.extend(results.clone());
            }
        }
    }

    for f in &analyze_files {
        cache.update_file(f);
    }

    let analyzed_paths: Vec<String> = analyze_files.iter().map(|f| f.file_path.clone()).collect();
    let mut findings = if analyze_files.is_empty() {
        Vec::new()
    } else {
        analyze_files_with_config(&analyze_files, rules, cfg, None, metrics.take(), None)
    };

    if !analyze_files.is_empty() {
        let mut grouped: HashMap<String, Vec<Finding>> = HashMap::new();
        for finding in &findings {
            let key = finding.file.to_string_lossy().into_owned();
            grouped.entry(key).or_default().push(finding.clone());
        }
        for path in analyzed_paths {
            let results = grouped.remove(&path).unwrap_or_default();
            cache.update_file_results(path, results);
        }
    }

    if !cached_findings.is_empty() {
        cached_findings.append(&mut findings);
        findings = cached_findings;
    }

    cache.save();
    findings
}
