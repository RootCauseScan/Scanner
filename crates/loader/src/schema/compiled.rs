use crate::matchers::MatcherKind;
use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::debug;

pub const GENERIC_LANGUAGE: &str = "generic";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
/// Severity associated with a rule or finding.
pub enum Severity {
    Info,
    Error,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Error => "ERROR",
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "error" => Ok(Severity::Error),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            "warning" => Ok(Severity::Medium),
            other => Err(format!("unknown severity '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Example cases for a rule, useful in documentation.
pub struct Example {
    pub bad: Option<String>,
    pub good: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleOptions {
    #[serde(default)]
    pub interfile: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Query on the AST when structural analysis is required.
pub struct AstQueryRule {
    pub kind: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
/// Representation ready for rule execution.
pub struct CompiledRule {
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub remediation: Option<String>,
    pub fix: Option<String>,
    pub interfile: bool,
    pub matcher: MatcherKind,
    pub source_file: Option<String>,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub languages: Vec<String>,
}

impl CompiledRule {
    pub fn applies_to(&self, file_type: &str) -> bool {
        let trimmed = file_type.trim();
        if self.languages.iter().any(|lang| lang == GENERIC_LANGUAGE) {
            return true;
        }
        if trimmed.is_empty() {
            return false;
        }
        self.languages
            .iter()
            .any(|lang| lang.eq_ignore_ascii_case(trimmed))
    }
}

#[derive(Debug, Clone, Default)]
/// Collection of compiled rules.
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
}

pub(crate) fn normalize_languages(langs: Option<Vec<String>>) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    if let Some(list) = langs {
        for lang in list {
            let trimmed = lang.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_lowercase();
            if seen.insert(lower.clone()) {
                normalized.push(lower);
            }
        }
    }
    if normalized.is_empty() {
        normalized.push(GENERIC_LANGUAGE.to_string());
    }
    normalized
}

pub(crate) fn log_rule_summary(rule: &CompiledRule) {
    if !tracing::level_enabled!(tracing::Level::DEBUG) {
        return;
    }
    match &rule.matcher {
        MatcherKind::TaintRule {
            sources,
            sanitizers,
            reclass,
            sinks,
        } => {
            debug!(
                rule_id = %rule.id,
                matcher = "taint",
                sources = sources.len(),
                sinks = sinks.len(),
                sanitizers = sanitizers.len(),
                reclass = reclass.len(),
                message = %rule.message,
                file = ?rule.source_file,
                "compiled taint rule"
            );
            for (idx, tp) in sources.iter().enumerate() {
                debug!(
                    rule_id = %rule.id,
                    kind = "source",
                    index = idx,
                    allow = tp.allow.len(),
                    allow_focus = ?tp.allow_focus_groups,
                    inside = tp.inside.len(),
                    inside_focus = ?tp.inside_focus_groups,
                    not_inside = tp.not_inside.len(),
                    focus = ?tp.focus,
                    "taint source pattern"
                );
            }
            for (idx, tp) in sinks.iter().enumerate() {
                debug!(
                    rule_id = %rule.id,
                    kind = "sink",
                    index = idx,
                    allow = tp.allow.len(),
                    inside = tp.inside.len(),
                    not_inside = tp.not_inside.len(),
                    focus = ?tp.focus,
                    "taint sink pattern"
                );
            }
        }
        MatcherKind::TextRegex(_, pat) => {
            debug!(
                rule_id = %rule.id,
                matcher = "text_regex",
                message = %rule.message,
                file = ?rule.source_file,
                pattern = %pat,
                "compiled text regex rule"
            );
        }
        MatcherKind::TextRegexMulti {
            allow,
            deny,
            inside,
            not_inside,
        } => {
            debug!(
                rule_id = %rule.id,
                matcher = "text_regex_multi",
                message = %rule.message,
                file = ?rule.source_file,
                allow = allow.len(),
                deny = deny.is_some(),
                inside = inside.len(),
                not_inside = not_inside.len(),
                "compiled contextual text rule"
            );
        }
        MatcherKind::JsonPathEq(path, _) => {
            debug!(
                rule_id = %rule.id,
                matcher = "json_eq",
                message = %rule.message,
                file = ?rule.source_file,
                json_path = %path,
                "compiled JSON equality rule"
            );
        }
        MatcherKind::JsonPathRegex(path, _) => {
            debug!(
                rule_id = %rule.id,
                matcher = "json_regex",
                message = %rule.message,
                file = ?rule.source_file,
                json_path = %path,
                "compiled JSON regex rule"
            );
        }
        MatcherKind::AstQuery(query) => {
            debug!(
                rule_id = %rule.id,
                matcher = "ast_query",
                message = %rule.message,
                file = ?rule.source_file,
                query_kind = ?query.kind,
                query_value = ?query.value,
                "compiled AST query rule"
            );
        }
        MatcherKind::AstPattern(ast) => {
            debug!(
                rule_id = %rule.id,
                matcher = "ast_pattern",
                message = %rule.message,
                file = ?rule.source_file,
                ast_kind = %ast.kind,
                "compiled AST rule"
            );
        }
        MatcherKind::RegoWasm {
            wasm_path,
            entrypoint,
        } => {
            debug!(
                rule_id = %rule.id,
                matcher = "rego_wasm",
                message = %rule.message,
                file = ?rule.source_file,
                wasm = %wasm_path,
                entrypoint,
                "compiled Rego WASM rule"
            );
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WasmMeta {
    pub id: String,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub message: Option<String>,
    pub remediation: Option<String>,
    pub fix: Option<String>,
    pub entrypoint: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_languages")]
    pub languages: Option<Vec<String>>,
}

const MAX_WASM_BYTES: u64 = 10 * 1024 * 1024; // 10MB limit

pub(crate) fn compile_wasm_rule(
    rs: &mut RuleSet,
    seen: &mut HashSet<String>,
    wasm_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    let meta = fs::metadata(wasm_path)
        .with_context(|| format!("Failed to read rule file metadata: {}", wasm_path.display()))?;
    if meta.len() < 8 || meta.len() > MAX_WASM_BYTES {
        bail!("Invalid WASM module size");
    }

    // Check magic header and version
    let mut file = fs::File::open(wasm_path)
        .with_context(|| format!("Failed to open rule file: {}", wasm_path.display()))?;
    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .with_context(|| format!("Failed to read rule header: {}", wasm_path.display()))?;
    if &header[0..4] != b"\0asm" || header[4..8] != [0x01, 0x00, 0x00, 0x00] {
        bail!("Invalid WASM module signature");
    }

    // Try to load metadata from sidecar file (module.wasm.json/yaml/yml)
    let meta_path_json = wasm_sidecar_path(wasm_path, "json");
    let meta_path_yaml = wasm_sidecar_path(wasm_path, "yaml");
    let meta_path_yml = wasm_sidecar_path(wasm_path, "yml");

    let mut meta_info: Option<WasmMeta> = None;
    if meta_path_json.exists() {
        let data = fs::read_to_string(&meta_path_json).with_context(|| {
            format!(
                "Failed to read WASM metadata file: {}",
                meta_path_json.display()
            )
        })?;
        meta_info = Some(serde_json::from_str(&data).with_context(|| {
            format!(
                "Failed to parse WASM metadata: {}",
                meta_path_json.display()
            )
        })?);
    } else if meta_path_yaml.exists() {
        let data = fs::read_to_string(&meta_path_yaml).with_context(|| {
            format!(
                "Failed to read WASM metadata file: {}",
                meta_path_yaml.display()
            )
        })?;
        meta_info = Some(serde_yaml::from_str(&data).with_context(|| {
            format!(
                "Failed to parse WASM metadata: {}",
                meta_path_yaml.display()
            )
        })?);
    } else if meta_path_yml.exists() {
        let data = fs::read_to_string(&meta_path_yml).with_context(|| {
            format!(
                "Failed to read WASM metadata file: {}",
                meta_path_yml.display()
            )
        })?;
        meta_info = Some(serde_yaml::from_str(&data).with_context(|| {
            format!("Failed to parse WASM metadata: {}", meta_path_yml.display())
        })?);
    }

    let default_id = wasm_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "wasm".into());
    let meta = meta_info.unwrap_or(WasmMeta {
        id: default_id.clone(),
        severity: None,
        category: None,
        message: None,
        remediation: None,
        fix: None,
        entrypoint: None,
        languages: None,
    });

    let rule_id = meta.id;
    if !seen.insert(rule_id.clone()) {
        bail!("duplicate rule id: {rule_id}");
    }
    let severity = meta
        .severity
        .as_deref()
        .unwrap_or("MEDIUM")
        .parse()
        .map_err(|e: String| anyhow!(e))?;
    let source_file = wasm_path
        .strip_prefix(base_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let languages = normalize_languages(meta.languages.clone());
    rs.rules.push(CompiledRule {
        id: rule_id,
        severity,
        category: meta.category.unwrap_or_else(|| "wasm".into()),
        message: meta.message.unwrap_or_default(),
        remediation: meta.remediation,
        fix: meta.fix,
        interfile: false,
        matcher: MatcherKind::RegoWasm {
            wasm_path: wasm_path.to_string_lossy().into(),
            entrypoint: meta.entrypoint.unwrap_or_else(|| "deny".into()),
        },
        source_file,
        sources: Vec::new(),
        sinks: Vec::new(),
        languages,
    });
    Ok(())
}

fn wasm_sidecar_path(wasm_path: &Path, ext: &str) -> PathBuf {
    let mut p = wasm_path.to_path_buf();
    let side_ext = format!("wasm.{ext}");
    p.set_extension(side_ext);
    p
}
