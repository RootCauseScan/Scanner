//! Loads rules from YAML, JSON or Rego-WASM modules
//! and compiles them to an internal executable representation.

use anyhow::{anyhow, Context};
use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use tracing::debug;

#[path = "../../engine/src/pattern.rs"]
mod ast_pattern;
pub use ast_pattern::{AstPattern, MetaVar, TaintPattern};

mod walk;
pub use walk::visit;

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
/// Rule defined in the project's own YAML format.
pub struct YamlRule {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub patterns: Option<Vec<Pattern>>,
    pub ast_query: Option<AstQueryRule>,
    #[serde(rename = "ast-pattern")]
    pub ast_pattern: Option<AstPattern>,
    pub message: Option<String>,
    pub remediation: Option<String>,
    pub fix: Option<String>,
    pub examples: Option<Vec<Example>>,
    #[serde(default)]
    pub options: RuleOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Individual textual pattern within a YAML rule.
pub struct Pattern {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Rule expressed in simplified JSON.
pub struct JsonRule {
    pub description: Option<String>,
    pub severity: Option<String>,
    pub query: Option<JsonQuery>,
    pub ast_query: Option<AstQueryRule>,
    #[serde(rename = "ast-pattern")]
    pub ast_pattern: Option<AstPattern>,
    #[serde(default)]
    pub options: RuleOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// JSONPath query used by [`JsonRule`].
pub struct JsonQuery {
    pub r#type: Option<String>,
    pub path: Option<String>,
    pub value: Option<JsonValue>,
    pub pattern: Option<String>,
    pub message: Option<String>,
    pub remediation: Option<String>,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Query on the AST when structural analysis is required.
pub struct AstQueryRule {
    pub kind: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Subset of rules compatible with Semgrep.
pub struct SemgrepRule {
    pub id: String,
    pub message: Option<String>,
    pub severity: Option<String>,
    pub mode: Option<String>,
    pub pattern: Option<String>,
    #[serde(rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    #[serde(rename = "patterns")]
    pub patterns: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-either")]
    pub pattern_either: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-not")]
    pub pattern_not: Option<String>,
    #[serde(rename = "pattern-inside")]
    pub pattern_inside: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-sources")]
    pub pattern_sources: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-sanitizers")]
    pub pattern_sanitizers: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-sinks")]
    pub pattern_sinks: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-reclass")]
    pub pattern_reclass: Option<Vec<YamlValue>>,
    #[serde(rename = "metavariable-pattern")]
    pub metavariable_pattern: Option<YamlValue>,
    #[serde(rename = "metavariable-regex")]
    pub metavariable_regex: Option<Vec<MetavariableRegex>>,
    #[serde(rename = "focus-metavariable")]
    pub focus_metavariable: Option<String>,
    pub fix: Option<String>,
    #[serde(default)]
    pub options: RuleOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetavariableRegex {
    pub metavariable: String,
    pub regex: String,
}

#[derive(Debug, Clone)]
pub enum AnyRegex {
    Std(Regex),
    Fancy(FancyRegex),
}

pub mod regex_ext {
    pub type Regex = crate::AnyRegex;
}

pub struct AnyMatch<'a> {
    text: &'a str,
}

impl<'a> AnyMatch<'a> {
    pub fn as_str(&self) -> &'a str {
        self.text
    }
}

pub struct AnyCaptures<'a> {
    get_fn: Box<dyn Fn(usize) -> Option<AnyMatch<'a>> + 'a>,
}

impl<'a> AnyCaptures<'a> {
    pub fn get(&self, idx: usize) -> Option<AnyMatch<'a>> {
        (self.get_fn)(idx)
    }
}

impl AnyRegex {
    pub fn is_fancy(&self) -> bool {
        matches!(self, Self::Fancy(_))
    }
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Std(r) => r.is_match(text),
            Self::Fancy(r) => r.is_match(text).unwrap_or(false),
        }
    }

    pub fn find_iter<'a>(
        &'a self,
        text: &'a str,
    ) -> Box<dyn Iterator<Item = (usize, usize)> + 'a> {
        match self {
            Self::Std(r) => Box::new(r.find_iter(text).map(|m| (m.start(), m.end()))),
            Self::Fancy(r) => Box::new(
                r.find_iter(text)
                    .filter_map(|m| m.ok())
                    .map(|m| (m.start(), m.end())),
            ),
        }
    }

    pub fn captures<'a>(&'a self, text: &'a str) -> Option<AnyCaptures<'a>> {
        match self {
            Self::Std(r) => r.captures(text).map(|caps| {
                AnyCaptures {
                    get_fn: Box::new(move |idx| caps.get(idx).map(|m| AnyMatch { text: m.as_str() })),
                }
            }),
            Self::Fancy(r) => match r.captures(text) {
                Ok(Some(caps)) => Some(AnyCaptures {
                    get_fn: Box::new(move |idx| caps.get(idx).map(|m| AnyMatch { text: m.as_str() })),
                }),
                _ => None,
            },
        }
    }
}

impl From<Regex> for AnyRegex {
    fn from(r: Regex) -> Self {
        AnyRegex::Std(r)
    }
}

impl From<FancyRegex> for AnyRegex {
    fn from(r: FancyRegex) -> Self {
        AnyRegex::Fancy(r)
    }
}

#[derive(Debug, Clone)]
/// Expression for AST queries, combining type and value.
pub struct Query {
    pub kind: Regex,
    pub value: Option<Regex>,
}

#[derive(Debug, Clone)]
pub enum MatcherKind {
    /// Regex search in plain text.
    TextRegex(AnyRegex, String /*scope/path*/),
    /// Multiple allow/deny expressions evaluated in the same file.
    TextRegexMulti {
        allow: Vec<(AnyRegex, String)>,
        deny: Option<AnyRegex>,
        inside: Vec<AnyRegex>,
        not_inside: Vec<AnyRegex>,
    },
    /// Exact comparison of a JSON value in a path.
    JsonPathEq(String, JsonValue),
    /// Regex evaluation over a JSON value.
    JsonPathRegex(String, Regex),
    /// Query on AST.
    AstQuery(Query),
    /// Structural pattern over AST.
    AstPattern(AstPattern),
    /// Executes a Rego module compiled to WASM.
    RegoWasm {
        wasm_path: String,
        entrypoint: String,
    },
    /// Information flow rules between sources and sinks.
    TaintRule {
        sources: Vec<TaintPattern>,
        sanitizers: Vec<TaintPattern>,
        reclass: Vec<TaintPattern>,
        sinks: Vec<TaintPattern>,
    },
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
}

#[derive(Debug, Clone, Default)]
/// Collection of compiled rules.
pub struct RuleSet {
    pub rules: Vec<CompiledRule>,
}

/// Recursively reads a directory and compiles the found rules.
///
/// # Example
/// ```no_run
/// use loader::load_rules;
/// let rules = load_rules(std::path::Path::new("rules")).unwrap();
/// assert!(!rules.rules.is_empty());
/// ```
pub fn load_rules(dir: &Path) -> anyhow::Result<RuleSet> {
    let mut rs = RuleSet::default();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let excl = |p: &Path| {
        // Exclude the .git folder
        p.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == ".git")
            .unwrap_or(false)
    };
    visit(dir, &excl, &mut |path| {
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        debug!(file = %path.display(), "Discovered rule candidate");
        if name.ends_with(".wasm") {
            debug!(file = %path.display(), "Parsing WASM rule");
            compile_wasm_rule(&mut rs, &mut seen_ids, path, dir)
                .with_context(|| format!("Failed to parse WASM rule file: {}", path.display()))?;
        } else if (name.ends_with(".yaml") || name.ends_with(".yml")) && !name.contains(".wasm.") {
            debug!(file = %path.display(), "Parsing YAML rule");
            let data = fs::read_to_string(path)
                .with_context(|| format!("Failed to read rule file: {}", path.display()))?;
            let doc: YamlValue = serde_yaml::from_str(&data)
                .with_context(|| format!("Failed to parse rule file: {}", path.display()))?;
            if let Some(rules) = doc.get("rules").and_then(|v| v.as_sequence()) {
                for r in rules {
                    if r.get("pattern").is_some()
                        || r.get("pattern-not").is_some()
                        || r.get("pattern-either").is_some()
                        || r.get("patterns").is_some()
                        || r.get("pattern-sources").is_some()
                        || r.get("pattern-sinks").is_some()
                        || r.get("pattern-regex").is_some()
                        || r.get("metavariable-pattern").is_some()
                    {
                        let sr: SemgrepRule =
                            serde_yaml::from_value(r.clone()).with_context(|| {
                                format!("Failed to parse rule file: {}", path.display())
                            })?;
                        compile_semgrep_rule(&mut rs, &mut seen_ids, sr, path, dir)?;
                    } else {
                        let yr: YamlRule =
                            serde_yaml::from_value(r.clone()).with_context(|| {
                                format!("Failed to parse rule file: {}", path.display())
                            })?;
                        compile_yaml_rule(&mut rs, &mut seen_ids, yr, path, dir)?;
                    }
                }
            }
        } else if name.ends_with(".json") && !name.contains(".wasm.") {
            debug!(file = %path.display(), "Parsing JSON rule");
            let data = fs::read_to_string(path)
                .with_context(|| format!("Failed to read rule file: {}", path.display()))?;
            let v: serde_json::Value = serde_json::from_str(&data)
                .with_context(|| format!("Failed to parse rule file: {}", path.display()))?;
            if let Some(obj) = v.get("rules").and_then(|v| v.as_object()) {
                for (ns, category_obj) in obj {
                    if let Some(inner) = category_obj.as_object() {
                        for (id, rule_v) in inner {
                            let jr: JsonRule = serde_json::from_value(rule_v.clone())
                                .with_context(|| {
                                    format!("Failed to parse rule file: {}", path.display())
                                })?;
                            compile_json_rule(
                                &mut rs,
                                &mut seen_ids,
                                format!("{ns}.{id}"),
                                jr,
                                path,
                                dir,
                            )?;
                        }
                    }
                }
            }
        } else {
            debug!(file = %path.display(), "Skipping non-rule file");
        }
        Ok(())
    })?;
    Ok(rs)
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
}

const MAX_WASM_BYTES: u64 = 10 * 1024 * 1024; // 10MB limit

fn compile_wasm_rule(
    rs: &mut RuleSet,
    seen: &mut HashSet<String>,
    wasm_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    let meta = fs::metadata(wasm_path)
        .with_context(|| format!("Failed to read rule file metadata: {}", wasm_path.display()))?;
    if meta.len() < 8 || meta.len() > MAX_WASM_BYTES {
        anyhow::bail!("Invalid WASM module size");
    }

    // Check magic header and version
    let mut file = fs::File::open(wasm_path)
        .with_context(|| format!("Failed to open rule file: {}", wasm_path.display()))?;
    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .with_context(|| format!("Failed to read rule header: {}", wasm_path.display()))?;
    if &header[0..4] != b"\0asm" || header[4..8] != [0x01, 0x00, 0x00, 0x00] {
        anyhow::bail!("Invalid WASM module signature");
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
    });

    let rule_id = meta.id;
    if !seen.insert(rule_id.clone()) {
        anyhow::bail!("duplicate rule id: {rule_id}");
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
    });
    Ok(())
}

fn wasm_sidecar_path(wasm_path: &Path, ext: &str) -> PathBuf {
    let mut p = wasm_path.to_path_buf();
    let side_ext = format!("wasm.{ext}");
    p.set_extension(side_ext);
    p
}

fn compile_yaml_rule(
    rs: &mut RuleSet,
    seen: &mut HashSet<String>,
    yr: YamlRule,
    file_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    if !seen.insert(yr.id.clone()) {
        anyhow::bail!("duplicate rule id: {}", yr.id);
    }
    let severity = yr
        .severity
        .as_deref()
        .unwrap_or("MEDIUM")
        .parse()
        .map_err(|e: String| anyhow!(e))?;
    let category = yr.category.clone().unwrap_or_else(|| "general".into());
    let message = yr
        .message
        .clone()
        .unwrap_or_else(|| yr.description.clone().unwrap_or_default());
    let remediation = yr.remediation.clone();
    let fix = yr.fix.clone();
    let source_file = file_path
        .strip_prefix(base_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    if let Some(patterns) = yr.patterns.clone() {
        for p in patterns {
            // Use FancyRegex to support look-around in user regex patterns
            let re = FancyRegex::new(&p.pattern)?;
            rs.rules.push(CompiledRule {
                id: yr.id.clone(),
                severity,
                category: category.clone(),
                message: message.clone(),
                remediation: remediation.clone(),
                fix: fix.clone(),
                interfile: yr.options.interfile,
                matcher: MatcherKind::TextRegex(re.into(), String::new()),
                source_file: source_file.clone(),
                sources: Vec::new(),
                sinks: Vec::new(),
            });
        }
    }
    if let Some(aq) = yr.ast_query {
        let kind = Regex::new(&aq.kind)?;
        let value = match aq.value {
            Some(v) => Some(Regex::new(&v)?),
            None => None,
        };
        rs.rules.push(CompiledRule {
            id: yr.id.clone(),
            severity,
            category: category.clone(),
            message: message.clone(),
            remediation: remediation.clone(),
            fix: fix.clone(),
            interfile: yr.options.interfile,
            matcher: MatcherKind::AstQuery(Query { kind, value }),
            source_file: source_file.clone(),
            sources: Vec::new(),
            sinks: Vec::new(),
        });
    }
    if let Some(ap) = yr.ast_pattern {
        rs.rules.push(CompiledRule {
            id: yr.id.clone(),
            severity,
            category,
            message,
            remediation,
            fix,
            interfile: yr.options.interfile,
            matcher: MatcherKind::AstPattern(ap),
            source_file,
            sources: Vec::new(),
            sinks: Vec::new(),
        });
    }
    Ok(())
}

fn compile_json_rule(
    rs: &mut RuleSet,
    seen: &mut HashSet<String>,
    id: String,
    jr: JsonRule,
    file_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    if !seen.insert(id.clone()) {
        anyhow::bail!("duplicate rule id: {id}");
    }
    let severity: Severity = jr
        .severity
        .as_deref()
        .unwrap_or("MEDIUM")
        .parse()
        .map_err(|e: String| anyhow!(e))?;
    let description = jr.description.clone().unwrap_or_default();
    let source_file = file_path
        .strip_prefix(base_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    if let Some(q) = jr.query {
        if let (Some(path), Some(val)) = (q.path.clone(), q.value.clone()) {
            rs.rules.push(CompiledRule {
                id: id.clone(),
                severity,
                category: "json".into(),
                message: q.message.clone().unwrap_or_else(|| description.clone()),
                remediation: q.remediation.clone(),
                fix: q.fix.clone(),
                interfile: jr.options.interfile,
                matcher: MatcherKind::JsonPathEq(path, val),
                source_file: source_file.clone(),
                sources: Vec::new(),
                sinks: Vec::new(),
            });
        }
        if let (Some(path), Some(pat)) = (q.path, q.pattern) {
            let re = Regex::new(&pat)?;
            rs.rules.push(CompiledRule {
                id: id.clone(),
                severity,
                category: "json".into(),
                message: q.message.unwrap_or_else(|| "".into()),
                remediation: None,
                fix: q.fix.clone(),
                interfile: jr.options.interfile,
                matcher: MatcherKind::JsonPathRegex(path, re),
                source_file: source_file.clone(),
                sources: Vec::new(),
                sinks: Vec::new(),
            });
        }
    }
    if let Some(aq) = jr.ast_query {
        let kind = Regex::new(&aq.kind)?;
        let value = match aq.value {
            Some(v) => Some(Regex::new(&v)?),
            None => None,
        };
        rs.rules.push(CompiledRule {
            id: id.clone(),
            severity,
            category: "ast".into(),
            message: description.clone(),
            remediation: None,
            fix: None,
            interfile: jr.options.interfile,
            matcher: MatcherKind::AstQuery(Query { kind, value }),
            source_file: source_file.clone(),
            sources: Vec::new(),
            sinks: Vec::new(),
        });
    }
    if let Some(ap) = jr.ast_pattern {
        rs.rules.push(CompiledRule {
            id,
            severity,
            category: "ast".into(),
            message: description,
            remediation: None,
            fix: None,
            interfile: jr.options.interfile,
            matcher: MatcherKind::AstPattern(ap),
            source_file,
            sources: Vec::new(),
            sinks: Vec::new(),
        });
    }
    Ok(())
}

pub fn semgrep_to_regex(pattern: &str, mv: &HashMap<String, String>) -> String {
    fn esc(seg: &str) -> String {
        let mut out = String::new();
        for ch in seg.chars() {
            match ch {
                '{' | '}' => {
                    out.push('\\');
                    out.push(ch);
                }
                _ => out.push_str(&regex::escape(&ch.to_string())),
            }
        }
        out
    }
    let metav = Regex::new(r"\$[A-Za-z_][A-Za-z0-9_]*").expect("valid metavariable regex");
    let mut p = String::new();
    let mut last = 0;
    for m in metav.find_iter(pattern) {
        p.push_str(&esc(&pattern[last..m.start()]));
        let var = &pattern[m.start() + 1..m.end()];
        if let Some(r) = mv.get(var) {
            // Support PCRE-style anchors used in some Semgrep rules
            // by translating \A/\Z/\z to ^/$ which are supported
            // by the Rust regex engines we use.
            let anchored = r
                .replace("\\A", "^")
                .replace("\\Z", "$")
                .replace("\\z", "$");
            let r = anchored.trim_start_matches('^').trim_end_matches('$');
            p.push_str(&format!("({r})"));
        } else {
            p.push_str("[^\n]*?");
        }
        last = m.end();
    }
    p.push_str(&esc(&pattern[last..]));
    p = p.replace("\\.\\.\\.", ".*?");
    p = p.replace(" ", "\\s+");
    format!("(?s).*{p}.*")
}

pub fn semgrep_to_regex_exact(pattern: &str, mv: &HashMap<String, String>) -> String {
    fn esc(seg: &str) -> String {
        let mut out = String::new();
        for ch in seg.chars() {
            match ch {
                '{' | '}' => {
                    out.push('\\');
                    out.push(ch);
                }
                _ => out.push_str(&regex::escape(&ch.to_string())),
            }
        }
        out
    }
    let metav = Regex::new(r"\$[A-Za-z_][A-Za-z0-9_]*").expect("valid metavariable regex");
    let mut p = String::new();
    let mut last = 0;
    for m in metav.find_iter(pattern) {
        p.push_str(&esc(&pattern[last..m.start()]));
        let var = &pattern[m.start() + 1..m.end()];
        if let Some(r) = mv.get(var) {
            let anchored = r
                .replace("\\A", "^")
                .replace("\\Z", "$")
                .replace("\\z", "$");
            let r = anchored.trim_start_matches('^').trim_end_matches('$');
            p.push_str(&format!("({r})"));
        } else {
            p.push_str("[^\n]*?");
        }
        last = m.end();
    }
    p.push_str(&esc(&pattern[last..]));
    p = p.replace("\\.\\.\\.", ".*?");
    p = p.replace(" ", "\\s+");
    format!("(?s){p}")
}

fn collect_metavar_regex(
    value: &YamlValue,
    mv: &mut HashMap<String, String>,
    focus: &mut Option<String>,
) {
    // Handle both sequence and single-map forms of metavariable-regex
    if let Some(node) = value.get("metavariable-regex") {
        if let Some(seq) = node.as_sequence() {
            for item in seq {
                if let (Some(var), Some(re)) = (
                    item.get("metavariable").and_then(|v| v.as_str()),
                    item.get("regex").and_then(|v| v.as_str()),
                ) {
                    mv.insert(var.trim_start_matches('$').to_string(), re.to_string());
                }
            }
        } else if let Some(map) = node.as_mapping() {
            let var = map
                .get("metavariable")
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches('$').to_string());
            let re = map.get("regex").and_then(|v| v.as_str()).map(|s| s.to_string());
            if let (Some(var), Some(re)) = (var, re) {
                mv.insert(var, re);
            }
        }
    }
    if focus.is_none() {
        if let Some(f) = value.get("focus-metavariable").and_then(|v| v.as_str()) {
            *focus = Some(f.to_string());
        }
    }
    if let Some(obj) = value.as_mapping() {
        // Also support being called on the metavariable-regex mapping itself
        if let (Some(var), Some(re)) = (
            obj.get(&YamlValue::from("metavariable"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches('$').to_string()),
            obj.get(&YamlValue::from("regex")).and_then(|v| v.as_str()).map(|s| s.to_string()),
        ) {
            mv.insert(var, re);
        }
        for val in obj.values() {
            collect_metavar_regex(val, mv, focus);
        }
    } else if let Some(seq) = value.as_sequence() {
        for val in seq {
            collect_metavar_regex(val, mv, focus);
        }
    }
}

#[derive(Clone, Copy)]
enum PatternKind {
    Pattern,
    Inside,
    NotInside,
    Not,
    Regex,
}

fn extract_patterns(
    value: &YamlValue,
    kind: Option<PatternKind>,
    out: &mut Vec<(PatternKind, String)>,
    seen: &mut HashSet<usize>,
) {
    let ptr = value as *const _ as usize;
    if !seen.insert(ptr) {
        return;
    }
    if let Some(map) = value.as_mapping() {
        for (k, v) in map {
            if let Some(key) = k.as_str() {
                match key {
                    "pattern" => {
                        let k = kind.unwrap_or(PatternKind::Pattern);
                        if let Some(s) = v.as_str() {
                            out.push((k, s.to_string()));
                        } else {
                            extract_patterns(v, Some(k), out, seen);
                        }
                        continue;
                    }
                    "pattern-regex" => {
                        if let Some(s) = v.as_str() {
                            out.push((PatternKind::Regex, s.to_string()));
                        } else {
                            extract_patterns(v, Some(PatternKind::Regex), out, seen);
                        }
                        continue;
                    }
                    "pattern-inside" => {
                        if let Some(s) = v.as_str() {
                            out.push((PatternKind::Inside, s.to_string()));
                        } else {
                            extract_patterns(v, Some(PatternKind::Inside), out, seen);
                        }
                        continue;
                    }
                    "pattern-not-inside" => {
                        if let Some(s) = v.as_str() {
                            out.push((PatternKind::NotInside, s.to_string()));
                        } else {
                            extract_patterns(v, Some(PatternKind::NotInside), out, seen);
                        }
                        continue;
                    }
                    "pattern-not" => {
                        if let Some(s) = v.as_str() {
                            out.push((PatternKind::Not, s.to_string()));
                        } else {
                            extract_patterns(v, Some(PatternKind::Not), out, seen);
                        }
                        continue;
                    }
                    "metavariable-pattern" => {
                        if let Some(map) = v.as_mapping() {
                            if let Some(pv) = map.get("pattern") {
                                let k = kind.unwrap_or(PatternKind::Pattern);
                                extract_patterns(pv, Some(k), out, seen);
                            }
                            if let Some(pv) = map.get("patterns") {
                                extract_patterns(pv, kind, out, seen);
                            }
                        } else if let Some(seq) = v.as_sequence() {
                            for item in seq {
                                if let Some(map) = item.as_mapping() {
                                    if let Some(pv) = map.get("pattern") {
                                        let k = kind.unwrap_or(PatternKind::Pattern);
                                        extract_patterns(pv, Some(k), out, seen);
                                    }
                                    if let Some(pv) = map.get("patterns") {
                                        extract_patterns(pv, kind, out, seen);
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    "pattern-either" | "patterns" => {
                        extract_patterns(v, kind, out, seen);
                        continue;
                    }
                    _ => {}
                }
            }
            extract_patterns(v, kind, out, seen);
        }
    } else if let Some(seq) = value.as_sequence() {
        for item in seq {
            extract_patterns(item, kind, out, seen);
        }
    } else if let Some(s) = value.as_str() {
        if let Some(k) = kind {
            out.push((k, s.to_string()));
        }
    }
}

fn compile_taint_patterns(
    arr: &[YamlValue],
    mv: &HashMap<String, String>,
) -> anyhow::Result<TaintPattern> {
    fn handle_entry(
        entry: &YamlValue,
        mv: &HashMap<String, String>,
        pattern: &mut TaintPattern,
    ) -> anyhow::Result<()> {
        if let Some(p) = entry.get("pattern").and_then(|v| v.as_str()) {
            for line in p
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "...")
            {
                pattern
                    .allow
                    .push(FancyRegex::new(&semgrep_to_regex_exact(line, mv))?.into());
            }
        }
        if let Some(p) = entry.get("pattern-inside").and_then(|v| v.as_str()) {
            for line in p
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "...")
            {
                pattern
                    .inside
                    .push(FancyRegex::new(&semgrep_to_regex_exact(line, mv))?.into());
            }
        }
        if let Some(p) = entry.get("pattern-not-inside").and_then(|v| v.as_str()) {
            for line in p
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "...")
            {
                pattern
                    .not_inside
                    .push(FancyRegex::new(&semgrep_to_regex_exact(line, mv))?.into());
            }
        }
        if let Some(n) = entry.get("pattern-not").and_then(|v| v.as_str()) {
            let combined: String = n
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "...")
                .collect::<Vec<_>>()
                .join("\n");
            pattern.deny = Some(FancyRegex::new(&semgrep_to_regex_exact(&combined, mv))?.into());
        }
        if let Some(arr) = entry.get("pattern-either").and_then(|v| v.as_sequence()) {
            for item in arr {
                handle_entry(item, mv, pattern)?;
            }
        }
        if let Some(arr) = entry.get("patterns").and_then(|v| v.as_sequence()) {
            for item in arr {
                handle_entry(item, mv, pattern)?;
            }
        }
        Ok(())
    }

    let mut pattern = TaintPattern::default();
    for item in arr {
        handle_entry(item, mv, &mut pattern)?;
    }
    Ok(pattern)
}

fn compile_semgrep_rule(
    rs: &mut RuleSet,
    seen: &mut HashSet<String>,
    sr: SemgrepRule,
    file_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    if !seen.insert(sr.id.clone()) {
        anyhow::bail!("duplicate rule id: {}", sr.id);
    }
    let severity: Severity = sr
        .severity
        .as_deref()
        .unwrap_or("MEDIUM")
        .parse()
        .map_err(|e: String| anyhow!(e))?;
    let message = sr.message.clone().unwrap_or_default();
    let source_file = file_path
        .strip_prefix(base_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let mut mv = HashMap::new();
    let mut _focus = sr.focus_metavariable.clone();
    if let Some(arr) = &sr.metavariable_regex {
        for item in arr {
            mv.insert(
                item.metavariable.trim_start_matches('$').to_string(),
                item.regex.clone(),
            );
        }
    }
    let sr_yaml = serde_yaml::to_value(&sr)?;
    collect_metavar_regex(&sr_yaml, &mut mv, &mut _focus);
    let mut patterns = Vec::new();
    let mut seen_patterns = HashSet::new();
    extract_patterns(&sr_yaml, None, &mut patterns, &mut seen_patterns);
    let mut sources = Vec::new();
    if let Some(arr) = sr.pattern_sources.clone() {
        for src in arr {
            if let Some(seq) = src.get("patterns").and_then(|v| v.as_sequence()) {
                let mut tp = compile_taint_patterns(seq, &mv)?;
                tp.focus = _focus.clone();
                sources.push(tp);
            } else if src.get("pattern-either").is_some() || src.get("pattern").is_some() {
                // Handle single pattern or pattern-either directly
                let single_item = vec![src];
                let mut tp = compile_taint_patterns(&single_item, &mv)?;
                tp.focus = _focus.clone();
                sources.push(tp);
            }
        }
    }

    let mut sanitizers = Vec::new();
    if let Some(arr) = sr.pattern_sanitizers.clone() {
        for san in arr {
            if let Some(seq) = san.get("patterns").and_then(|v| v.as_sequence()) {
                let mut tp = compile_taint_patterns(seq, &mv)?;
                tp.focus = _focus.clone();
                sanitizers.push(tp);
            } else if san.get("pattern-either").is_some() || san.get("pattern").is_some() {
                // Handle single pattern or pattern-either directly
                let single_item = vec![san];
                let mut tp = compile_taint_patterns(&single_item, &mv)?;
                tp.focus = _focus.clone();
                sanitizers.push(tp);
            }
        }
    }

    let mut sinks = Vec::new();
    if let Some(arr) = sr.pattern_sinks.clone() {
        for snk in arr {
            if let Some(seq) = snk.get("patterns").and_then(|v| v.as_sequence()) {
                sinks.push(compile_taint_patterns(seq, &mv)?);
            } else if snk.get("pattern-either").is_some() || snk.get("pattern").is_some() {
                // Handle single pattern or pattern-either directly
                let single_item = vec![snk];
                sinks.push(compile_taint_patterns(&single_item, &mv)?);
            }
        }
    }

    let mut reclass = Vec::new();
    if let Some(arr) = sr.pattern_reclass.clone() {
        for rc in arr {
            if let Some(seq) = rc.get("patterns").and_then(|v| v.as_sequence()) {
                reclass.push(compile_taint_patterns(seq, &mv)?);
            } else if rc.get("pattern-either").is_some() || rc.get("pattern").is_some() {
                // Handle single pattern or pattern-either directly
                let single_item = vec![rc];
                reclass.push(compile_taint_patterns(&single_item, &mv)?);
            }
        }
    }

    if !sources.is_empty() || !sinks.is_empty() {
        rs.rules.push(CompiledRule {
            id: sr.id,
            severity,
            category: "semgrep".into(),
            message,
            remediation: None,
            fix: sr.fix.clone(),
            interfile: sr.options.interfile,
            matcher: MatcherKind::TaintRule {
                sources,
                sanitizers,
                reclass,
                sinks,
            },
            source_file: source_file.clone(),
            sources: Vec::new(),
            sinks: Vec::new(),
        });
        return Ok(());
    }
    let use_multi = sr.patterns.is_some()
        || sr.pattern_inside.is_some()
        || sr.pattern_not_inside.is_some()
        || sr.pattern_either.is_some();

    if use_multi {
        let mut allow: Vec<(AnyRegex, String)> = Vec::new();
        let mut deny_parts: Vec<String> = Vec::new();
        let mut inside = Vec::new();
        let mut not_inside = Vec::new();
        for (kind, pat) in patterns {
            match kind {
                PatternKind::Pattern => {
                    for line in pat
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty() && *l != "...")
                    {
                        let re_str = semgrep_to_regex_exact(line, &mv);
                        allow.push((FancyRegex::new(&re_str)?.into(), line.to_string()));
                    }
                }
                PatternKind::Inside => {
                    let combined: String = pat
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty())
                        .collect::<Vec<_>>()
                        .join("\n");
                    let mut re = semgrep_to_regex_exact(&combined, &mv);
                    re = re.replacen("(?s)", "(?ms)^", 1);
                    inside.push(FancyRegex::new(&re)?.into());
                }
                PatternKind::NotInside => {
                    let combined: String = pat
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty())
                        .collect::<Vec<_>>()
                        .join("\n");
                    let mut re = semgrep_to_regex_exact(&combined, &mv);
                    re = re.replacen("(?s)", "(?ms)^", 1);
                    not_inside.push(FancyRegex::new(&re)?.into());
                }
                PatternKind::Not => {
                    let combined: String = pat
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty() && *l != "...")
                        .collect::<Vec<_>>()
                        .join("\n");
                    deny_parts.push(semgrep_to_regex_exact(&combined, &mv));
                }
                PatternKind::Regex => {
                    allow.push((FancyRegex::new(&pat)?.into(), pat));
                }
            }
        }
        if !allow.is_empty() {
            let deny = if !deny_parts.is_empty() {
                let cleaned: Vec<String> = deny_parts
                    .into_iter()
                    .map(|s| s.strip_prefix("(?s)").map(|x| x.to_string()).unwrap_or(s))
                    .collect();
                let joined = cleaned.join(")|(?:");
                let big = format!("(?s)(?:{})", joined);
                Some(FancyRegex::new(&big)?.into())} else { None };
            rs.rules.push(CompiledRule {
                id: sr.id,
                severity,
                category: "semgrep".into(),
                message,
                remediation: None,
                fix: sr.fix.clone(),
                interfile: sr.options.interfile,
                matcher: MatcherKind::TextRegexMulti {
                    allow,
                    deny,
                    inside,
                    not_inside,
                },
                source_file: source_file.clone(),
                sources: Vec::new(),
                sinks: Vec::new(),
            });
        }
    } else if let Some(p) = sr.pattern {
        let re = FancyRegex::new(&semgrep_to_regex(&p, &mv))?;
        rs.rules.push(CompiledRule {
            id: sr.id,
            severity,
            category: "semgrep".into(),
            message,
            remediation: None,
            fix: sr.fix,
            interfile: sr.options.interfile,
            matcher: MatcherKind::TextRegex(re.into(), p),
            source_file,
            sources: Vec::new(),
            sinks: Vec::new(),
        });
    } else if let Some(pr) = sr.pattern_regex {
        let re = FancyRegex::new(&pr)?;
        rs.rules.push(CompiledRule {
            id: sr.id,
            severity,
            category: "semgrep".into(),
            message,
            remediation: None,
            fix: sr.fix,
            interfile: sr.options.interfile,
            matcher: MatcherKind::TextRegex(re.into(), pr),
            source_file,
            sources: Vec::new(),
            sinks: Vec::new(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::PatternKind;
    use super::*;
    use regex::Regex;
    use std::collections::{HashMap, HashSet};
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn loads_wasm_rule_with_metadata() {
        let dir = tempdir().unwrap();
        let wasm = dir.path().join("test.wasm");
        // minimal wasm header with version
        fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();
        let meta = serde_json::json!({
            "id": "wasm.test",
            "severity": "LOW",
            "message": "msg",
            "remediation": "fix",
            "category": "wasm",
        });
        fs::write(
            dir.path().join("test.wasm.json"),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        let r = &rs.rules[0];
        assert!(matches!(r.matcher, MatcherKind::RegoWasm { .. }));
        assert_eq!(r.id, "wasm.test");
        assert_eq!(r.severity, Severity::Low);
        assert_eq!(r.message, "msg");
        assert_eq!(r.remediation.as_deref(), Some("fix"));
    }

    #[test]
    fn invalid_wasm_fails() {
        let dir = tempdir().unwrap();
        let wasm = dir.path().join("bad.wasm");
        fs::write(&wasm, b"notwasm").unwrap();
        let err = load_rules(dir.path()).unwrap_err();
        assert!(err.to_string().contains("WASM"));
    }

    #[test]
    fn loads_ast_query_rule() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
  - id: rust.no-println
    severity: LOW
    category: rust
    ast_query:
      kind: "Call"
      value: "println!"
    message: no println
"#;
        fs::write(dir.path().join("rules.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::AstQuery(q) => {
                assert!(q.kind.is_match("Call"));
            }
            _ => panic!("expected ast query"),
        }
    }

    #[test]
    fn loads_semgrep_rule() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.sample
  message: semgrep msg
  severity: LOW
  pattern: foo($X)
"#;
        fs::write(dir.path().join("sem.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegex(re, _) => {
                assert!(re.is_match("foo(123)"));
            }
            _ => panic!("expected text regex"),
        }
    }

    #[test]
    fn loads_semgrep_rule_with_context() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.ctx
  message: semgrep ctx
  severity: LOW
  pattern: foo()
  pattern-inside:
    - pattern: bar(...)
  pattern-not-inside:
    - pattern: baz(...)
"#;
        fs::write(dir.path().join("ctx.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegexMulti {
                inside, not_inside, ..
            } => {
                assert_eq!(inside.len(), 1);
                assert_eq!(not_inside.len(), 1);
            }
            _ => panic!("expected TextRegexMulti"),
        }
    }

    #[test]
    fn extract_patterns_recurses_nested() {
        let yaml: YamlValue = serde_yaml::from_str(
            r#"pattern-either:
  - pattern: foo(...)
  - patterns:
      - pattern-inside: bar(...)
      - pattern-not-inside: baz(...)
"#,
        )
        .unwrap();
        let mut acc = Vec::new();
        let mut seen = HashSet::new();
        extract_patterns(&yaml, None, &mut acc, &mut seen);
        assert_eq!(acc.len(), 3);
        assert!(acc.iter().any(|(k, _)| matches!(k, PatternKind::Pattern)));
        assert!(acc.iter().any(|(k, _)| matches!(k, PatternKind::Inside)));
        assert!(acc.iter().any(|(k, _)| matches!(k, PatternKind::NotInside)));
    }

    #[test]
    fn extract_patterns_ignores_scalars() {
        let yaml: YamlValue = serde_yaml::from_str("just a string").unwrap();
        let mut acc = Vec::new();
        let mut seen = HashSet::new();
        extract_patterns(&yaml, None, &mut acc, &mut seen);
        assert!(acc.is_empty());
    }

    #[test]
    fn loads_semgrep_rule_with_nested_patterns() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.nested
  message: nested
  severity: LOW
  patterns:
    - pattern: foo(...)
      pattern-either:
        - pattern-inside: bar(...)
        - pattern-not-inside: baz(...)
"#;
        fs::write(dir.path().join("nested.yml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegexMulti {
                allow,
                inside,
                not_inside,
                ..
            } => {
                assert_eq!(allow.len(), 1);
                assert_eq!(inside.len(), 1);
                assert_eq!(not_inside.len(), 1);
            }
            _ => panic!("expected TextRegexMulti"),
        }
    }

    #[test]
    fn multiline_not_inside_compiles_single_regex() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.multiline
  message: multi
  severity: LOW
  patterns:
    - pattern: io.jsonwebtoken.Jwts.builder();
    - pattern-not-inside: |-
        $RETURNTYPE $FUNC(...) {
          ...
          $JWTS.signWith(...);
          ...
        }
"#;
        fs::write(dir.path().join("multi.yml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegexMulti {
                allow, not_inside, ..
            } => {
                assert_eq!(allow.len(), 1);
                assert_eq!(not_inside.len(), 1);
            }
            _ => panic!("expected TextRegexMulti"),
        }
    }

    #[test]
    fn semgrep_to_regex_handles_metavars() {
        let mv = HashMap::new();
        let re = Regex::new(&semgrep_to_regex("print($X)", &mv)).unwrap();
        assert!(re.is_match("print(123)"));
        assert!(!re.is_match("println(123)"));
    }

    #[test]
    fn semgrep_to_regex_preserves_braces() {
        let mv = HashMap::new();
        let re = Regex::new(&semgrep_to_regex("{% debug %}", &mv)).unwrap();
        assert!(re.is_match("{% debug %}"));
    }

    #[test]
    fn semgrep_to_regex_exact_preserves_braces() {
        let mv = HashMap::new();
        let re = Regex::new(&semgrep_to_regex_exact("{% debug %}", &mv)).unwrap();
        assert!(re.is_match("{% debug %}"));
    }

    #[test]
    fn metavariable_regex_filters_matches() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.metavar
  message: test
  severity: LOW
  pattern: foo($X)
  metavariable-regex:
    - metavariable: $X
      regex: "^\\d+$"
"#;
        fs::write(dir.path().join("mv.yml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegex(re, _) => {
                assert!(re.is_match("foo(123)"));
                assert!(!re.is_match("foo(bar)"));
            }
            _ => panic!("expected text regex"),
        }
    }

    #[test]
    fn invalid_metavariable_regex_fails() {
        let dir = tempdir().unwrap();
        let bad = "rules:\n- id: bad\n  pattern: foo($X)\n  metavariable-regex: oops\n";
        fs::write(dir.path().join("bad.yml"), bad).unwrap();
        let err = load_rules(dir.path()).unwrap_err();
        assert!(err.downcast_ref::<serde_yaml::Error>().is_some());
    }

    #[test]
    fn loads_semgrep_pattern_regex_rule() {
        // pattern taken from semgrep/semgrep-rules/generic/secrets/gitleaks/slack-legacy-bot-token.yaml
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.pattern-regex
  message: regex msg
  severity: LOW
  pattern-regex: "(xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26})"
"#;
        fs::write(dir.path().join("pr.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegex(re, _) => {
                assert!(re.is_match("xoxb-12345678-abcdefghijklmnopqr"));
            }
            _ => panic!("expected text regex"),
        }
    }

    #[test]
    fn loads_semgrep_metavariable_pattern_rule() {
        // rule adapted from semgrep/semgrep-rules/c/lang/security/double-free.yaml
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.metavariable-pattern
  message: double free
  severity: LOW
  patterns:
    - pattern: |
        free($VAR);
        ...
        $FREE($VAR);
    - metavariable-pattern:
        metavariable: $FREE
        pattern: $FREE
  metavariable-regex:
    - metavariable: $FREE
      regex: free|release
"#;
        fs::write(dir.path().join("mvpat.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegexMulti { allow, .. } => {
                assert!(allow.iter().any(|(re, _)| re.is_match("release")));
            }
            _ => panic!("expected TextRegexMulti"),
        }
    }

    #[test]
    fn loads_json_rule() {
        let dir = tempdir().unwrap();
        let rule_json = r#"{
  "rules": {
    "docker": {
      "no-latest": {
        "severity": "HIGH",
        "query": {
          "path": "$.services[*].image",
          "pattern": ":latest$",
          "message": "Evita tags latest",
          "remediation": "Usa versiones fijas"
        }
      }
    }
  }
}"#;
        fs::write(dir.path().join("rule.json"), rule_json).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::JsonPathRegex(path, re) => {
                assert_eq!(path, "$.services[*].image");
                assert!(re.is_match("nginx:latest"));
            }
            _ => panic!("expected json path regex"),
        }
    }

    #[test]
    fn invalid_json_rule_fails() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("bad.json"), "{not json").unwrap();
        let err = load_rules(dir.path()).unwrap_err();
        assert!(err.downcast_ref::<serde_json::Error>().is_some());
    }

    #[test]
    fn loads_java_rules() {
        use std::path::PathBuf;
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/java");
        let rs = load_rules(&dir).expect("load java rules");
        assert!(rs.rules.iter().any(|r| r.id == "java.no-system-exit"));
    }

    #[test]
    fn loads_taint_rule() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: example-taint-rule
  message: Example taint rule
  languages: [python]
  severity: error
  mode: taint
  pattern-sources:
    - patterns:
        - pattern: input($X)
  pattern-sinks:
    - patterns:
        - pattern: eval($X)
"#;
        fs::write(dir.path().join("taint.yml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TaintRule {
                sources,
                sanitizers,
                reclass,
                sinks,
            } => {
                assert!(!sources.is_empty());
                assert!(sanitizers.is_empty());
                assert!(reclass.is_empty());
                assert!(!sinks.is_empty());
            }
            _ => panic!("expected taint rule"),
        }
    }

    #[test]
    fn invalid_taint_rule_fails() {
        let dir = tempdir().unwrap();
        let bad = "rules:\n- id: bad\n  pattern-sources: oops\n";
        fs::write(dir.path().join("bad.yml"), bad).unwrap();
        let err = load_rules(dir.path()).unwrap_err();
        assert!(err.downcast_ref::<serde_yaml::Error>().is_some());
    }
    #[test]
    fn taint_rule_propagates_focus() {
        let sr_yaml = r#"id: focus
message: msg
severity: LOW
pattern-sources:
  - patterns:
      - pattern: |
          $VAR = source()
pattern-sinks:
  - patterns:
      - pattern: |
          sink($VAR)
focus-metavariable: $VAR
"#;
        let sr: SemgrepRule = serde_yaml::from_str(sr_yaml).unwrap();
        let mut rs = RuleSet::default();
        let mut seen = HashSet::new();
        let file_path = Path::new("rules/test.yaml");
        let base_dir = Path::new("rules");
        compile_semgrep_rule(&mut rs, &mut seen, sr, file_path, base_dir).unwrap();
        match &rs.rules[0].matcher {
            MatcherKind::TaintRule { sources, .. } => {
                assert_eq!(sources[0].focus.as_deref(), Some("$VAR"));
            }
            _ => panic!("expected taint rule"),
        }
    }
}
