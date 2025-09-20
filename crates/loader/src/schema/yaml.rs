use crate::matchers::{MatcherKind, Query};
use crate::schema::compiled::{
    normalize_languages, AstQueryRule, CompiledRule, Example, RuleOptions, RuleSet, Severity,
};
use anyhow::anyhow;
use fancy_regex::Regex as FancyRegex;
use patterns::AstPattern;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use std::collections::HashSet;
use std::path::Path;

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
    #[serde(default, deserialize_with = "crate::schema::deserialize_languages")]
    pub languages: Option<Vec<String>>,
    #[serde(default)]
    pub options: RuleOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Individual textual pattern within a YAML rule.
pub struct Pattern {
    pub pattern: String,
}

pub(crate) fn compile_yaml_rule(
    rs: &mut RuleSet,
    seen: &mut HashSet<String>,
    yr: YamlRule,
    file_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    if !seen.insert(yr.id.clone()) {
        anyhow::bail!("duplicate rule id: {}", yr.id);
    }
    let severity: Severity = yr
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
    let languages = normalize_languages(yr.languages.clone());
    let source_file = file_path
        .strip_prefix(base_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    if let Some(patterns) = yr.patterns.clone() {
        for p in patterns {
            // Use FancyRegex to support look-around in user regex patterns
            let re = FancyRegex::new(&p.pattern)?;
            let rule = CompiledRule {
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
                languages: languages.clone(),
            };
            rs.rules.push(rule);
        }
    }
    if let Some(aq) = yr.ast_query {
        let kind = Regex::new(&aq.kind)?;
        let value = match aq.value {
            Some(v) => Some(Regex::new(&v)?),
            None => None,
        };
        let rule = CompiledRule {
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
            languages: languages.clone(),
        };
        rs.rules.push(rule);
    }
    if let Some(ap) = yr.ast_pattern {
        let rule = CompiledRule {
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
            languages,
        };
        rs.rules.push(rule);
    }
    Ok(())
}

pub(crate) fn load_yaml_rules(
    rs: &mut RuleSet,
    seen_ids: &mut HashSet<String>,
    doc: &YamlValue,
    file_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
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
                let sr: crate::schema::semgrep::SemgrepRule = serde_yaml::from_value(r.clone())?;
                crate::schema::semgrep::compile_semgrep_rule(
                    rs, seen_ids, sr, file_path, base_dir,
                )?;
            } else {
                let yr: YamlRule = serde_yaml::from_value(r.clone())?;
                compile_yaml_rule(rs, seen_ids, yr, file_path, base_dir)?;
            }
        }
    }
    Ok(())
}
