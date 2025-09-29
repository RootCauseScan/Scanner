use crate::timeline::{EventFormat, EventTimeline, TimelineSink};
use crate::{visualization, Format};
use anyhow::{anyhow, Result};
use engine::{
    analyze_file, build_cfg, build_dfg, load_rules_with_events, parse_file_with_events,
    set_debug_sink, CompiledRule, Finding, MatcherKind, RuleSet,
};
use ir::{DataFlowGraph, FileAst, FileIR};
use std::cell::{Ref, RefCell, RefMut};
use std::path::{Path, PathBuf};

pub struct DebugToolkit {
    timeline: TimelineSink,
}

pub struct DebugScope<'a> {
    toolkit: &'a DebugToolkit,
    active: bool,
}

impl<'a> Drop for DebugScope<'a> {
    fn drop(&mut self) {
        if self.active {
            self.toolkit.deactivate();
        }
    }
}

impl DebugToolkit {
    pub fn new() -> Self {
        Self {
            timeline: TimelineSink::new(),
        }
    }

    pub fn reset(&self) {
        self.timeline.reset();
    }

    pub fn scope(&self) -> DebugScope<'_> {
        self.activate();
        DebugScope {
            toolkit: self,
            active: true,
        }
    }

    pub fn run_with_scope<F, T>(&self, action: F) -> T
    where
        F: FnOnce() -> T,
    {
        let scope = self.scope();
        let output = action();
        drop(scope);
        output
    }

    pub fn run_with_scope_result<F, T>(&self, action: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let scope = self.scope();
        let output = action();
        drop(scope);
        output
    }

    pub fn timeline(&self) -> EventTimeline {
        self.timeline.snapshot()
    }

    pub fn events_as(&self, format: EventFormat) -> String {
        let timeline = self.timeline();
        match format {
            EventFormat::Text => timeline.to_text(),
            EventFormat::Json => timeline.to_json_string(),
            EventFormat::Mermaid => timeline.to_mermaid(),
        }
    }

    pub fn inspect_file(&self, path: &Path) -> Result<FileInspection> {
        self.run_with_scope_result(|| {
            let fir = parse_file_with_events(path, None, None)?
                .ok_or_else(|| anyhow!("unsupported file type: {}", path.display()))?;
            Ok(FileInspection::new(fir))
        })
    }

    pub fn parse_raw(&self, path: &Path) -> Result<Option<FileIR>> {
        self.run_with_scope_result(|| parse_file_with_events(path, None, None))
    }

    pub fn inspect_rules(&self, path: &Path) -> Result<RuleInspection> {
        self.run_with_scope_result(|| {
            let ruleset = load_rules_with_events(path)?;
            Ok(RuleInspection::new(ruleset))
        })
    }

    pub fn load_rules_raw(&self, path: &Path) -> Result<RuleSet> {
        self.run_with_scope_result(|| load_rules_with_events(path))
    }

    pub fn analyze(&self, file: &FileInspection, rules: &RuleInspection) -> AnalysisSnapshot {
        self.run_with_scope(|| {
            let fir = file.borrow();
            let findings = analyze_file(&fir, rules.ruleset());
            AnalysisSnapshot::new(findings)
        })
    }

    fn activate(&self) {
        set_debug_sink(Some(Box::new(self.timeline.clone())));
    }

    fn deactivate(&self) {
        set_debug_sink(None);
    }
}

pub struct FileInspection {
    fir: RefCell<FileIR>,
}

impl FileInspection {
    fn new(fir: FileIR) -> Self {
        Self {
            fir: RefCell::new(fir),
        }
    }

    pub fn borrow(&self) -> Ref<'_, FileIR> {
        self.fir.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<'_, FileIR> {
        self.fir.borrow_mut()
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from(self.fir.borrow().file_path.clone())
    }

    pub fn file_type(&self) -> String {
        self.fir.borrow().file_type.clone()
    }

    pub fn ast(&self) -> Option<FileAst> {
        self.fir.borrow().ast.clone()
    }

    pub fn ensure_dfg(&self) -> Result<()> {
        if self.fir.borrow().dfg.is_some() {
            return Ok(());
        }
        build_dfg(&mut self.fir.borrow_mut())?;
        Ok(())
    }

    pub fn dfg(&self) -> Option<DataFlowGraph> {
        self.fir.borrow().dfg.clone()
    }

    pub fn format_ast(&self, format: Format, simplified: bool) -> Result<String> {
        let fir = self.fir.borrow();
        let ast = fir
            .ast
            .as_ref()
            .ok_or_else(|| anyhow!("AST not available"))?;
        let rendered = match format {
            Format::Text => format!("{ast:#?}"),
            Format::Json => ast.to_json()?,
            Format::Dot => {
                if simplified {
                    visualization::ast_to_simplified_dot(ast)
                } else {
                    visualization::ast_to_dot_escaped(ast)
                }
            }
            Format::Mermaid => ast.to_mermaid(),
            Format::Tree => {
                if simplified {
                    visualization::ast_to_simplified_tree(ast)
                } else {
                    visualization::ast_to_tree(ast)
                }
            }
        };
        Ok(rendered)
    }

    pub fn format_cfg(&self, format: Format) -> Result<String> {
        let fir = self.fir.borrow();
        let cfg = build_cfg(&fir).ok_or_else(|| anyhow!("CFG not available"))?;
        let rendered = match format {
            Format::Text => format!("{cfg:#?}"),
            Format::Json => cfg.to_json()?,
            Format::Dot => cfg.to_dot(),
            Format::Mermaid => cfg.to_mermaid(),
            Format::Tree => visualization::cfg_to_tree(&cfg),
        };
        Ok(rendered)
    }

    pub fn format_dfg(&self, format: Format) -> Result<String> {
        self.ensure_dfg()?;
        let fir = self.fir.borrow();
        let dfg = fir
            .dfg
            .as_ref()
            .ok_or_else(|| anyhow!("DFG not available"))?;
        let rendered = match format {
            Format::Text => format!("{dfg:#?}"),
            Format::Json => dfg.to_json()?,
            Format::Dot => dfg.to_dot(),
            Format::Mermaid => dfg.to_mermaid(),
            Format::Tree => visualization::dfg_to_tree(dfg),
        };
        Ok(rendered)
    }

    pub fn summary(&self) -> FileSummary {
        let fir = self.fir.borrow();
        let ast_nodes = fir.ast.as_ref().map(|ast| ast.nodes.len()).unwrap_or(0);
        let dfg_nodes = fir.dfg.as_ref().map(|dfg| dfg.nodes.len()).unwrap_or(0);
        FileSummary {
            path: PathBuf::from(&fir.file_path),
            file_type: fir.file_type.clone(),
            ir_nodes: fir.nodes.len(),
            ast_nodes,
            dfg_nodes,
            has_source: fir.source.is_some(),
        }
    }
}

pub struct RuleInspection {
    ruleset: RuleSet,
}

impl RuleInspection {
    fn new(ruleset: RuleSet) -> Self {
        Self { ruleset }
    }

    pub fn ruleset(&self) -> &RuleSet {
        &self.ruleset
    }

    pub fn render(&self, format: Format) -> Result<String> {
        let rule = self
            .ruleset
            .rules
            .first()
            .ok_or_else(|| anyhow!("no rule found"))?;
        let rendered = match format {
            Format::Text => format!("{rule:#?}"),
            Format::Json => {
                let json = serde_json::json!({
                    "id": rule.id,
                    "severity": rule.severity,
                    "category": rule.category,
                    "message": rule.message,
                    "remediation": rule.remediation,
                    "interfile": rule.interfile,
                    "matcher": matcher_summary(rule),
                });
                serde_json::to_string_pretty(&json)?
            }
            Format::Dot => rule_to_dot(rule),
            Format::Mermaid => rule_to_mermaid(rule),
            Format::Tree => format!("Rule: {}", rule.id),
        };
        Ok(rendered)
    }

    pub fn summary(&self) -> RuleSummary {
        let total_rules = self.ruleset.rules.len();
        let mut languages = std::collections::BTreeSet::new();
        for rule in &self.ruleset.rules {
            for lang in &rule.languages {
                languages.insert(lang.clone());
            }
        }
        RuleSummary {
            total_rules,
            sample_ids: self
                .ruleset
                .rules
                .iter()
                .take(5)
                .map(|r| r.id.clone())
                .collect(),
            languages: languages.into_iter().collect(),
        }
    }
}

pub struct AnalysisSnapshot {
    findings: Vec<Finding>,
}

impl AnalysisSnapshot {
    fn new(findings: Vec<Finding>) -> Self {
        Self { findings }
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn matched_rules(&self) -> usize {
        let mut unique = std::collections::HashSet::new();
        for finding in &self.findings {
            unique.insert(finding.rule_id.clone());
        }
        unique.len()
    }

    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleSummary {
    pub total_rules: usize,
    pub sample_ids: Vec<String>,
    pub languages: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileSummary {
    pub path: PathBuf,
    pub file_type: String,
    pub ir_nodes: usize,
    pub ast_nodes: usize,
    pub dfg_nodes: usize,
    pub has_source: bool,
}

fn matcher_summary(rule: &CompiledRule) -> String {
    match &rule.matcher {
        MatcherKind::TextRegex(_, pattern) => format!("TextRegex pattern: {}", pattern),
        MatcherKind::TextRegexMulti {
            allow,
            deny,
            inside,
            not_inside,
        } => format!(
            "TextRegexMulti allow={} deny={} inside={} not_inside={}",
            allow.len(),
            deny.as_ref().map(|_| "yes").unwrap_or("no"),
            inside.len(),
            not_inside.len()
        ),
        MatcherKind::JsonPathEq(path, value) => {
            let val = truncate(&serde_json::to_string(value).unwrap_or_default(), 80);
            format!("JsonPathEq {} == {}", path, val)
        }
        MatcherKind::JsonPathRegex(path, _) => format!("JsonPathRegex {}", path),
        MatcherKind::AstQuery(_) => "AstQuery".to_string(),
        MatcherKind::AstPattern(_) => "AstPattern".to_string(),
        MatcherKind::RegoWasm {
            wasm_path,
            entrypoint,
        } => format!("RegoWasm {}::{}", wasm_path, entrypoint),
        MatcherKind::TaintRule {
            sources,
            sanitizers,
            sinks,
            ..
        } => format!(
            "TaintRule sources={} sanitizers={} sinks={}",
            sources.len(),
            sanitizers.len(),
            sinks.len()
        ),
    }
}

fn rule_to_dot(rule: &CompiledRule) -> String {
    let mut out = String::from("digraph Rule {\n");
    out.push_str("    rankdir=LR;\n");
    out.push_str("    node [shape=box, fontname=\"Arial\"];\n\n");

    let rule_label = format!(
        "Rule: {}\\nSeverity: {:?}\\nCategory: {}\\nInterfile: {}",
        escape_dot(&rule.id),
        rule.severity,
        escape_dot(&rule.category),
        rule.interfile
    );
    out.push_str(&format!("    rule [label=\"{}\"];\n", rule_label));

    if !rule.message.is_empty() {
        out.push_str(&format!(
            "    message [shape=note, label=\"Message: {}\"];\n",
            escape_dot(&truncate(&rule.message, 120))
        ));
        out.push_str("    rule -> message;\n");
    }

    if let Some(remediation) = &rule.remediation {
        if !remediation.is_empty() {
            out.push_str(&format!(
                "    remediation [shape=folder, label=\"Remediation: {}\"];\n",
                escape_dot(&truncate(remediation, 120))
            ));
            out.push_str("    rule -> remediation;\n");
        }
    }

    let matcher = matcher_summary(rule);
    out.push_str(&format!(
        "    matcher [shape=component, label=\"Matcher: {}\"];\n",
        escape_dot(&truncate(&matcher, 160))
    ));
    out.push_str("    rule -> matcher;\n");

    out.push('}');
    out
}

fn rule_to_mermaid(rule: &CompiledRule) -> String {
    let mut out = String::from("graph TD\n");
    out.push_str(&format!(
        "    rule[\"Rule: {}<br/>Severity: {:?}<br/>Category: {}<br/>Interfile: {}\"]\n",
        escape_mermaid(&rule.id),
        rule.severity,
        escape_mermaid(&rule.category),
        rule.interfile
    ));

    if !rule.message.is_empty() {
        out.push_str(&format!(
            "    message[\"Message: {}\"]\n",
            escape_mermaid(&truncate(&rule.message, 120))
        ));
        out.push_str("    rule --> message\n");
    }

    if let Some(remediation) = &rule.remediation {
        if !remediation.is_empty() {
            out.push_str(&format!(
                "    remediation[\"Remediation: {}\"]\n",
                escape_mermaid(&truncate(remediation, 120))
            ));
            out.push_str("    rule --> remediation\n");
        }
    }

    let matcher = matcher_summary(rule);
    out.push_str(&format!(
        "    matcher[\"Matcher: {}\"]\n",
        escape_mermaid(&truncate(&matcher, 160))
    ));
    out.push_str("    rule --> matcher\n");

    out
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = String::new();
    for ch in value.chars().take(max_chars.saturating_sub(1)) {
        truncated.push(ch);
    }
    truncated.push('…');
    truncated
}

fn escape_dot(value: &str) -> String {
    value
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('|', "\\|")
}

fn escape_mermaid(value: &str) -> String {
    value
        .replace('"', "\\\"")
        .replace('\n', "<br/>")
        .replace('[', "&#91;")
        .replace(']', "&#93;")
}
