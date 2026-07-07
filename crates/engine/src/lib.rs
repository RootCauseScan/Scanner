//! Analysis engine that evaluates rules over the intermediate representation.
//! Orchestrates parallel execution, applies timeouts and generates findings.

use ir::{AstNode, FileAst, FileIR};
use loader::schema::compiled::GENERIC_LANGUAGE;
use loader::{
    semgrep_to_regex, semgrep_to_regex_exact, AnyRegex, AstPattern as LoaderAstPattern,
    MetaVar as LoaderMetaVar,
};
pub use loader::{CompiledRule, MatcherKind, RuleSet, Severity, SubMatcher, TaintPattern};
use parsers::ParserMetrics;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread_local;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use rego_wasm::RegoWasm;
use tokio::runtime::{Handle, Runtime};

pub mod cache;
pub mod cfg;
pub mod dataflow;
pub mod debug;
pub mod dfg;
pub mod function_taint;
mod hash;
pub mod pattern;
pub mod plugin;
pub mod regex_ext;
pub use cache::AnalysisCache;
pub use cfg::{build_cfg, has_unsanitized_route};
pub use debug::{set_debug_sink, DebugEvent, DebugSink};
pub use dfg::{build_dfg, link_nodes, mark_sanitized};
pub use function_taint::{
    all_function_taints, get_function_taint, record_function_taints, reset_function_taints,
    FunctionTaint,
};
mod path;
use path::cache_stats;
pub use path::{
    canonical_cache_stats, path_regex_cache_contains, path_regex_cache_size, reset_canonical_cache,
    reset_path_regex_cache,
};
pub use path::{
    canonicalize_path, path_matches, set_canonical_cache_capacity, set_path_regex_cache_capacity,
    CANONICAL_CACHE_CAPACITY, CANONICAL_PATHS, PATH_REGEX_CACHE_CAPACITY,
};

use crate::debug::emit;
use cache::rule_cache::{RuleCache, RuleCacheKey};

// ── Inter-file taint state ────────────────────────────────────────────────────
// Collects per-file source/sink data during parallel analysis; a sequential
// second pass then connects them through the CallGraph.

#[derive(Default)]
struct InterFileTaintState {
    /// rule_id → [(enclosing_func_name, file_path)]
    source_funcs: HashMap<String, Vec<(String, String)>>,
    /// rule_id → [(enclosing_func_name, file_path, sink_text, line, col, excerpt)]
    sink_funcs: HashMap<String, Vec<(String, String, String, usize, usize, String)>>,
}

static INTER_FILE_TAINT: OnceLock<Mutex<InterFileTaintState>> = OnceLock::new();

fn inter_file_state() -> &'static Mutex<InterFileTaintState> {
    INTER_FILE_TAINT.get_or_init(|| Mutex::new(InterFileTaintState::default()))
}

fn reset_inter_file_state() {
    if let Ok(mut s) = inter_file_state().lock() {
        s.source_funcs.clear();
        s.sink_funcs.clear();
    }
}

/// Returns the qualified name (ClassName.methodName) of the function that
/// contains `target_line` in the file's AST. Used for inter-file taint.
fn enclosing_function_name(file: &FileIR, target_line: usize) -> Option<String> {
    let ast = file.ast.as_ref()?;
    let mut best: Option<(usize, String)> = None;
    collect_func_for_line(&ast.nodes, target_line, None, &mut best);
    best.map(|(_, name)| name)
}

fn collect_func_for_line(
    nodes: &[AstNode],
    target_line: usize,
    class_ctx: Option<&str>,
    best: &mut Option<(usize, String)>,
) {
    for node in nodes {
        let cur_class: Option<&str> = if node.kind == "ClassDeclaration" {
            node.value.as_str().or(class_ctx)
        } else {
            class_ctx
        };
        if (node.kind.contains("Function") || node.kind == "MethodDeclaration")
            && node.meta.line <= target_line
        {
            if let Some(name) = node.value.as_str() {
                let qualified = match cur_class {
                    Some(cls) => format!("{cls}.{name}"),
                    None => name.to_string(),
                };
                let start = node.meta.line;
                if best.as_ref().map_or(true, |(l, _)| start >= *l) {
                    *best = Some((start, qualified));
                }
            }
        }
        collect_func_for_line(&node.children, target_line, cur_class, best);
    }
}

fn record_interfile_sources(rule: &CompiledRule, file: &FileIR, source_syms: &[(String, usize, usize)]) {
    let mut state = match inter_file_state().lock() {
        Ok(s) => s,
        Err(e) => e.into_inner(),
    };
    let entry = state.source_funcs.entry(rule.id.clone()).or_default();
    for (_, line, _) in source_syms {
        if let Some(func) = enclosing_function_name(file, *line) {
            let key = (func, file.file_path.clone());
            if !entry.contains(&key) {
                entry.push(key);
            }
        }
    }
}

fn record_interfile_sinks(
    rule: &CompiledRule,
    file: &FileIR,
    sink_hits: &[(String, usize, usize, String)],
) {
    let mut state = match inter_file_state().lock() {
        Ok(s) => s,
        Err(e) => e.into_inner(),
    };
    let entry = state.sink_funcs.entry(rule.id.clone()).or_default();
    for (sink_text, line, col, excerpt) in sink_hits {
        if let Some(func) = enclosing_function_name(file, *line) {
            entry.push((
                func,
                file.file_path.clone(),
                sink_text.clone(),
                *line,
                *col,
                excerpt.clone(),
            ));
        }
    }
}

/// Returns true if `callee` (from the CallGraph, e.g. "service.doThing") could
/// refer to `sink_func` (class-qualified, e.g. "ServiceClass.doThing").
/// Matches on the method-name suffix to bridge instance-variable vs class-name prefixes.
fn callee_matches_sink_func(callee: &str, sink_func: &str) -> bool {
    if callee == sink_func {
        return true;
    }
    let callee_method = callee.rsplit_once('.').map(|(_, m)| m).unwrap_or(callee);
    let sink_method = sink_func.rsplit_once('.').map(|(_, m)| m).unwrap_or(sink_func);
    !callee_method.is_empty()
        && !sink_method.is_empty()
        && callee_method == sink_method
        && callee.contains('.')
}

fn eval_interfile_taint(rules: &RuleSet) -> Vec<Finding> {
    let state = match inter_file_state().lock() {
        Ok(s) => s,
        Err(e) => e.into_inner(),
    };
    let call_graph = dataflow::get_call_graph();
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    for rule in &rules.rules {
        if !matches!(rule.matcher, MatcherKind::TaintRule { .. }) {
            continue;
        }
        let source_funcs = match state.source_funcs.get(&rule.id) {
            Some(v) => v,
            None => continue,
        };
        let sink_funcs = match state.sink_funcs.get(&rule.id) {
            Some(v) => v,
            None => continue,
        };

        for (src_func, src_file) in source_funcs {
            let Some(callees) = call_graph.edges.get(src_func) else {
                continue;
            };
            for (sink_func, sink_file, _sink_text, line, col, excerpt) in sink_funcs {
                if src_file == sink_file {
                    continue; // per-file analysis already handled this
                }
                let connected = callees
                    .iter()
                    .any(|callee| callee_matches_sink_func(callee, sink_func));
                if !connected {
                    continue;
                }
                let id = blake3::hash(
                    format!("{}:{}:{}:{}", rule.id, sink_file, line, col).as_bytes(),
                )
                .to_hex()
                .to_string();
                if seen_ids.insert(id.clone()) {
                    findings.push(Finding {
                        id,
                        rule_id: rule.id.clone(),
                        rule_file: rule.source_file.clone(),
                        severity: rule.severity,
                        file: PathBuf::from(sink_file),
                        line: *line,
                        column: *col,
                        excerpt: excerpt.clone(),
                        message: rule.message.clone(),
                        remediation: rule.remediation.clone(),
                        fix: rule.fix.clone(),
                    });
                }
            }
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────

pub fn parse_file_with_events(
    path: &Path,
    suppress_comment: Option<&str>,
    metrics: Option<&mut ParserMetrics>,
) -> anyhow::Result<Option<FileIR>> {
    emit(DebugEvent::ParseStart {
        path: path.to_path_buf(),
    });
    let res = parsers::parse_file(path, suppress_comment, metrics);
    emit(DebugEvent::ParseEnd {
        path: path.to_path_buf(),
    });
    res
}

pub fn load_rules_with_events(path: &Path) -> anyhow::Result<RuleSet> {
    let rules = loader::load_rules(path)?;
    for r in &rules.rules {
        emit(DebugEvent::RuleCompiled { id: r.id.clone() });
    }
    Ok(rules)
}

/// Searches for a contamination path from a definition to a use.
/// Performs a BFS over the edges of the `DataFlowGraph`, ignoring symbols
/// marked as sanitized. Returns the sequence of nodes from source
/// to sink if it exists.
pub fn find_taint_path(fir: &FileIR, source: &str, sink: &str) -> Option<Vec<usize>> {
    let dfg = fir.dfg.as_ref()?;

    fn is_unsanitized(fir: &FileIR, name: &str) -> bool {
        fir.symbols.get(name).is_none_or(|s| !s.sanitized)
    }

    let mut id_to_idx = HashMap::new();
    for (i, node) in dfg.nodes.iter().enumerate() {
        id_to_idx.insert(node.id, i);
    }
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); dfg.nodes.len()];
    let mut indegree: Vec<usize> = vec![0; dfg.nodes.len()];
    for &(from, to) in &dfg.edges {
        if let (Some(&f), Some(&t)) = (id_to_idx.get(&from), id_to_idx.get(&to)) {
            adj[f].push(t);
            indegree[t] += 1;
        }
    }

    // Collect the names of variables referenced in the sink text so we can
    // identify DFG nodes that represent the sink end of the path.
    let sink_vars: HashSet<String> = extract_sink_variables(sink)
        .into_iter()
        .map(|(name, _)| name)
        .collect();

    // If none of the sink_vars appear as DFG node names, the sink parameter is
    // a function name rather than a variable — fall back to legacy mode (any
    // unsanitized Use node is accepted as the sink endpoint).
    let any_sink_node_exists = !sink_vars.is_empty()
        && dfg.nodes.iter().any(|n| sink_vars.contains(&n.name));

    // Determine the source node name (strip leading '$' for PHP superglobals).
    let source_key = source.trim_start_matches('$');

    let mut queue: VecDeque<(usize, Vec<usize>)> = VecDeque::new();
    let mut visited = vec![false; dfg.nodes.len()];

    // Seed BFS from every Def/Param node whose name matches the source variable.
    // Fall back to all zero-indegree unsanitized Def nodes when the source name
    // is empty or not found in the DFG (preserves existing behaviour for callers
    // that pass an empty source string).
    let seeded_from_source = dfg.nodes.iter().enumerate().any(|(_, n)| {
        (n.name == source || n.name == source_key)
            && matches!(n.kind, ir::DFNodeKind::Def | ir::DFNodeKind::Param)
    });

    for (idx, node) in dfg.nodes.iter().enumerate() {
        let is_source_node = if seeded_from_source {
            (node.name == source || node.name == source_key)
                && matches!(node.kind, ir::DFNodeKind::Def | ir::DFNodeKind::Param)
                && is_unsanitized(fir, &node.name)
        } else {
            // Fallback: any zero-indegree unsanitized Def
            matches!(node.kind, ir::DFNodeKind::Def)
                && indegree[idx] == 0
                && is_unsanitized(fir, &node.name)
        };
        if is_source_node && !visited[idx] {
            queue.push_back((idx, vec![idx]));
            visited[idx] = true;
        }
    }

    while let Some((current, path)) = queue.pop_front() {
        let cur_node = &dfg.nodes[current];

        // A path reaches the sink when we find a node whose name appears in the
        // sink text (or the sink text itself matches).  We accept Def, Use and
        // Assign nodes as potential sink endpoints.
        let reaches_sink = !sink_vars.is_empty()
            && sink_vars.contains(&cur_node.name)
            && matches!(
                cur_node.kind,
                ir::DFNodeKind::Use | ir::DFNodeKind::Def | ir::DFNodeKind::Assign
            );

        // Also accept the legacy condition (any unsanitized Use) when we have no
        // sink variable information, or when the sink name doesn't correspond to
        // any variable in the DFG (i.e. it's a function name like "sink").
        let legacy_sink = !any_sink_node_exists
            && matches!(cur_node.kind, ir::DFNodeKind::Use)
            && is_unsanitized(fir, &cur_node.name);

        if reaches_sink || legacy_sink {
            return Some(path);
        }

        for &next in &adj[current] {
            if visited[next] || !is_unsanitized(fir, &dfg.nodes[next].name) {
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(next);
            visited[next] = true;
            queue.push_back((next, next_path));
        }
    }
    None
}

/// Returns true if in the DFG there is a path from the definition of `source_sym`
/// to any node (Def or Use) whose name is in `sink_vars`. Used for PHP when the
/// sink uses an intermediate variable (e.g. $id) that flows from a superglobal.
fn dfg_reaches_any_var(fir: &FileIR, source_sym: &str, sink_vars: &[String]) -> bool {
    let dfg = match fir.dfg.as_ref() {
        Some(d) => d,
        None => return false,
    };
    let sym_key = source_sym.trim_start_matches('$');
    let def_id = match fir.symbols.get(sym_key).or_else(|| fir.symbols.get(source_sym)).and_then(|s| s.def) {
        Some(id) => id,
        None => return false,
    };
    let id_to_idx: HashMap<_, _> = dfg
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.id, i))
        .collect();
    let start_idx = match id_to_idx.get(&def_id) {
        Some(&i) => i,
        None => return false,
    };
    let sink_set: HashSet<&str> = sink_vars.iter().map(String::as_str).collect();
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); dfg.nodes.len()];
    for &(from, to) in &dfg.edges {
        if let (Some(&f), Some(&t)) = (id_to_idx.get(&from), id_to_idx.get(&to)) {
            adj[f].push(t);
        }
    }
    let mut visited = vec![false; dfg.nodes.len()];
    let mut queue = VecDeque::new();
    queue.push_back(start_idx);
    visited[start_idx] = true;
    while let Some(idx) = queue.pop_front() {
        let name = &dfg.nodes[idx].name;
        if sink_set.contains(name.as_str()) {
            return true;
        }
        for &next in &adj[idx] {
            if !visited[next] {
                visited[next] = true;
                queue.push_back(next);
            }
        }
    }
    false
}

pub use hash::{analyze_files_cached, rules_fingerprint};

static RAYON_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

fn thread_pool() -> &'static rayon::ThreadPool {
    RAYON_POOL.get_or_init(|| ThreadPoolBuilder::new().build().expect("rayon thread pool"))
}

static TOKIO: OnceLock<Runtime> = OnceLock::new();

fn init_tokio() {
    let _ = TOKIO.get_or_init(|| Runtime::new().expect("tokio runtime"));
}

fn tokio_handle() -> Handle {
    TOKIO.get().expect("tokio runtime").handle().clone()
}
thread_local! {
    static WASM_POOL: RefCell<HashMap<String, Vec<RegoWasm>>> = RefCell::new(HashMap::new());
}

/// Pre-loads WASM instances for Rego rules and avoids repeated initialisations.
pub fn warmup_wasm_rules(rules: &RuleSet) {
    init_tokio();
    let handle = Handle::try_current().unwrap_or_else(|_| tokio_handle());
    for rule in &rules.rules {
        if let MatcherKind::RegoWasm { wasm_path, .. } = &rule.matcher {
            debug!("Loading WASM rule: {}", wasm_path);
            let bytes = match fs::read(wasm_path) {
                Ok(b) => b,
                Err(e) => {
                    warn!(path = %wasm_path, error = ?e, "failed to read WASM");
                    continue;
                }
            };
            debug!("Compiling WASM rule: {}", wasm_path);
            let start = std::time::Instant::now();
            let instance = match handle.block_on(RegoWasm::from_bytes_with_limits(
                &bytes,
                None,
                Some(WASM_FUEL),
                Some(WASM_MEMORY),
            )) {
                Ok(i) => {
                    let elapsed = start.elapsed();
                    debug!(
                        "WASM rule compiled successfully: {} in {:?}",
                        wasm_path, elapsed
                    );
                    i
                }
                Err(e) => {
                    warn!(path = %wasm_path, error = ?e, "failed to instantiate Rego WASM");
                    continue;
                }
            };
            WASM_POOL.with(|pool| {
                let mut map = pool.borrow_mut();
                map.entry(wasm_path.clone()).or_default().push(instance);
            });
        }
    }
}

struct ApplicableRuleIndex<'a> {
    total_rules: usize,
    generic: Arc<[&'a CompiledRule]>,
    by_language: HashMap<String, Arc<[&'a CompiledRule]>>,
    empty: Arc<[&'a CompiledRule]>,
}

impl<'a> ApplicableRuleIndex<'a> {
    fn new(rules: &'a RuleSet) -> Self {
        let total_rules = rules.rules.len();
        let mut generic_entries: Vec<(usize, &'a CompiledRule)> = Vec::new();
        let mut by_language_entries: HashMap<String, Vec<(usize, &'a CompiledRule)>> =
            HashMap::new();

        for (idx, rule) in rules.rules.iter().enumerate() {
            if rule.languages.iter().any(|lang| lang == GENERIC_LANGUAGE) {
                generic_entries.push((idx, rule));
                continue;
            }
            for lang in &rule.languages {
                let normalized = lang.trim().to_ascii_lowercase();
                by_language_entries
                    .entry(normalized)
                    .or_default()
                    .push((idx, rule));
            }
        }

        let generic_vec: Vec<&'a CompiledRule> =
            generic_entries.iter().map(|(_, rule)| *rule).collect();
        let generic = Arc::from(generic_vec.into_boxed_slice());
        let empty = Arc::from(Vec::<&'a CompiledRule>::new().into_boxed_slice());

        let mut by_language = HashMap::with_capacity(by_language_entries.len());
        for (lang, specific_rules) in by_language_entries {
            let mut merged: Vec<&'a CompiledRule> =
                Vec::with_capacity(generic_entries.len() + specific_rules.len());
            let mut generic_idx = 0;
            let mut specific_idx = 0;
            while generic_idx < generic_entries.len() && specific_idx < specific_rules.len() {
                if generic_entries[generic_idx].0 < specific_rules[specific_idx].0 {
                    merged.push(generic_entries[generic_idx].1);
                    generic_idx += 1;
                } else {
                    merged.push(specific_rules[specific_idx].1);
                    specific_idx += 1;
                }
            }
            merged.extend(
                generic_entries
                    .iter()
                    .skip(generic_idx)
                    .map(|(_, rule)| *rule),
            );
            merged.extend(
                specific_rules
                    .iter()
                    .skip(specific_idx)
                    .map(|(_, rule)| *rule),
            );
            by_language.insert(lang, Arc::from(merged.into_boxed_slice()));
        }

        Self {
            total_rules,
            generic,
            by_language,
            empty,
        }
    }

    fn rules_for(&self, file_type: &str) -> Arc<[&'a CompiledRule]> {
        let trimmed = file_type.trim();
        if trimmed.is_empty() {
            return if self.generic.is_empty() {
                self.empty.clone()
            } else {
                self.generic.clone()
            };
        }
        let key = trimmed.to_ascii_lowercase();
        self.by_language.get(&key).cloned().unwrap_or_else(|| {
            if self.generic.is_empty() {
                self.empty.clone()
            } else {
                self.generic.clone()
            }
        })
    }

    fn total_rules(&self) -> usize {
        self.total_rules
    }
}

const WASM_FUEL: u64 = 10_000_000;
const WASM_MEMORY: usize = 10 * 1024 * 1024; // 10MB
const WASM_TIMEOUT: Duration = Duration::from_secs(2);
const AST_QUERY_TIMEOUT: Duration = Duration::from_millis(100);
// Guard for fancy-regex scanning to avoid catastrophic backtracking
const FANCY_REGEX_GUARD: Duration = Duration::from_millis(300);
const AST_QUERY_MAX_NODES: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Result of evaluating a rule over a file.
/// Contains basic information for reports.
pub struct Finding {
    /// Unique identifier of the finding.
    pub id: String,
    /// Rule that generated the finding.
    pub rule_id: String,
    /// File where the rule is defined.
    pub rule_file: Option<String>,
    /// Severity assigned by the rule.
    pub severity: Severity,
    /// Path of the affected file.
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    /// Relevant code fragment.
    pub excerpt: String,
    /// Descriptive message of the problem.
    pub message: String,
    /// Suggested steps to remediate.
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
/// Minimal entry to represent a finding in a baseline.
pub struct BaselineEntry {
    /// Finding identifier.
    pub id: String,
    /// Normalised file path.
    pub file: PathBuf,
    /// Associated line in the file.
    pub line: usize,
}

impl From<&Finding> for BaselineEntry {
    fn from(f: &Finding) -> Self {
        BaselineEntry {
            id: f.id.clone(),
            file: canonicalize_path(&f.file),
            line: f.line,
        }
    }
}

fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));
}

static RULE_CACHE: OnceLock<RuleCache> = OnceLock::new();
static RULE_CACHE_RUNTIME_CAPACITY: AtomicUsize = AtomicUsize::new(1024);
static SLOW_RULE_DELAYS: OnceLock<Mutex<HashMap<String, Duration>>> = OnceLock::new();

pub const RULE_CACHE_CAPACITY: usize = 1024;

pub fn set_rule_cache_capacity(n: usize) {
    RULE_CACHE_RUNTIME_CAPACITY.store(n, Ordering::Relaxed);
    reset_rule_cache();
}

pub fn register_slow_rule_delay(rule_id: &str, delay: Duration) {
    let registry = SLOW_RULE_DELAYS.get_or_init(|| Mutex::new(HashMap::new()));
    registry
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(rule_id.to_string(), delay);
}

fn rule_cache_stats_inner() -> (usize, usize) {
    rule_cache().stats()
}

pub fn reset_rule_cache() {
    if let Some(cache) = RULE_CACHE.get() {
        cache.reset();
    }
}

pub fn rule_cache_stats() -> (usize, usize) {
    rule_cache_stats_inner()
}

pub fn eval_rule(file: &FileIR, rule: &CompiledRule) -> Vec<Finding> {
    debug!(
        "eval_rule: Starting evaluation of rule '{}' for file '{}'",
        rule.id, file.file_path
    );
    let key = RuleCacheKey {
        file: PathBuf::from(&file.file_path),
        rule_id: rule.id.clone(),
        content_hash: cache::hash_file(file),
    };

    let cap = RULE_CACHE_RUNTIME_CAPACITY.load(Ordering::Relaxed);
    let (result, hit) = rule_cache().get_or_insert(key, cap, || {
        debug!(
            "eval_rule: Calling eval_rule_impl for rule '{}' and file '{}'",
            rule.id, file.file_path
        );
        let res = eval_rule_impl(file, rule);
        debug!(
            "eval_rule: eval_rule_impl completed for rule '{}' and file '{}', found {} findings",
            rule.id,
            file.file_path,
            res.len()
        );
        res
    });

    if !hit {
        debug!(
            "eval_rule: Completed evaluation of rule '{}' for file '{}'",
            rule.id, file.file_path
        );
    }

    result
}

fn rule_cache() -> &'static RuleCache {
    RULE_CACHE.get_or_init(RuleCache::default)
}

fn regex_ranges_any(source: &str, regs: &[AnyRegex]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for re in regs {
        if re.is_fancy() {
            // Use the same protection for fancy regex as in other places
            let start_guard = Instant::now();
            let mut offset = 0usize;
            for seg in source.split_inclusive('\n') {
                if start_guard.elapsed() > FANCY_REGEX_GUARD {
                    debug!("regex_ranges_any: Aborting fancy regex scan due to guard timeout");
                    break;
                }
                let mut match_count = 0;
                for (ls, le) in re.find_iter(seg) {
                    // Prevent infinite loops in fancy regex by limiting matches per segment
                    match_count += 1;
                    if match_count > 1000 {
                        debug!("regex_ranges_any: Aborting fancy regex scan due to too many matches in segment");
                        break;
                    }

                    // Check timeout more frequently within the iterator
                    if start_guard.elapsed() > FANCY_REGEX_GUARD {
                        debug!("regex_ranges_any: Aborting fancy regex scan due to guard timeout in iterator");
                        break;
                    }

                    let s = offset + ls;
                    let e = offset + le;
                    ranges.push((s, e));
                }
                offset += seg.len();
            }
        } else {
            for (s, e) in re.find_iter(source) {
                ranges.push((s, e));
            }
        }
    }
    ranges
}

fn line_col_at(source: &str, pos: usize) -> (usize, usize) {
    let pos = floor_char_boundary(source, pos);
    let mut line = 1usize;
    let mut line_start = 0usize;
    for (idx, ch) in source[..pos].char_indices() {
        if ch == '\n' {
            line += 1;
            line_start = idx + 1;
        }
    }
    let column = pos - line_start + 1;
    (line, column)
}

fn floor_char_boundary(source: &str, pos: usize) -> usize {
    let mut pos = pos.min(source.len());
    while pos > 0 && !source.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
}

static ASSIGN_LHS_RE: OnceLock<Regex> = OnceLock::new();

fn derive_assignment_lhs(source: &str, pos: usize) -> Option<String> {
    let pos = floor_char_boundary(source, pos);
    let line_start = source[..pos].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    let prefix = &source[line_start..pos];
    if prefix.is_empty() {
        return None;
    }
    let re = ASSIGN_LHS_RE.get_or_init(|| {
        Regex::new(
            r"(?:(?P<prefix>[$@%&*]+))?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[A-Za-z_][A-Za-z0-9_]*)?\s*=\s*$",
        )
            .expect("valid assignment regex")
    });
    re.captures(prefix)
        .and_then(|caps| caps.name("name").map(|m| m.as_str().to_string()))
}

// Common Java/C/JS keywords that should not be treated as variable names.
const LANG_KEYWORDS: &[&str] = &[
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
    "const", "continue", "default", "do", "double", "else", "enum", "extends", "final",
    "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
    "interface", "long", "native", "new", "package", "private", "protected", "public",
    "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
    "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false",
    "null", "String", "Object", "var", "let", "const", "function", "typeof", "instanceof",
    "in", "of", "async", "await", "yield",
];

fn extract_sink_variables(text: &str) -> Vec<(String, usize)> {
    let mut vars = Vec::new();
    let mut iter = text.char_indices().peekable();

    while let Some((idx, ch)) = iter.next() {
        if ch == '$' {
            // PHP-style variable: $varName
            let mut var_name = String::new();
            while let Some(&(_, next_ch)) = iter.peek() {
                if next_ch.is_ascii_alphanumeric() || next_ch == '_' {
                    var_name.push(next_ch);
                    iter.next();
                } else {
                    break;
                }
            }
            if !var_name.is_empty() {
                vars.push((var_name, idx));
            }
        } else if ch.is_ascii_alphabetic() || ch == '_' {
            // Java/Python/JS identifier: starts with letter or underscore
            let mut var_name = ch.to_string();
            while let Some(&(_, next_ch)) = iter.peek() {
                if next_ch.is_ascii_alphanumeric() || next_ch == '_' {
                    var_name.push(next_ch);
                    iter.next();
                } else {
                    break;
                }
            }
            if var_name.len() > 1 && !LANG_KEYWORDS.contains(&var_name.as_str()) {
                vars.push((var_name, idx));
            }
        }
    }

    vars
}

const PHP_SUPERGLOBALS: &[&str] = &[
    "_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_ENV", "_FILES", "_SESSION", "GLOBALS",
];

fn regex_ranges_with_focus(
    source: &str,
    regs: &[AnyRegex],
    focus_groups: &[Option<usize>],
) -> Vec<(usize, usize, Option<String>)> {
    let mut ranges = Vec::new();
    for (idx, re) in regs.iter().enumerate() {
        let focus_group = focus_groups.get(idx).copied().flatten();
        if re.is_fancy() {
            let start_guard = Instant::now();
            let mut offset = 0usize;
            for seg in source.split_inclusive('\n') {
                if start_guard.elapsed() > FANCY_REGEX_GUARD {
                    debug!(
                        "regex_ranges_with_focus: Aborting fancy regex scan due to guard timeout"
                    );
                    break;
                }
                let mut match_count = 0;
                for (ls, le) in re.find_iter(seg) {
                    match_count += 1;
                    if match_count > 1000 {
                        debug!("regex_ranges_with_focus: Aborting fancy regex scan due to too many matches in segment");
                        break;
                    }
                    if start_guard.elapsed() > FANCY_REGEX_GUARD {
                        debug!("regex_ranges_with_focus: Aborting fancy regex scan due to guard timeout in iterator");
                        break;
                    }

                    let s = offset + ls;
                    let e = offset + le;
                    let captured = focus_group.and_then(|grp| {
                        re.captures(&seg[ls..le])
                            .and_then(|caps| caps.get(grp).map(|m| m.as_str().to_string()))
                    });
                    ranges.push((s, e, captured));
                }
                offset += seg.len();
            }
        } else {
            for (s, e) in re.find_iter(source) {
                let captured = focus_group.and_then(|grp| {
                    re.captures(&source[s..e])
                        .and_then(|caps| caps.get(grp).map(|m| m.as_str().to_string()))
                });
                ranges.push((s, e, captured));
            }
        }
    }
    ranges
}

fn enclosing_block(source: &str, pos: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut start = None;
    let mut depth = 0usize;
    for (i, &b) in bytes[..pos].iter().enumerate().rev() {
        match b {
            b'{' => {
                if depth == 0 {
                    let mut line_start = i;
                    while line_start > 0 && bytes[line_start - 1] != b'\n' {
                        line_start -= 1;
                    }
                    // include the method signature line
                    start = Some(line_start);
                    break;
                } else {
                    depth -= 1;
                }
            }
            b'}' => depth += 1,
            _ => {}
        }
    }
    let s = start?;
    depth = 0;
    let mut end = None;
    for (i, &b) in bytes.iter().enumerate().skip(pos) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                if depth == 0 {
                    end = Some(i + 1);
                    break;
                } else {
                    depth -= 1;
                }
            }
            _ => {}
        }
    }
    end.map(|e| (s, e))
}

/// Collects alias mappings from parser symbol data. Only entries with canonical paths
/// containing `::` are returned so languages without such separators are ignored.
fn use_aliases(file: &FileIR) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = file
        .symbols
        .iter()
        .filter_map(|(name, sym)| {
            sym.alias_of
                .as_ref()
                .filter(|c| c.contains("::"))
                .map(|c| (name.clone(), c.clone()))
        })
        .collect();

    out.extend(file.nodes.iter().filter_map(|n| {
        if let Some(rest) = n.path.strip_prefix("import_from.") {
            let parts: Vec<&str> = rest.split('.').collect();
            if parts.is_empty() {
                return None;
            }
            let alias = n
                .value
                .as_str()
                .unwrap_or_else(|| parts.last().expect("import path has segments"))
                .to_string();
            Some((alias, parts.join(".")))
        } else if let Some(rest) = n.path.strip_prefix("import.") {
            let alias = n
                .value
                .as_str()
                .unwrap_or_else(|| {
                    rest.rsplit([':', '.'])
                        .next()
                        .expect("module path has segments")
                })
                .to_string();
            Some((alias, rest.to_string()))
        } else {
            None
        }
    }));

    out
}

fn analyze_file_inner(file: &FileIR, rule_index: &ApplicableRuleIndex<'_>) -> Vec<Finding> {
    init_tokio();
    let applicable_rules = rule_index.rules_for(&file.file_type);
    debug!(
        "Analyzing file '{}' with {} applicable rules (total rules: {})",
        file.file_path,
        applicable_rules.len(),
        rule_index.total_rules()
    );
    debug!("Starting rule evaluation for file '{}'", file.file_path);
    let findings: Vec<Finding> = applicable_rules
        .iter()
        .copied()
        .flat_map(|r| {
            debug!("Evaluating rule '{}' for file '{}'", r.id, file.file_path);
            let result = eval_rule(file, r);
            debug!(
                "Rule '{}' evaluation completed for file '{}', found {} findings",
                r.id,
                file.file_path,
                result.len()
            );
            result
        })
        .collect();
    debug!("Rule evaluation completed for file '{}'", file.file_path);
    debug!(
        "File '{}' analysis completed, found {} findings",
        file.file_path,
        findings.len()
    );
    findings
}

struct FileToAnalyze<'a> {
    file: &'a FileIR,
    hash: Option<String>,
}

struct FileAnalysisResult {
    hash: Option<String>,
    findings: Vec<Finding>,
    metrics: Option<EngineMetrics>,
}

fn analyze_files_inner(
    files: &[FileToAnalyze<'_>],
    rule_index: &ApplicableRuleIndex<'_>,
    cfg: &EngineConfig,
    collect_metrics: bool,
    progress: Option<&Arc<dyn Fn(usize) + Send + Sync + 'static>>,
) -> Vec<FileAnalysisResult> {
    debug!(
        "analyze_files_inner: Starting file processing for {} files",
        files.len()
    );
    let results: Vec<FileAnalysisResult> = files
        .par_iter()
        .map(|item| {
            let display_id = item.hash.as_deref().unwrap_or(&item.file.file_path);
            debug!("analyze_files_inner: Processing file '{}'", display_id);
            let mut per_file_metrics = if collect_metrics {
                Some(EngineMetrics::default())
            } else {
                None
            };
            let findings = analyze_file_with_config_inner(
                item.file,
                rule_index,
                cfg,
                per_file_metrics.as_mut(),
            );
            debug!(
                "analyze_files_inner: Completed processing file '{}', found {} findings",
                display_id,
                findings.len()
            );
            if let Some(cb) = progress {
                cb(1);
            }
            FileAnalysisResult {
                hash: item.hash.clone(),
                findings,
                metrics: per_file_metrics,
            }
        })
        .collect();
    debug!("analyze_files_inner: Completed file processing");
    results
}

pub fn analyze_files(
    files: &[FileIR],
    rules: &RuleSet,
    cache: Option<&mut AnalysisCache>,
) -> Vec<Finding> {
    analyze_files_with_config(files, rules, &EngineConfig::default(), cache, None, None)
}

#[derive(Debug, Clone, Default)]
pub struct EngineConfig {
    pub file_timeout: Option<Duration>,
    pub rule_timeout: Option<Duration>,
    pub baseline: Option<HashSet<BaselineEntry>>,
    pub suppress_comment: Option<String>,
    pub analysis_errors: Option<Arc<Mutex<Vec<AnalysisError>>>>,
}

#[derive(Debug, Clone)]
pub enum AnalysisError {
    RuleTimeout {
        rule_id: String,
        file_path: String,
        timeout_ms: u128,
    },
    RulePanic {
        rule_id: String,
        file_path: String,
    },
}

#[derive(Debug, Default, Serialize)]
pub struct EngineMetrics {
    pub file_times_ms: HashMap<String, u128>,
    pub rule_times_ms: HashMap<String, u128>,
    pub findings: usize,
    pub canonical_cache_hits: usize,
    pub canonical_cache_misses: usize,
    pub rule_cache_hits: usize,
    pub rule_cache_misses: usize,
    pub parser: ParserMetrics,
}

fn rules_require_call_graph(rules: &RuleSet) -> bool {
    rules
        .rules
        .iter()
        .any(|rule| rule.interfile || matches!(rule.matcher, MatcherKind::TaintRule { .. }))
}

fn configure_call_graph(files: &[FileIR], rules: &RuleSet) {
    if rules_require_call_graph(rules) {
        dataflow::set_call_graph(dataflow::CallGraph::build(files));
    } else {
        dataflow::set_call_graph(dataflow::CallGraph::default());
    }
}

pub fn analyze_files_with_config(
    files: &[FileIR],
    rules: &RuleSet,
    cfg: &EngineConfig,
    mut cache: Option<&mut AnalysisCache>,
    mut metrics: Option<&mut EngineMetrics>,
    progress: Option<&Arc<dyn Fn(usize) + Send + Sync + 'static>>,
) -> Vec<Finding> {
    reset_function_taints();
    reset_inter_file_state();
    configure_call_graph(files, rules);
    warmup_wasm_rules(rules);
    let rule_index = ApplicableRuleIndex::new(rules);
    let rules_hash = if cache.is_some() {
        Some(hash::rules_fingerprint(rules))
    } else {
        None
    };
    if let (Some(cache_ref), Some(hash)) = (cache.as_deref_mut(), rules_hash.as_ref()) {
        cache_ref.set_rules_hash(hash.clone());
    }
    debug!(
        "Starting analysis with config of {} files with {} rules",
        files.len(),
        rules.rules.len()
    );
    let mut cached = Vec::new();
    let mut to_analyze = Vec::new();
    if cache.is_some() {
        for f in files {
            let hash = cache::hash_file(f);
            if let Some(cached_findings) = cache.as_ref().and_then(|c| c.get(&hash)) {
                cached.extend(cached_findings.clone());
            } else {
                to_analyze.push(FileToAnalyze {
                    file: f,
                    hash: Some(hash),
                });
            }
        }
    } else {
        for f in files {
            to_analyze.push(FileToAnalyze {
                file: f,
                hash: None,
            });
        }
    }

    let collect_metrics = metrics.is_some();
    let parallel_results =
        analyze_files_inner(&to_analyze, &rule_index, cfg, collect_metrics, progress);

    let mut findings: Vec<Finding> = Vec::new();
    for result in parallel_results {
        if let Some(hash) = result.hash.as_ref() {
            if let Some(rules_hash) = rules_hash.as_deref() {
                if let Some(c) = cache.as_deref_mut() {
                    c.insert(hash.clone(), result.findings.clone(), rules_hash);
                }
            }
        }
        if let (Some(m), Some(per_file)) = (metrics.as_deref_mut(), result.metrics) {
            for (k, v) in per_file.file_times_ms {
                m.file_times_ms.insert(k, v);
            }
            for (k, v) in per_file.rule_times_ms {
                *m.rule_times_ms.entry(k).or_insert(0) += v;
            }
        }
        findings.extend(result.findings);
    }
    findings.extend(cached);

    // Inter-file taint: connect sources in one file to sinks in a callee file.
    findings.extend(eval_interfile_taint(rules));

    // Apply baseline filtering
    if let Some(baseline) = &cfg.baseline {
        findings.retain(|f| !baseline.contains(&BaselineEntry::from(f)));
    }

    // Apply inline suppression filtering
    if cfg.suppress_comment.is_some() {
        let suppressed: HashMap<_, _> = files
            .iter()
            .map(|f| (PathBuf::from(&f.file_path), &f.suppressed))
            .collect();
        findings.retain(|f| {
            suppressed
                .get(&f.file)
                .is_none_or(|set| !set.contains(&f.line))
        });
    }

    dedup_findings(&mut findings);

    if let Some(m) = metrics {
        m.findings = findings.len();
        let (hits, misses) = cache_stats();
        m.canonical_cache_hits = hits;
        m.canonical_cache_misses = misses;
        let (rh, rm) = rule_cache_stats_inner();
        m.rule_cache_hits = rh;
        m.rule_cache_misses = rm;
    }

    findings
}

pub fn analyze_files_streaming<I>(
    files: I,
    rules: &RuleSet,
    cfg: &EngineConfig,
    mut cache: Option<&mut AnalysisCache>,
    mut metrics: Option<&mut EngineMetrics>,
    progress: Option<&Arc<dyn Fn(usize) + Send + Sync + 'static>>,
) -> Vec<Finding>
where
    I: IntoIterator<Item = FileIR>,
{
    function_taint::reset_function_taints();
    let needs_call_graph = rules_require_call_graph(rules);
    if !needs_call_graph {
        dataflow::set_call_graph(dataflow::CallGraph::default());
    }
    warmup_wasm_rules(rules);
    let rule_index = ApplicableRuleIndex::new(rules);
    let rules_hash = if cache.is_some() {
        Some(hash::rules_fingerprint(rules))
    } else {
        None
    };
    if let (Some(cache_ref), Some(hash)) = (cache.as_deref_mut(), rules_hash.as_ref()) {
        cache_ref.set_rules_hash(hash.clone());
    }
    let mut findings = Vec::new();
    debug!(
        "Starting streaming analysis with {} rules",
        rules.rules.len()
    );
    // When a call graph is needed, collect all files first so the graph spans
    // the entire corpus rather than being rebuilt per-file.
    let mut all_files: Vec<FileIR> = files.into_iter().collect();
    // Link inter-file Java imports so cross-class taint flows are resolved.
    parsers::languages::java::link_java_files(&mut all_files);
    if needs_call_graph {
        dataflow::set_call_graph(dataflow::CallGraph::build(&all_files));
    }

    // Pre-pass: drain cache hits sequentially (cache is &mut, not shareable).
    let mut to_analyze: Vec<(FileIR, Option<String>)> = Vec::with_capacity(all_files.len());
    for f in all_files {
        if let Some(cache_ref) = cache.as_ref() {
            let computed = cache::hash_file(&f);
            if let Some(cached) = cache_ref.get(&computed) {
                findings.extend(cached.clone());
                if let Some(cb) = progress {
                    cb(1);
                }
                continue;
            }
            to_analyze.push((f, Some(computed)));
        } else {
            to_analyze.push((f, None));
        }
    }
    let to_analyze_count = to_analyze.len();
    let cache_hit_count = findings.len();
    debug!(
        "Streaming analysis: {} files to analyze ({} served from cache)",
        to_analyze_count, cache_hit_count
    );

    // Analysis phase: parallel when no per-file metrics tracking is needed.
    // Each file's analysis is independent once the call graph and symbol table
    // are built, so rayon par_iter gives ~N-CPU speedup with no correctness risk.
    // The inner rule-timeout pool (RAYON_POOL) is separate from the global pool
    // used by par_iter, so there is no deadlock.
    let analyzed: Vec<(Option<String>, Vec<Finding>)> = if metrics.is_none() {
        to_analyze
            .par_iter()
            .map(|(f, hash)| {
                let mut res = analyze_file_with_config_inner(f, &rule_index, cfg, None);
                if cfg.suppress_comment.is_some() {
                    res.retain(|fi| !f.suppressed.contains(&fi.line));
                }
                if let Some(cb) = progress {
                    cb(1);
                }
                (hash.clone(), res)
            })
            .collect()
    } else {
        // Sequential path: preserves per-file and per-rule timing in metrics.
        let mut results = Vec::with_capacity(to_analyze.len());
        for (idx, (f, hash)) in to_analyze.into_iter().enumerate() {
            debug!(
                "Streaming analysis: processing file {}: {}",
                idx + 1,
                f.file_path
            );
            let mut res =
                analyze_file_with_config_inner(&f, &rule_index, cfg, metrics.as_deref_mut());
            if cfg.suppress_comment.is_some() {
                res.retain(|fi| !f.suppressed.contains(&fi.line));
            }
            if let Some(cb) = progress {
                cb(1);
            }
            results.push((hash, res));
        }
        results
    };

    // Post-pass: cache inserts (sequential) and collect all findings.
    for (hash, res) in analyzed {
        if let Some(rules_hash) = rules_hash.as_deref() {
            if let Some(c) = cache.as_deref_mut() {
                if let Some(hash_value) = hash.as_ref() {
                    c.insert(hash_value.clone(), res.clone(), rules_hash);
                }
            }
        }
        findings.extend(res);
    }
    debug!(
        "Streaming analysis completed for {} files",
        to_analyze_count + cache_hit_count
    );
    if let Some(baseline) = &cfg.baseline {
        findings.retain(|f| !baseline.contains(&BaselineEntry::from(f)));
    }
    dedup_findings(&mut findings);
    if let Some(m) = metrics {
        m.findings = findings.len();
        let (hits, misses) = cache_stats();
        m.canonical_cache_hits = hits;
        m.canonical_cache_misses = misses;
        let (rh, rm) = rule_cache_stats_inner();
        m.rule_cache_hits = rh;
        m.rule_cache_misses = rm;
    }
    findings
}

/// Combines internal findings with those from plugins.
///
/// Plugin findings are filtered according to `EngineConfig` to apply
/// baseline and suppression comments. They are then deduplicated and merged
/// with internal findings.
pub fn merge_plugin_findings(
    files: &[FileIR],
    mut base: Vec<Finding>,
    mut plugin: Vec<Finding>,
    cfg: &EngineConfig,
) -> Vec<Finding> {
    if let Some(baseline) = &cfg.baseline {
        plugin.retain(|f| !baseline.contains(&BaselineEntry::from(f)));
    }
    if cfg.suppress_comment.is_some() {
        let suppressed: HashMap<_, _> = files
            .iter()
            .map(|f| (PathBuf::from(&f.file_path), &f.suppressed))
            .collect();
        plugin.retain(|f| {
            suppressed
                .get(&f.file)
                .is_none_or(|set| !set.contains(&f.line))
        });
    }
    base.extend(plugin);
    dedup_findings(&mut base);
    base
}

fn analyze_file_with_config_inner(
    file: &FileIR,
    rule_index: &ApplicableRuleIndex<'_>,
    cfg: &EngineConfig,
    mut metrics: Option<&mut EngineMetrics>,
) -> Vec<Finding> {
    init_tokio();
    let start = Instant::now();
    let mut out = Vec::new();
    let pool = thread_pool();
    let operation_timeout = cfg.rule_timeout.or(cfg.file_timeout);
    let file_arc = if operation_timeout.is_some() {
        Some(Arc::new(file.clone()))
    } else {
        None
    };
    let applicable_rules = rule_index.rules_for(&file.file_type);
    for r in applicable_rules.iter().copied() {
        debug!("Evaluating rule '{}' on file '{}'", r.id, file.file_path);
        let rule_start = Instant::now();
        let findings = if let Some(rt) = operation_timeout {
            if rt.is_zero() {
                Vec::new()
            } else {
                // Evaluate rule with timeout via worker thread and channel
                let (tx, rx) = mpsc::channel();
                let file_cloned =
                    Arc::clone(file_arc.as_ref().expect("rule timeout implies shared file"));
                let rule_cloned = Arc::new(r.clone());
                pool.spawn(move || {
                    let res = std::panic::catch_unwind(|| eval_rule(&file_cloned, &rule_cloned));
                    let _ = tx.send(res);
                });
                match rx.recv_timeout(rt) {
                    Ok(Ok(findings)) => findings,
                    Ok(Err(_)) => {
                        if let Some(errors) = &cfg.analysis_errors {
                            let mut guard = errors.lock().unwrap_or_else(|e| e.into_inner());
                            guard.push(AnalysisError::RulePanic {
                                rule_id: r.id.clone(),
                                file_path: file.file_path.clone(),
                            });
                        }
                        Vec::new()
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if let Some(errors) = &cfg.analysis_errors {
                            let mut guard = errors.lock().unwrap_or_else(|e| e.into_inner());
                            guard.push(AnalysisError::RuleTimeout {
                                rule_id: r.id.clone(),
                                file_path: file.file_path.clone(),
                                timeout_ms: rt.as_millis(),
                            });
                        }
                        Vec::new()
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => Vec::new(),
                }
            }
        } else {
            eval_rule(file, r)
        };
        if let Some(m) = metrics.as_deref_mut() {
            let elapsed = rule_start.elapsed().as_millis();
            *m.rule_times_ms.entry(r.id.clone()).or_insert(0) += elapsed;
            debug!(rule = r.id, time_ms = elapsed, "rule evaluated");
        }
        out.extend(findings);
    }
    if let Some(m) = metrics {
        let elapsed = start.elapsed().as_millis();
        m.file_times_ms.insert(file.file_path.clone(), elapsed);
        debug!(file = %file.file_path, time_ms = elapsed, "file analyzed");
    }
    out
}

pub fn analyze_file_with_config(
    file: &FileIR,
    rules: &RuleSet,
    cfg: &EngineConfig,
    metrics: Option<&mut EngineMetrics>,
) -> Vec<Finding> {
    configure_call_graph(std::slice::from_ref(file), rules);
    let rule_index = ApplicableRuleIndex::new(rules);
    analyze_file_with_config_inner(file, &rule_index, cfg, metrics)
}

pub fn analyze_file(file: &FileIR, rules: &RuleSet) -> Vec<Finding> {
    configure_call_graph(std::slice::from_ref(file), rules);
    let rule_index = ApplicableRuleIndex::new(rules);
    analyze_file_inner(file, &rule_index)
}

pub fn load_baseline(path: &Path) -> anyhow::Result<HashSet<BaselineEntry>> {
    let data = fs::read_to_string(path)?;
    let entries: Vec<BaselineEntry> = serde_json::from_str(&data)?;
    Ok(entries.into_iter().collect())
}

pub fn write_baseline(path: &Path, findings: &[Finding]) -> anyhow::Result<()> {
    let entries: Vec<BaselineEntry> = findings.iter().map(BaselineEntry::from).collect();
    let data = serde_json::to_string_pretty(&entries)?;
    fs::write(path, data)?;
    Ok(())
}

fn eval_rule_impl(file: &FileIR, rule: &CompiledRule) -> Vec<Finding> {
    debug!(
        "eval_rule_impl: Starting implementation for rule '{}' and file '{}'",
        rule.id, file.file_path
    );
    emit(DebugEvent::MatchAttempt {
        rule_id: rule.id.clone(),
        file: PathBuf::from(&file.file_path),
    });
    if let Some(delay) = SLOW_RULE_DELAYS
        .get()
        .and_then(|r| r.lock().unwrap_or_else(|e| e.into_inner()).get(&rule.id).copied())
    {
        std::thread::sleep(delay);
    }
    let canonical_path = canonicalize_path(&file.file_path);
    let canonical = canonical_path.to_string_lossy();
    let findings = match &rule.matcher {
        MatcherKind::TextRegex(re, orig) => {
            debug!(rule=%rule.id, file=%file.file_path, kind="TextRegex", fancy=re.is_fancy(), pat=%orig.chars().take(120).collect::<String>());
            let source_owned = if file.source.is_none() && !file.nodes.is_empty() {
                serde_json::to_string(&file.nodes).ok()
            } else {
                None
            };
            let source = file.source.as_deref().or(source_owned.as_deref()).unwrap_or("");
            let mut seen_lines: HashSet<usize> = HashSet::new();
            let mut findings: Vec<Finding> = re
                .find_iter(source)
                .filter_map(|(ms, _me)| {
                    let mut line_num = 1usize;
                    let mut line_start = 0usize;
                    for (idx, ch) in source[..ms].char_indices() {
                        if ch == '\n' {
                            line_num += 1;
                            line_start = idx + 1;
                        }
                    }
                    if !seen_lines.insert(line_num) {
                        return None;
                    }
                    let column = source[line_start..ms].chars().count() + 1;
                    let line_end = source[ms..]
                        .find('\n')
                        .map(|i| ms + i)
                        .unwrap_or(source.len());
                    let excerpt = source[line_start..line_end].to_string();
                    let id = blake3::hash(
                        format!("{}:{}:{}:{}", rule.id, canonical, line_num, column).as_bytes(),
                    )
                    .to_hex()
                    .to_string();
                    Some(Finding {
                        id,
                        rule_id: rule.id.clone(),
                        rule_file: rule.source_file.clone(),
                        severity: rule.severity,
                        file: PathBuf::from(&file.file_path),
                        line: line_num,
                        column,
                        excerpt,
                        message: rule.message.clone(),
                        remediation: rule.remediation.clone(),
                        fix: rule.fix.clone(),
                    })
                })
                .collect();

            let aliases = use_aliases(file);

            if findings.is_empty() && !orig.is_empty() {
                let call_part = orig.split('(').next().unwrap_or("").trim();
                for (alias, module) in &aliases {
                    if call_part == module.as_str()
                        || call_part.starts_with(&(module.clone() + "::"))
                        || call_part.starts_with(&(module.clone() + "."))
                    {
                        let remainder = orig.strip_prefix(module).unwrap_or("");
                        let alias_pattern = format!("{alias}{remainder}");
                        let alias_re_str = semgrep_to_regex(&alias_pattern, &HashMap::new());
                        if let Ok(alias_re) = Regex::new(&alias_re_str) {
                            for (idx, line) in source.lines().enumerate() {
                                if alias_re.is_match(line) {
                                    let line_num = idx + 1;
                                    let id = blake3::hash(
                                        format!("{}:{}:{}:{}", rule.id, canonical, line_num, 1)
                                            .as_bytes(),
                                    )
                                    .to_hex()
                                    .to_string();
                                    findings.push(Finding {
                                        id,
                                        rule_id: rule.id.clone(),
                                        rule_file: rule.source_file.clone(),
                                        severity: rule.severity,
                                        file: PathBuf::from(&file.file_path),
                                        line: line_num,
                                        column: 1,
                                        excerpt: line.to_string(),
                                        message: rule.message.clone(),
                                        remediation: rule.remediation.clone(),
                                        fix: rule.fix.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            findings
        }
        MatcherKind::TextRegexMulti { subs } => {
            debug!(rule=%rule.id, file=%file.file_path, kind="TextRegexMulti", subs=subs.len());
            let source = file.source.as_deref().unwrap_or("");
            let mut findings = Vec::new();
            let aliases = use_aliases(file);
            for sub in subs {
            let allow = &sub.allow;
            let deny = sub.deny.as_ref();
            let inside = &sub.inside;
            let not_inside = &sub.not_inside;
            let inside_ranges = regex_ranges_any(source, inside);
            let not_inside_ranges = regex_ranges_any(source, not_inside);
            if !inside.is_empty() && inside_ranges.is_empty() {
                // This sub requires a context (pattern-inside) not present in
                // this file. Skip this sub and try sibling subs.
                continue;
            }
            for (idx, (re, orig)) in allow.iter().enumerate() {
                if re.is_fancy() {
                    debug!(
                        rule = %rule.id,
                        file = %file.file_path,
                        idx,
                        kind = "TextRegexMulti.allow",
                        fancy = true,
                        pat = %orig.chars().take(120).collect::<String>(),
                        "Scanning fancy regex"
                    );
                }
                // For fancy regexes (look-around), scan line by line to reduce catastrophic backtracking.
                if re.is_fancy() {
                    let start_guard = Instant::now();
                    let mut offset = 0usize;
                    for seg in source.split_inclusive('\n') {
                        if start_guard.elapsed() > FANCY_REGEX_GUARD {
                            debug!(
                                rule = %rule.id,
                                file = %file.file_path,
                                idx,
                                kind = "TextRegexMulti.allow",
                                "Aborting fancy regex scan due to guard timeout"
                            );
                            break;
                        }
                        let mut match_count = 0;
                        for (ls, le) in re.find_iter(seg) {
                            // Prevent infinite loops in fancy regex by limiting matches per segment
                            match_count += 1;
                            if match_count > 1000 {
                                debug!(
                                    rule = %rule.id,
                                    file = %file.file_path,
                                    idx,
                                    kind = "TextRegexMulti.allow",
                                    "Aborting fancy regex scan due to too many matches in segment"
                                );
                                break;
                            }

                            // Check timeout more frequently within the iterator
                            if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                debug!(
                                    rule = %rule.id,
                                    file = %file.file_path,
                                    idx,
                                    kind = "TextRegexMulti.allow",
                                    "Aborting fancy regex scan due to guard timeout in iterator"
                                );
                                break;
                            }

                            let start = offset + ls;
                            let end = offset + le;
                            if let Some(deny_re) = deny {
                                if deny_re.is_match(&source[start..end]) {
                                    continue;
                                }
                            }
                            if !inside_ranges.is_empty()
                                && inside_ranges.iter().all(|(s, e)| start < *s || end > *e)
                            {
                                continue;
                            }
                            let block_match = || {
                                not_inside.iter().any(|re| {
                                    if let Some((s, e)) = enclosing_block(source, start) {
                                        re.is_match(&source[s..e])
                                    } else {
                                        false
                                    }
                                })
                            };
                            let in_not_inside = if !not_inside_ranges.is_empty() {
                                not_inside_ranges
                                    .iter()
                                    .any(|(s, e)| start >= *s && end <= *e)
                                    || block_match()
                            } else {
                                block_match()
                            };
                            if in_not_inside {
                                continue;
                            }
                            let mut line = 1;
                            let mut line_start = 0;
                            for (idx, ch) in source[..start].char_indices() {
                                if ch == '\n' {
                                    line += 1;
                                    line_start = idx + 1;
                                }
                            }
                            let column = start - line_start + 1;
                            let line_end = source[end..]
                                .find('\n')
                                .map(|i| end + i)
                                .unwrap_or_else(|| source.len());
                            let excerpt = source[line_start..line_end].to_string();
                            let id = blake3::hash(
                                format!("{}:{}:{}:{}", rule.id, canonical, line, column).as_bytes(),
                            )
                            .to_hex()
                            .to_string();
                            findings.push(Finding {
                                id,
                                rule_id: rule.id.clone(),
                                rule_file: rule.source_file.clone(),
                                severity: rule.severity,
                                file: PathBuf::from(&file.file_path),
                                line,
                                column,
                                excerpt,
                                message: rule.message.clone(),
                                remediation: rule.remediation.clone(),
                                fix: rule.fix.clone(),
                            });
                        }
                        offset += seg.len();
                    }
                    // Try alias expansion path below too if needed
                } else {
                    for (start, end) in re.find_iter(source) {
                        if let Some(deny_re) = deny {
                            if deny_re.is_match(&source[start..end]) {
                                continue;
                            }
                        }
                        if !inside_ranges.is_empty()
                            && inside_ranges.iter().all(|(s, e)| start < *s || end > *e)
                        {
                            continue;
                        }
                        let block_match = || {
                            not_inside.iter().any(|re| {
                                if let Some((s, e)) = enclosing_block(source, start) {
                                    re.is_match(&source[s..e])
                                } else {
                                    false
                                }
                            })
                        };
                        let in_not_inside = if !not_inside_ranges.is_empty() {
                            not_inside_ranges
                                .iter()
                                .any(|(s, e)| start >= *s && end <= *e)
                                || block_match()
                        } else {
                            block_match()
                        };
                        if in_not_inside {
                            continue;
                        }
                        let mut line = 1;
                        let mut line_start = 0;
                        for (idx, ch) in source[..start].char_indices() {
                            if ch == '\n' {
                                line += 1;
                                line_start = idx + 1;
                            }
                        }
                        let column = start - line_start + 1;
                        let line_end = source[end..]
                            .find('\n')
                            .map(|i| end + i)
                            .unwrap_or_else(|| source.len());
                        let excerpt = source[line_start..line_end].to_string();
                        let id = blake3::hash(
                            format!("{}:{}:{}:{}", rule.id, canonical, line, column).as_bytes(),
                        )
                        .to_hex()
                        .to_string();
                        findings.push(Finding {
                            id,
                            rule_id: rule.id.clone(),
                            rule_file: rule.source_file.clone(),
                            severity: rule.severity,
                            file: PathBuf::from(&file.file_path),
                            line,
                            column,
                            excerpt,
                            message: rule.message.clone(),
                            remediation: rule.remediation.clone(),
                            fix: rule.fix.clone(),
                        });
                    }
                }
                if !orig.is_empty() {
                    let call_part = orig.split('(').next().unwrap_or("").trim();
                    for (alias, module) in &aliases {
                        if call_part == module.as_str()
                            || call_part.starts_with(&(module.clone() + "::"))
                            || call_part.starts_with(&(module.clone() + "."))
                        {
                            let remainder = orig.strip_prefix(module).unwrap_or("");
                            let alias_pattern = format!("{alias}{remainder}");
                            let alias_re_str =
                                semgrep_to_regex_exact(&alias_pattern, &HashMap::new());
                            if let Ok(alias_re) = Regex::new(&alias_re_str) {
                                for m in alias_re.find_iter(source) {
                                    if let Some(deny_re) = deny {
                                        if deny_re.is_match(&source[m.start()..m.end()]) {
                                            continue;
                                        }
                                    }
                                    if !inside_ranges.is_empty()
                                        && inside_ranges
                                            .iter()
                                            .all(|(s, e)| m.start() < *s || m.end() > *e)
                                    {
                                        continue;
                                    }
                                    let block_match = || {
                                        not_inside.iter().any(|re| {
                                            if let Some((s, e)) = enclosing_block(source, m.start())
                                            {
                                                re.is_match(&source[s..e])
                                            } else {
                                                false
                                            }
                                        })
                                    };
                                    let in_not_inside = if !not_inside_ranges.is_empty() {
                                        not_inside_ranges
                                            .iter()
                                            .any(|(s, e)| m.start() >= *s && m.end() <= *e)
                                            || block_match()
                                    } else {
                                        block_match()
                                    };
                                    if in_not_inside {
                                        continue;
                                    }
                                    let mut line = 1;
                                    let mut line_start = 0;
                                    for (idx, ch) in source[..m.start()].char_indices() {
                                        if ch == '\n' {
                                            line += 1;
                                            line_start = idx + 1;
                                        }
                                    }
                                    let column = m.start() - line_start + 1;
                                    let line_end = source[m.end()..]
                                        .find('\n')
                                        .map(|i| m.end() + i)
                                        .unwrap_or_else(|| source.len());
                                    let excerpt = source[line_start..line_end].to_string();
                                    let id = blake3::hash(
                                        format!("{}:{}:{}:{}", rule.id, canonical, line, column)
                                            .as_bytes(),
                                    )
                                    .to_hex()
                                    .to_string();
                                    findings.push(Finding {
                                        id,
                                        rule_id: rule.id.clone(),
                                        rule_file: rule.source_file.clone(),
                                        severity: rule.severity,
                                        file: PathBuf::from(&file.file_path),
                                        line,
                                        column,
                                        excerpt,
                                        message: rule.message.clone(),
                                        remediation: rule.remediation.clone(),
                                        fix: rule.fix.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            } // end for sub in subs
            findings
        }
        MatcherKind::JsonPathEq(path, val) => {
            debug!(rule=%rule.id, file=%file.file_path, kind="JsonPathEq", path=%path);
            jsonpath_findings(file, rule, canonical.as_ref(), path, Some(val), None)
        }
        MatcherKind::JsonPathRegex(path, re) => {
            debug!(rule=%rule.id, file=%file.file_path, kind="JsonPathRegex", path=%path);
            jsonpath_findings(file, rule, canonical.as_ref(), path, None, Some(re))
        }
        MatcherKind::AstQuery(q) => {
            debug!(rule=%rule.id, file=%file.file_path, kind="AstQuery");
            if let Some(ast) = &file.ast {
                ast_query_findings(ast, rule, canonical.as_ref(), q)
            } else {
                Vec::new()
            }
        }
        MatcherKind::AstPattern(p) => {
            debug!(rule=%rule.id, file=%file.file_path, kind="AstPattern");
            let pat = into_engine_pattern(p);
            match_ast_pattern(file, &pat)
                .into_iter()
                .map(|m| {
                    let excerpt = file
                        .source
                        .as_ref()
                        .and_then(|s| s.lines().nth(m.line - 1).map(|l| l.to_string()))
                        .unwrap_or_default();
                    let message = if m.metavars.is_empty() {
                        rule.message.clone()
                    } else {
                        let mut msg = rule.message.clone();
                        for (k, v) in &m.metavars {
                            msg = msg.replace(&format!("${k}"), v);
                        }
                        msg
                    };
                    Finding {
                        id: blake3::hash(
                            format!("{}:{}:{}:{}", rule.id, canonical, m.line, m.column).as_bytes(),
                        )
                        .to_hex()
                        .to_string(),
                        rule_id: rule.id.clone(),
                        rule_file: rule.source_file.clone(),
                        severity: rule.severity,
                        file: PathBuf::from(&file.file_path),
                        line: m.line,
                        column: m.column,
                        excerpt,
                        message,
                        remediation: rule.remediation.clone(),
                        fix: rule.fix.clone(),
                    }
                })
                .collect()
        }
        MatcherKind::RegoWasm {
            wasm_path,
            entrypoint,
        } => eval_rego_wasm(file, rule, canonical.as_ref(), wasm_path, entrypoint),
        MatcherKind::TaintRule {
            sources,
            sanitizers,
            reclass,
            sinks,
        } => {
            debug!(rule=%rule.id, file=%file.file_path, kind="TaintRule", sources=sources.len(), sanitizers=sanitizers.len(), reclass=reclass.len(), sinks=sinks.len());
            debug!(
                "TaintRule: Starting processing for rule '{}' and file '{}'",
                rule.id, file.file_path
            );
            let source_text = file.source.as_deref().unwrap_or("");
            let tracker = if !rule.sources.is_empty() && !rule.sinks.is_empty() {
                let graph = dataflow::get_call_graph();
                let mut t = dataflow::TaintTracker::new(graph);
                for s in &rule.sources {
                    t.mark_source(s);
                }
                for s in &rule.sinks {
                    t.mark_sink(s);
                }
                Some(t)
            } else {
                None
            };
            debug!("TaintRule: Starting sources processing for rule '{}' and file '{}', sources count: {}", rule.id, file.file_path, sources.len());
            let mut source_syms = Vec::new();
            for (tp_idx, tp) in sources.iter().enumerate() {
                let before_source_symbols = source_syms.len();
                debug!(
                    "TaintRule: Processing source {} for rule '{}' and file '{}'",
                    tp_idx, rule.id, file.file_path
                );
                debug!(
                    "TaintRule: Computing inside ranges for source {} for rule '{}' and file '{}'",
                    tp_idx, rule.id, file.file_path
                );
                let inside_matches =
                    regex_ranges_with_focus(source_text, &tp.inside, &tp.inside_focus_groups);
                if tp.focus.is_some()
                    && !tp.inside.is_empty()
                    && inside_matches.iter().all(|(_, _, sym)| sym.is_none())
                {
                    let inside_patterns: Vec<String> =
                        tp.inside.iter().map(|re| format!("{re:?}")).collect();
                    debug!(
                        rule = %rule.id,
                        file = %file.file_path,
                        tp_idx,
                        expected_focus = ?tp.focus,
                        inside_patterns = ?inside_patterns,
                        matches = inside_matches.len(),
                        kind = "taint.sources.focus.inside",
                        "Inside patterns matched without capturing focus metavariable"
                    );
                }
                let inside_ranges: Vec<(usize, usize)> =
                    inside_matches.iter().map(|(s, e, _)| (*s, *e)).collect();
                debug!("TaintRule: Computing not_inside ranges for source {} for rule '{}' and file '{}'", tp_idx, rule.id, file.file_path);
                let not_inside_ranges = regex_ranges_any(source_text, &tp.not_inside);
                // When this source has pattern-inside (e.g. require('express')) and the file doesn't match, skip this source.
                if !tp.inside.is_empty() && inside_ranges.is_empty() {
                    continue;
                }
                for (ms, _, sym) in &inside_matches {
                    if let Some(sym) = sym {
                        let (line, column) = line_col_at(source_text, *ms);
                        if !source_syms
                            .iter()
                            .any(|(existing, l, c)| existing == sym && *l == line && *c == column)
                        {
                            debug!(
                                rule = %rule.id,
                                file = %file.file_path,
                                tp_idx,
                                line,
                                column,
                                focus = %sym,
                                kind = "taint.sources.focus.inside",
                                "Captured focus metavariable from inside pattern"
                            );
                            source_syms.push((sym.clone(), line, column));
                        }
                    }
                }
                debug!(
                    "TaintRule: Starting allow patterns for source {} for rule '{}' and file '{}'",
                    tp_idx, rule.id, file.file_path
                );
                for (re_idx, re) in tp.allow.iter().enumerate() {
                    if re.is_fancy() {
                        debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sources.allow", fancy=true, "Scanning fancy regex");
                        let start_guard = Instant::now();
                        let mut offset = 0usize;
                        for seg in source_text.split_inclusive('\n') {
                            if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sources.allow", "Aborting fancy regex scan due to guard timeout");
                                break;
                            }
                            let mut match_count = 0;
                            for (ls, le) in re.find_iter(seg) {
                                // Prevent infinite loops in fancy regex by limiting matches per segment
                                match_count += 1;
                                if match_count > 1000 {
                                    debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sources.allow", "Aborting fancy regex scan due to too many matches in segment");
                                    break;
                                }

                                // Check timeout more frequently within the iterator
                                if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                    debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sources.allow", "Aborting fancy regex scan due to guard timeout in iterator");
                                    break;
                                }

                                let ms = offset + ls;
                                let me = offset + le;
                                if let Some(deny) = &tp.deny {
                                    if deny.is_match(&source_text[ms..me]) {
                                        continue;
                                    }
                                }
                                if !inside_ranges.is_empty()
                                    && inside_ranges.iter().all(|(s, e)| ms < *s || me > *e)
                                {
                                    continue;
                                }
                                let block_match = || {
                                    tp.not_inside.iter().any(|re| {
                                        if let Some((s, e)) = enclosing_block(source_text, ms) {
                                            re.is_match(&source_text[s..e])
                                        } else {
                                            false
                                        }
                                    })
                                };
                                let in_not_inside = if !not_inside_ranges.is_empty() {
                                    not_inside_ranges.iter().any(|(s, e)| ms >= *s && me <= *e)
                                        || block_match()
                                } else {
                                    block_match()
                                };
                                if in_not_inside {
                                    continue;
                                }
                                let mut symbol = None;
                                if tp.focus.is_some() {
                                    if let Some(caps) = re.captures(&source_text[ms..me]) {
                                        let group_idx = tp
                                            .allow_focus_groups
                                            .get(re_idx)
                                            .copied()
                                            .flatten()
                                            .unwrap_or(1);
                                        if let Some(sym) = caps.get(group_idx) {
                                            symbol = Some(sym.as_str().to_string());
                                        }
                                    }
                                }
                                if symbol.is_none() {
                                    if let Some(lhs) = derive_assignment_lhs(source_text, ms) {
                                        debug!(
                                            rule = %rule.id,
                                            file = %file.file_path,
                                            tp_idx,
                                            re_idx,
                                            focus = %lhs,
                                            kind = "taint.sources.allow",
                                            "Derived focus symbol from assignment"
                                        );
                                        symbol = Some(lhs);
                                    }
                                }
                                let mut push_symbol = |sym: String, pos: usize| {
                                    let (line, column) = line_col_at(source_text, pos);
                                    if !source_syms.iter().any(|(existing, l, c)| {
                                        existing == &sym && *l == line && *c == column
                                    }) {
                                        source_syms.push((sym, line, column));
                                    }
                                };

                                if let Some(sym) = symbol {
                                    push_symbol(sym, ms);
                                } else {
                                    let snippet = &source_text[ms..me];
                                    let snippet_vars = extract_sink_variables(snippet);
                                    let mut added_any = false;
                                    for (sym, rel_offset) in snippet_vars {
                                        push_symbol(sym, ms + rel_offset);
                                        added_any = true;
                                    }
                                    if !added_any && file.file_type.eq_ignore_ascii_case("php") {
                                        let line_start = source_text[..ms]
                                            .rfind('\n')
                                            .map(|idx| idx + 1)
                                            .unwrap_or(0);
                                        let line_end = source_text[line_start..]
                                            .find('\n')
                                            .map(|idx| line_start + idx)
                                            .unwrap_or_else(|| source_text.len());
                                        let line_text = &source_text[line_start..line_end];
                                        for (sym, rel_offset) in extract_sink_variables(line_text) {
                                            if PHP_SUPERGLOBALS.contains(&sym.as_str()) {
                                                push_symbol(sym, line_start + rel_offset);
                                            }
                                        }
                                    }
                                }
                            }
                            offset += seg.len();
                        }
                    } else {
                        for (ms, me) in re.find_iter(source_text) {
                            if let Some(deny) = &tp.deny {
                                if deny.is_match(&source_text[ms..me]) {
                                    continue;
                                }
                            }

                            if !inside_ranges.is_empty()
                                && inside_ranges.iter().all(|(s, e)| ms < *s || me > *e)
                            {
                                continue;
                            }
                            let block_match = || {
                                tp.not_inside.iter().any(|re| {
                                    if let Some((s, e)) = enclosing_block(source_text, ms) {
                                        re.is_match(&source_text[s..e])
                                    } else {
                                        false
                                    }
                                })
                            };
                            let in_not_inside = if !not_inside_ranges.is_empty() {
                                not_inside_ranges.iter().any(|(s, e)| ms >= *s && me <= *e)
                                    || block_match()
                            } else {
                                block_match()
                            };
                            if in_not_inside {
                                continue;
                            }
                            let mut symbol = None;
                            if tp.focus.is_some() {
                                if let Some(caps) = re.captures(&source_text[ms..me]) {
                                    let group_idx = tp
                                        .allow_focus_groups
                                        .get(re_idx)
                                        .copied()
                                        .flatten()
                                        .unwrap_or(1);
                                    if let Some(sym) = caps.get(group_idx) {
                                        symbol = Some(sym.as_str().to_string());
                                    }
                                }
                            }
                            if symbol.is_none() {
                                if let Some(lhs) = derive_assignment_lhs(source_text, ms) {
                                    debug!(
                                        rule = %rule.id,
                                        file = %file.file_path,
                                        tp_idx,
                                        re_idx,
                                        focus = %lhs,
                                        kind = "taint.sources.allow",
                                        "Derived focus symbol from assignment"
                                    );
                                    symbol = Some(lhs);
                                }
                            }
                            let mut push_symbol = |sym: String, pos: usize| {
                                let (line, column) = line_col_at(source_text, pos);
                                if !source_syms.iter().any(|(existing, l, c)| {
                                    existing == &sym && *l == line && *c == column
                                }) {
                                    source_syms.push((sym, line, column));
                                }
                            };

                            if let Some(sym) = symbol {
                                push_symbol(sym, ms);
                            } else {
                                let snippet = &source_text[ms..me];
                                let snippet_vars = extract_sink_variables(snippet);
                                let mut added_any = false;
                                for (sym, rel_offset) in snippet_vars {
                                    push_symbol(sym, ms + rel_offset);
                                    added_any = true;
                                }
                                if !added_any && file.file_type.eq_ignore_ascii_case("php") {
                                    let line_start = source_text[..ms]
                                        .rfind('\n')
                                        .map(|idx| idx + 1)
                                        .unwrap_or(0);
                                    let line_end = source_text[line_start..]
                                        .find('\n')
                                        .map(|idx| line_start + idx)
                                        .unwrap_or_else(|| source_text.len());
                                    let line_text = &source_text[line_start..line_end];
                                    for (sym, rel_offset) in extract_sink_variables(line_text) {
                                        if PHP_SUPERGLOBALS.contains(&sym.as_str()) {
                                            push_symbol(sym, line_start + rel_offset);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if tp.focus.is_some() && source_syms.len() == before_source_symbols {
                    debug!(
                        rule = %rule.id,
                        file = %file.file_path,
                        tp_idx,
                        allow_patterns = tp.allow.len(),
                        inside_matches = inside_matches.len(),
                        kind = "taint.sources",
                        "No source symbols captured from this source pattern"
                    );
                }
            }

            debug!(
                "TaintRule: Starting sanitizers processing for rule '{}' and file '{}'",
                rule.id, file.file_path
            );
            let mut sanitized_syms = std::collections::HashSet::new();
            for (tp_idx, tp) in sanitizers.iter().enumerate() {
                let inside_ranges: Vec<(usize, usize)> =
                    regex_ranges_with_focus(source_text, &tp.inside, &tp.inside_focus_groups)
                        .into_iter()
                        .map(|(s, e, _)| (s, e))
                        .collect();
                let not_inside_ranges = regex_ranges_any(source_text, &tp.not_inside);
                for (re_idx, re) in tp.allow.iter().enumerate() {
                    if re.is_fancy() {
                        debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sanitizers.allow", fancy=true, "Scanning fancy regex");
                        let start_guard = Instant::now();
                        let mut offset = 0usize;
                        for seg in source_text.split_inclusive('\n') {
                            if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sanitizers.allow", "Aborting fancy regex scan due to guard timeout");
                                break;
                            }
                            let mut match_count = 0;
                            for (ls, le) in re.find_iter(seg) {
                                // Prevent infinite loops in fancy regex by limiting matches per segment
                                match_count += 1;
                                if match_count > 1000 {
                                    debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sanitizers.allow", "Aborting fancy regex scan due to too many matches in segment");
                                    break;
                                }

                                // Check timeout more frequently within the iterator
                                if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                    debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sanitizers.allow", "Aborting fancy regex scan due to guard timeout in iterator");
                                    break;
                                }

                                let ms = offset + ls;
                                let me = offset + le;
                                if let Some(deny) = &tp.deny {
                                    if deny.is_match(&source_text[ms..me]) {
                                        continue;
                                    }
                                }
                                if !inside_ranges.is_empty()
                                    && inside_ranges.iter().all(|(s, e)| ms < *s || me > *e)
                                {
                                    continue;
                                }
                                let block_match = || {
                                    tp.not_inside.iter().any(|re| {
                                        if let Some((s, e)) = enclosing_block(source_text, ms) {
                                            re.is_match(&source_text[s..e])
                                        } else {
                                            false
                                        }
                                    })
                                };
                                let in_not_inside = if !not_inside_ranges.is_empty() {
                                    not_inside_ranges.iter().any(|(s, e)| ms >= *s && me <= *e)
                                        || block_match()
                                } else {
                                    block_match()
                                };
                                if in_not_inside {
                                    continue;
                                }
                                let mut symbol = None;
                                if tp.focus.is_some() {
                                    if let Some(caps) = re.captures(&source_text[ms..me]) {
                                        let group_idx = tp
                                            .allow_focus_groups
                                            .get(re_idx)
                                            .copied()
                                            .flatten()
                                            .unwrap_or(1);
                                        if let Some(sym) = caps.get(group_idx) {
                                            symbol = Some(sym.as_str().to_string());
                                        }
                                    }
                                }
                                if symbol.is_none() {
                                    symbol = derive_assignment_lhs(source_text, ms);
                                }
                                if let Some(sym) = symbol {
                                    sanitized_syms.insert(sym);
                                }
                            }
                            offset += seg.len();
                        }
                    } else {
                        for (ms, me) in re.find_iter(source_text) {
                            if let Some(deny) = &tp.deny {
                                if deny.is_match(&source_text[ms..me]) {
                                    continue;
                                }
                            }
                            if !inside_ranges.is_empty()
                                && inside_ranges.iter().all(|(s, e)| ms < *s || me > *e)
                            {
                                continue;
                            }
                            let block_match = || {
                                tp.not_inside.iter().any(|re| {
                                    if let Some((s, e)) = enclosing_block(source_text, ms) {
                                        re.is_match(&source_text[s..e])
                                    } else {
                                        false
                                    }
                                })
                            };
                            let in_not_inside = if !not_inside_ranges.is_empty() {
                                not_inside_ranges.iter().any(|(s, e)| ms >= *s && me <= *e)
                                    || block_match()
                            } else {
                                block_match()
                            };
                            if in_not_inside {
                                continue;
                            }
                            let mut symbol = None;
                            if tp.focus.is_some() {
                                if let Some(caps) = re.captures(&source_text[ms..me]) {
                                    let group_idx = tp
                                        .allow_focus_groups
                                        .get(re_idx)
                                        .copied()
                                        .flatten()
                                        .unwrap_or(1);
                                    if let Some(sym) = caps.get(group_idx) {
                                        symbol = Some(sym.as_str().to_string());
                                    }
                                }
                            }
                            if symbol.is_none() {
                                symbol = derive_assignment_lhs(source_text, ms);
                            }
                            if let Some(sym) = symbol {
                                sanitized_syms.insert(sym);
                            }
                        }
                    }
                }
            }

            let source_syms: Vec<_> = source_syms
                .into_iter()
                .filter(|(s, _, _)| !sanitized_syms.contains(s))
                .collect();

            debug!(
                rule = %rule.id,
                file = %file.file_path,
                sources_collected = source_syms.len(),
                sanitized = sanitized_syms.len(),
                "TaintRule: collected source symbols"
            );

            // Record for the inter-file taint second pass.
            if !source_syms.is_empty() {
                record_interfile_sources(rule, file, &source_syms);
            }

            debug!(
                "TaintRule: Starting reclass processing for rule '{}' and file '{}'",
                rule.id, file.file_path
            );
            let mut reclass_syms = std::collections::HashSet::new();
            for (tp_idx, tp) in reclass.iter().enumerate() {
                let inside_ranges: Vec<(usize, usize)> =
                    regex_ranges_with_focus(source_text, &tp.inside, &tp.inside_focus_groups)
                        .into_iter()
                        .map(|(s, e, _)| (s, e))
                        .collect();
                let not_inside_ranges = regex_ranges_any(source_text, &tp.not_inside);
                for (re_idx, re) in tp.allow.iter().enumerate() {
                    if re.is_fancy() {
                        debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.reclass.allow", fancy=true, "Scanning fancy regex");
                        let start_guard = Instant::now();
                        let mut offset = 0usize;
                        for seg in source_text.split_inclusive('\n') {
                            if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.reclass.allow", "Aborting fancy regex scan due to guard timeout");
                                break;
                            }
                            let mut match_count = 0;
                            for (ls, le) in re.find_iter(seg) {
                                // Prevent infinite loops in fancy regex by limiting matches per segment
                                match_count += 1;
                                if match_count > 1000 {
                                    debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.reclass.allow", "Aborting fancy regex scan due to too many matches in segment");
                                    break;
                                }

                                // Check timeout more frequently within the iterator
                                if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                    debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.reclass.allow", "Aborting fancy regex scan due to guard timeout in iterator");
                                    break;
                                }

                                let ms = offset + ls;
                                let me = offset + le;
                                if let Some(deny) = &tp.deny {
                                    if deny.is_match(&source_text[ms..me]) {
                                        continue;
                                    }
                                }
                                if !inside_ranges.is_empty()
                                    && inside_ranges.iter().all(|(s, e)| ms < *s || me > *e)
                                {
                                    continue;
                                }
                                let block_match = || {
                                    tp.not_inside.iter().any(|re| {
                                        if let Some((s, e)) = enclosing_block(source_text, ms) {
                                            re.is_match(&source_text[s..e])
                                        } else {
                                            false
                                        }
                                    })
                                };
                                let in_not_inside = if !not_inside_ranges.is_empty() {
                                    not_inside_ranges.iter().any(|(s, e)| ms >= *s && me <= *e)
                                        || block_match()
                                } else {
                                    block_match()
                                };
                                if in_not_inside {
                                    continue;
                                }
                                let mut symbol = None;
                                if tp.focus.is_some() {
                                    if let Some(caps) = re.captures(&source_text[ms..me]) {
                                        let group_idx = tp
                                            .allow_focus_groups
                                            .get(re_idx)
                                            .copied()
                                            .flatten()
                                            .unwrap_or(1);
                                        if let Some(sym) = caps.get(group_idx) {
                                            symbol = Some(sym.as_str().to_string());
                                        }
                                    }
                                }
                                if symbol.is_none() {
                                    symbol = derive_assignment_lhs(source_text, ms);
                                }
                                if let Some(sym) = symbol {
                                    reclass_syms.insert(sym);
                                }
                            }
                            offset += seg.len();
                        }
                    } else {
                        for (ms, me) in re.find_iter(source_text) {
                            if let Some(deny) = &tp.deny {
                                if deny.is_match(&source_text[ms..me]) {
                                    continue;
                                }
                            }
                            if !inside_ranges.is_empty()
                                && inside_ranges.iter().all(|(s, e)| ms < *s || me > *e)
                            {
                                continue;
                            }
                            let block_match = || {
                                tp.not_inside.iter().any(|re| {
                                    if let Some((s, e)) = enclosing_block(source_text, ms) {
                                        re.is_match(&source_text[s..e])
                                    } else {
                                        false
                                    }
                                })
                            };
                            let in_not_inside = if !not_inside_ranges.is_empty() {
                                not_inside_ranges.iter().any(|(s, e)| ms >= *s && me <= *e)
                                    || block_match()
                            } else {
                                block_match()
                            };
                            if in_not_inside {
                                continue;
                            }
                            let mut symbol = None;
                            if tp.focus.is_some() {
                                if let Some(caps) = re.captures(&source_text[ms..me]) {
                                    let group_idx = tp
                                        .allow_focus_groups
                                        .get(re_idx)
                                        .copied()
                                        .flatten()
                                        .unwrap_or(1);
                                    if let Some(sym) = caps.get(group_idx) {
                                        symbol = Some(sym.as_str().to_string());
                                    }
                                }
                            }
                            if symbol.is_none() {
                                symbol = derive_assignment_lhs(source_text, ms);
                            }
                            if let Some(sym) = symbol {
                                reclass_syms.insert(sym);
                            }
                        }
                    }
                }
            }

            debug!(
                "TaintRule: Starting sinks processing for rule '{}' and file '{}'",
                rule.id, file.file_path
            );
            debug!(
                "TaintRule: Sinks count: {} for rule '{}'",
                sinks.len(),
                rule.id
            );
            let mut sink_hits = Vec::new();
            for (tp_idx, tp) in sinks.iter().enumerate() {
                debug!(
                    "TaintRule: Processing sink {}/{} for rule '{}'",
                    tp_idx + 1,
                    sinks.len(),
                    rule.id
                );
                let inside_ranges: Vec<(usize, usize)> =
                    regex_ranges_with_focus(source_text, &tp.inside, &tp.inside_focus_groups)
                        .into_iter()
                        .map(|(s, e, _)| (s, e))
                        .collect();
                let not_inside_ranges = regex_ranges_any(source_text, &tp.not_inside);
                if !tp.inside.is_empty() && inside_ranges.is_empty() {
                    continue;
                }
                for (re_idx, re) in tp.allow.iter().enumerate() {
                    if re.is_fancy() {
                        debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sinks.allow", fancy=true, "Scanning fancy regex");
                        let start_guard = Instant::now();
                        let mut offset = 0usize;
                        for seg in source_text.split_inclusive('\n') {
                            if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sinks.allow", "Aborting fancy regex scan due to guard timeout");
                                break;
                            }
                            let mut match_count = 0;
                            for (ls, le) in re.find_iter(seg) {
                                // Prevent infinite loops in fancy regex by limiting matches per segment
                                match_count += 1;
                                if match_count > 1000 {
                                    debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sinks.allow", "Aborting fancy regex scan due to too many matches in segment");
                                    break;
                                }

                                // Check timeout more frequently within the iterator
                                if start_guard.elapsed() > FANCY_REGEX_GUARD {
                                    debug!(rule=%rule.id, file=%file.file_path, tp_idx, re_idx, kind="taint.sinks.allow", "Aborting fancy regex scan due to guard timeout in iterator");
                                    break;
                                }

                                let ms = offset + ls;
                                let me = offset + le;
                                if let Some(deny) = &tp.deny {
                                    if deny.is_match(&source_text[ms..me]) {
                                        continue;
                                    }
                                }
                                if !inside_ranges.is_empty()
                                    && inside_ranges.iter().all(|(s, e)| ms < *s || me > *e)
                                {
                                    continue;
                                }
                                let block_match = || {
                                    tp.not_inside.iter().any(|re| {
                                        if let Some((s, e)) = enclosing_block(source_text, ms) {
                                            re.is_match(&source_text[s..e])
                                        } else {
                                            false
                                        }
                                    })
                                };
                                let in_not_inside = if !not_inside_ranges.is_empty() {
                                    not_inside_ranges.iter().any(|(s, e)| ms >= *s && me <= *e)
                                        || block_match()
                                } else {
                                    block_match()
                                };
                                if in_not_inside {
                                    continue;
                                }
                                let mut line = 1usize;
                                let mut line_start = 0usize;
                                for (idx, ch) in source_text[..ms].char_indices() {
                                    if ch == '\n' {
                                        line += 1;
                                        line_start = idx + 1;
                                    }
                                }
                                let column = source_text[line_start..ms].chars().count() + 1;
                                let line_end = source_text[me..]
                                    .find('\n')
                                    .map(|i| me + i)
                                    .unwrap_or_else(|| source_text.len());
                                let excerpt = source_text[line_start..line_end].to_string();
                                sink_hits.push((
                                    source_text[ms..me].to_string(),
                                    line,
                                    column,
                                    excerpt,
                                ));
                            }
                            offset += seg.len();
                        }
                    } else {
                        for (ms, me) in re.find_iter(source_text) {
                            if let Some(deny) = &tp.deny {
                                if deny.is_match(&source_text[ms..me]) {
                                    continue;
                                }
                            }
                            if !inside_ranges.is_empty()
                                && inside_ranges.iter().all(|(s, e)| ms < *s || me > *e)
                            {
                                continue;
                            }
                            let block_match = || {
                                tp.not_inside.iter().any(|re| {
                                    if let Some((s, e)) = enclosing_block(source_text, ms) {
                                        re.is_match(&source_text[s..e])
                                    } else {
                                        false
                                    }
                                })
                            };
                            let in_not_inside = if !not_inside_ranges.is_empty() {
                                not_inside_ranges.iter().any(|(s, e)| ms >= *s && me <= *e)
                                    || block_match()
                            } else {
                                block_match()
                            };
                            if in_not_inside {
                                continue;
                            }
                            let mut line = 1usize;
                            let mut line_start = 0usize;
                            for (idx, ch) in source_text[..ms].char_indices() {
                                if ch == '\n' {
                                    line += 1;
                                    line_start = idx + 1;
                                }
                            }
                            let column = ms - line_start + 1;
                            let line_end = source_text[me..]
                                .find('\n')
                                .map(|i| me + i)
                                .unwrap_or_else(|| source_text.len());
                            let excerpt = source_text[line_start..line_end].to_string();
                            sink_hits.push((
                                source_text[ms..me].to_string(),
                                line,
                                column,
                                excerpt,
                            ));
                        }
                    }
                }
            }
            // Record for the inter-file taint second pass.
            if !sink_hits.is_empty() {
                record_interfile_sinks(rule, file, &sink_hits);
            }

            let has_flow = tracker.as_ref().map(|t| t.has_flow()).unwrap_or(true);
            let collect_sink_vars = |sink_text: &str, excerpt: &str, column: usize| {
                let mut vars: Vec<String> = extract_sink_variables(sink_text)
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect();
                if vars.is_empty() && file.file_type.eq_ignore_ascii_case("php") {
                    let excerpt_vars = extract_sink_variables(excerpt);
                    let col_idx = column.saturating_sub(1);
                    for (name, offset) in excerpt_vars {
                        if offset == col_idx
                            && PHP_SUPERGLOBALS.contains(&name.as_str())
                            && col_idx <= excerpt.len()
                            && excerpt[..col_idx].contains(',')
                            && !vars.iter().any(|existing| existing == &name)
                        {
                            vars.push(name);
                        }
                    }
                }
                vars
            };
            let sink_vars_unsanitized = |vars: &[String]| {
                if vars.is_empty() {
                    if file.file_type.eq_ignore_ascii_case("php") {
                        return false;
                    }
                    return true;
                }
                vars.iter()
                    .any(|var| file.symbols.get(var).map(|s| !s.sanitized).unwrap_or(true))
            };
            if source_syms.is_empty() {
                if !has_flow || tracker.is_none() {
                    return Vec::new();
                }
                let mut findings = Vec::new();
                for (_, line, column, excerpt) in &sink_hits {
                    let id = blake3::hash(
                        format!("{}:{}:{}:{}", rule.id, canonical, line, column).as_bytes(),
                    )
                    .to_hex()
                    .to_string();
                    findings.push(Finding {
                        id,
                        rule_id: rule.id.clone(),
                        rule_file: rule.source_file.clone(),
                        severity: rule.severity,
                        file: PathBuf::from(&file.file_path),
                        line: *line,
                        column: *column,
                        excerpt: excerpt.clone(),
                        message: rule.message.clone(),
                        remediation: rule.remediation.clone(),
                        fix: rule.fix.clone(),
                    });
                }
                debug!(
                    "eval_rule_impl: Returning {} findings for rule '{}' and file '{}'",
                    findings.len(),
                    rule.id,
                    file.file_path
                );
                return findings;
            }
            if !has_flow {
                debug!("eval_rule_impl: No flow found, returning empty findings for rule '{}' and file '{}'", rule.id, file.file_path);
                return Vec::new();
            }
            let mut findings = Vec::new();
            for (sym, _, _) in &source_syms {
                for (sink_text, line, column, excerpt) in &sink_hits {
                    // Skip if all variables in the sink are sanitized
                    let sink_vars = collect_sink_vars(sink_text, excerpt, *column);
                    if !sink_vars_unsanitized(&sink_vars) {
                        debug!(
                            "Skipping sink at line {} because all variables are sanitized: {}",
                            line, sink_text
                        );
                        continue;
                    }

                    let mut has_path = find_taint_path(file, sym, sink_text).is_some();
                    if !has_path && file.file_type.eq_ignore_ascii_case("php") {
                        let sym_php = sym.trim_start_matches('$');
                        if PHP_SUPERGLOBALS.contains(&sym_php) {
                            if sink_vars.iter().any(|var| var == sym || var == sym_php) {
                                has_path = true;
                            } else if !sink_vars.is_empty()
                                && dfg_reaches_any_var(file, sym_php, &sink_vars)
                            {
                                has_path = true;
                            }
                        }
                    }

                    if has_path {
                        let severity = if reclass_syms.contains(sym) {
                            Severity::Low
                        } else {
                            rule.severity
                        };
                        let id = blake3::hash(
                            format!("{}:{}:{}:{}", rule.id, canonical, line, column).as_bytes(),
                        )
                        .to_hex()
                        .to_string();
                        findings.push(Finding {
                            id,
                            rule_id: rule.id.clone(),
                            rule_file: rule.source_file.clone(),
                            severity,
                            file: PathBuf::from(&file.file_path),
                            line: *line,
                            column: *column,
                            excerpt: excerpt.clone(),
                            message: rule.message.clone(),
                            remediation: rule.remediation.clone(),
                            fix: rule.fix.clone(),
                        });
                    }
                }
            }
            findings
        }
    };
    emit(DebugEvent::MatchResult {
        rule_id: rule.id.clone(),
        file: PathBuf::from(&file.file_path),
        matched: !findings.is_empty(),
    });
    debug!(
        "Final return with {} findings for rule '{}' and file '{}'",
        findings.len(),
        rule.id,
        file.file_path
    );
    findings
}

fn eval_rego_wasm(
    file: &FileIR,
    rule: &CompiledRule,
    canonical: &str,
    path: &str,
    entrypoint: &str,
) -> Vec<Finding> {
    let handle = Handle::try_current().unwrap_or_else(|_| tokio_handle());
    let mut instance = match WASM_POOL.with(|pool| {
        // If the pool is currently borrowed, fall back to creating a new instance.
        if let Ok(mut map) = pool.try_borrow_mut() {
            let instances = map.entry(path.to_string()).or_default();
            if let Some(inst) = instances.pop() {
                return Ok(inst);
            }
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return Err(()),
        };
        // Use the runtime handle directly to avoid nested executors.
        handle
            .block_on(RegoWasm::from_bytes_with_limits(
                &bytes,
                None,
                Some(WASM_FUEL),
                Some(WASM_MEMORY),
            ))
            .map_err(|_| ())
    }) {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };

    instance.set_input(serde_json::to_value(file).unwrap_or(JsonValue::Null));
    let candidates = [
        entrypoint.to_string(),
        entrypoint.trim_start_matches("data.").to_string(),
        entrypoint.replace('.', "/"),
        entrypoint.trim_start_matches("data.").replace('.', "/"),
    ];
    for ep in candidates.into_iter().filter(|e| !e.is_empty()) {
        let output = handle
            .block_on(async { tokio::time::timeout(WASM_TIMEOUT, instance.evaluate(&ep)).await });
        match output {
            Ok(Ok(val)) => {
                WASM_POOL.with(|pool| {
                    if let Ok(mut map) = pool.try_borrow_mut() {
                        let instances = map.entry(path.to_string()).or_default();
                        instances.push(instance);
                    }
                });
                return parse_rego_output(file, rule, canonical, val);
            }
            Ok(Err(e)) if e.to_string().contains("entrypoint") => {
                continue;
            }
            _ => {
                break;
            }
        }
    }
    WASM_POOL.with(|pool| {
        if let Ok(mut map) = pool.try_borrow_mut() {
            let instances = map.entry(path.to_string()).or_default();
            instances.push(instance);
        }
    });
    Vec::new()
}

fn parse_rego_output(
    file: &FileIR,
    rule: &CompiledRule,
    canonical: &str,
    val: JsonValue,
) -> Vec<Finding> {
    fn obj_to_finding(
        file: &FileIR,
        rule: &CompiledRule,
        canonical: &str,
        obj: &serde_json::Map<String, JsonValue>,
    ) -> Finding {
        let msg = obj
            .get("msg")
            .or_else(|| obj.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or(&rule.message);
        let line = obj.get("line").and_then(|l| l.as_u64()).unwrap_or(0) as usize;
        let column = obj.get("column").and_then(|c| c.as_u64()).unwrap_or(0) as usize;
        let excerpt = obj
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let id = blake3::hash(format!("{}:{}:{}:{}", rule.id, canonical, line, column).as_bytes())
            .to_hex()
            .to_string();
        Finding {
            id,
            rule_id: rule.id.clone(),
            rule_file: rule.source_file.clone(),
            severity: rule.severity,
            file: PathBuf::from(&file.file_path),
            line,
            column,
            excerpt,
            message: msg.to_string(),
            remediation: rule.remediation.clone(),
            fix: rule.fix.clone(),
        }
    }

    if let Some(arr) = val.as_array() {
        let mut findings = Vec::new();
        for v in arr {
            if let Some(obj) = v.as_object() {
                if let Some(res) = obj.get("result") {
                    if let Some(rarr) = res.as_array() {
                        for inner in rarr {
                            if let Some(iobj) = inner.as_object() {
                                findings.push(obj_to_finding(file, rule, canonical, iobj));
                            } else if let Some(s) = inner.as_str() {
                                let id = blake3::hash(
                                    format!("{}:{}:0:0:{}", rule.id, canonical, s).as_bytes(),
                                )
                                .to_hex()
                                .to_string();
                                findings.push(Finding {
                                    id,
                                    rule_id: rule.id.clone(),
                                    rule_file: rule.source_file.clone(),
                                    severity: rule.severity,
                                    file: PathBuf::from(&file.file_path),
                                    line: 0,
                                    column: 0,
                                    excerpt: String::new(),
                                    message: s.to_string(),
                                    remediation: rule.remediation.clone(),
                                    fix: rule.fix.clone(),
                                });
                            }
                        }
                    } else if let Some(iobj) = res.as_object() {
                        findings.push(obj_to_finding(file, rule, canonical, iobj));
                    }
                } else {
                    findings.push(obj_to_finding(file, rule, canonical, obj));
                }
            } else if let Some(s) = v.as_str() {
                let id = blake3::hash(format!("{}:{}:0:0:{}", rule.id, canonical, s).as_bytes())
                    .to_hex()
                    .to_string();
                findings.push(Finding {
                    id,
                    rule_id: rule.id.clone(),
                    rule_file: rule.source_file.clone(),
                    severity: rule.severity,
                    file: PathBuf::from(&file.file_path),
                    line: 0,
                    column: 0,
                    excerpt: String::new(),
                    message: s.to_string(),
                    remediation: rule.remediation.clone(),
                    fix: rule.fix.clone(),
                });
            }
        }
        findings
    } else if let Some(obj) = val.as_object() {
        obj.iter()
            .filter_map(|(k, v)| {
                if v.as_bool().unwrap_or(false) {
                    let id = blake3::hash(format!("{}:{}:0:0:{}", rule.id, canonical, k).as_bytes())
                        .to_hex()
                        .to_string();
                    Some(Finding {
                        id,
                        rule_id: rule.id.clone(),
                        rule_file: rule.source_file.clone(),
                        severity: rule.severity,
                        file: PathBuf::from(&file.file_path),
                        line: 0,
                        column: 0,
                        excerpt: String::new(),
                        message: k.to_string(),
                        remediation: rule.remediation.clone(),
                        fix: rule.fix.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    } else {
        Vec::new()
    }
}

fn ast_query_findings(
    ast: &ir::FileAst,
    rule: &CompiledRule,
    canonical: &str,
    q: &loader::Query,
) -> Vec<Finding> {
    #[allow(clippy::too_many_arguments)]
    fn walk(
        node: &ir::AstNode,
        ast: &ir::FileAst,
        rule: &CompiledRule,
        canonical: &str,
        q: &loader::Query,
        out: &mut Vec<Finding>,
        count: &mut usize,
        start: Instant,
    ) {
        if *count >= AST_QUERY_MAX_NODES || start.elapsed() >= AST_QUERY_TIMEOUT {
            return;
        }
        *count += 1;
        let kind_ok = q.kind.is_match(&node.kind);
        let value_ok = if let Some(re) = &q.value {
            node.value.as_str().map(|s| re.is_match(s)).unwrap_or(false)
        } else {
            true
        };
        if kind_ok && value_ok {
            let id = blake3::hash(
                format!(
                    "{}:{}:{}:{}",
                    rule.id, canonical, node.meta.line, node.meta.column
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string();
            out.push(Finding {
                id,
                rule_id: rule.id.clone(),
                rule_file: rule.source_file.clone(),
                severity: rule.severity,
                file: PathBuf::from(&ast.file_path),
                line: node.meta.line,
                column: node.meta.column,
                excerpt: node.value.to_string(),
                message: rule.message.clone(),
                remediation: rule.remediation.clone(),
                fix: rule.fix.clone(),
            });
        }
        for child in &node.children {
            if *count >= AST_QUERY_MAX_NODES || start.elapsed() >= AST_QUERY_TIMEOUT {
                break;
            }
            walk(child, ast, rule, canonical, q, out, count, start);
        }
    }

    let start = Instant::now();
    let mut findings = Vec::new();
    let mut count = 0usize;
    for n in &ast.nodes {
        if count >= AST_QUERY_MAX_NODES || start.elapsed() >= AST_QUERY_TIMEOUT {
            break;
        }
        walk(n, ast, rule, canonical, q, &mut findings, &mut count, start);
    }
    findings
}

#[derive(Debug)]
struct AstMatch {
    line: usize,
    column: usize,
    metavars: HashMap<String, String>,
}

fn into_engine_pattern(p: &LoaderAstPattern) -> pattern::AstPattern {
    pattern::AstPattern {
        kind: p.kind.clone(),
        within: p.within.clone(),
        metavariables: p
            .metavariables
            .iter()
            .map(|(k, v)| (k.clone(), into_engine_metavar(v)))
            .collect(),
    }
}

fn into_engine_metavar(v: &LoaderMetaVar) -> pattern::MetaVar {
    pattern::MetaVar {
        kind: v.kind.clone(),
        value: v.value.clone(),
    }
}

fn match_ast_pattern(file: &FileIR, pattern: &pattern::AstPattern) -> Vec<AstMatch> {
    debug!(
        "match_ast_pattern: Starting AST pattern matching for file '{}'",
        file.file_path
    );
    let ast = match &file.ast {
        Some(a) => a,
        None => {
            debug!(
                "match_ast_pattern: No AST available for file '{}'",
                file.file_path
            );
            return Vec::new();
        }
    };
    debug!(
        "match_ast_pattern: Processing {} nodes for file '{}'",
        ast.index.len(),
        file.file_path
    );
    let mut matches = Vec::new();
    let mut node_count = 0;
    for node in &ast.index {
        node_count += 1;
        if node_count % 1000 == 0 {
            debug!(
                "match_ast_pattern: Processed {} nodes for file '{}'",
                node_count, file.file_path
            );
        }
        if node.kind == pattern.kind && within_ok(ast, node, pattern.within.as_deref()) {
            if node_count % 1000 == 0 {
                debug!(
                    "match_ast_pattern: Capturing metavars for node {} of type '{}'",
                    node_count, node.kind
                );
            }
            if let Some(mv) = capture_metavars(node, &pattern.metavariables) {
                matches.push(AstMatch {
                    line: node.meta.line,
                    column: node.meta.column,
                    metavars: mv,
                });
            }
        }
    }
    debug!(
        "match_ast_pattern: Completed AST pattern matching for file '{}', found {} matches",
        file.file_path,
        matches.len()
    );
    matches
}

fn within_ok(ast: &FileAst, node: &AstNode, kind: Option<&str>) -> bool {
    if let Some(k) = kind {
        let mut cur = node.parent.and_then(|p| ast.index.get(p));
        while let Some(n) = cur {
            if n.kind == k {
                return true;
            }
            cur = n.parent.and_then(|p| ast.index.get(p));
        }
        false
    } else {
        true
    }
}

fn capture_metavars(
    node: &AstNode,
    vars: &HashMap<String, pattern::MetaVar>,
) -> Option<HashMap<String, String>> {
    let mut map = HashMap::new();
    for (name, mv) in vars {
        if let Some(found) = find_descendant(node, mv) {
            let val = found.value.as_str().unwrap_or_default().to_string();
            map.insert(name.clone(), val);
        } else {
            return None;
        }
    }
    Some(map)
}

fn find_descendant<'a>(node: &'a AstNode, mv: &pattern::MetaVar) -> Option<&'a AstNode> {
    if node.kind == mv.kind
        && mv
            .value
            .as_ref()
            .is_none_or(|v| node.value.as_str() == Some(v))
    {
        return Some(node);
    }
    for child in &node.children {
        if let Some(found) = find_descendant(child, mv) {
            return Some(found);
        }
    }
    None
}

fn jsonpath_findings(
    file: &FileIR,
    rule: &CompiledRule,
    canonical: &str,
    path: &str,
    equals: Option<&JsonValue>,
    re: Option<&Regex>,
) -> Vec<Finding> {
    let mut out = Vec::with_capacity(file.nodes.len());
    for n in file.nodes.iter().filter(|n| {
        n.kind == "k8s" || n.kind == "terraform" || n.kind == "yaml" || n.kind == "json"
    }) {
        if path_matches(path, &n.path) {
            let ok = if let Some(eq) = equals {
                &n.value == eq
            } else if let Some(rx) = re {
                n.value.as_str().map(|s| rx.is_match(s)).unwrap_or(false)
            } else {
                false
            };
            if ok {
                let id = blake3::hash(
                    format!(
                        "{}:{}:{}:{}",
                        rule.id, canonical, n.meta.line, n.meta.column
                    )
                    .as_bytes(),
                )
                .to_hex()
                .to_string();
                out.push(Finding {
                    id,
                    rule_id: rule.id.clone(),
                    rule_file: rule.source_file.clone(),
                    severity: rule.severity,
                    file: PathBuf::from(&file.file_path),
                    line: n.meta.line,
                    column: n.meta.column,
                    excerpt: format!("{}", n.value),
                    message: rule.message.clone(),
                    remediation: rule.remediation.clone(),
                    fix: rule.fix.clone(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{derive_assignment_lhs, line_col_at};

    #[test]
    fn derive_assignment_lhs_handles_non_char_boundary() {
        let source = "<?php
$foo = 1; —
";
        let em_dash = source.find('—').expect("must include em dash");
        let non_boundary = em_dash + 1;

        assert_eq!(derive_assignment_lhs(source, non_boundary), None);
    }

    #[test]
    fn line_col_at_handles_non_char_boundary() {
        let source = "a
—
";
        let em_dash = source.find('—').expect("must include em dash");
        let non_boundary = em_dash + 1;

        assert_eq!(line_col_at(source, non_boundary), (2, 1));
    }
}
