//! Analysis engine that evaluates rules over the intermediate representation.
//! Orchestrates parallel execution, applies timeouts and generates findings.

use ir::{AstNode, FileAst, FileIR};
use loader::{
    semgrep_to_regex, semgrep_to_regex_exact, AnyRegex, AstPattern as LoaderAstPattern,
    MetaVar as LoaderMetaVar,
};
pub use loader::{CompiledRule, MatcherKind, RuleSet, Severity, TaintPattern};
use parsers::ParserMetrics;
use rayon::{prelude::*, ThreadPoolBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, OnceLock, RwLock};
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
mod function_taint;
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
#[cfg(test)]
pub use path::{
    canonical_cache_stats, path_regex_cache_contains, path_regex_cache_size, reset_canonical_cache,
    reset_path_regex_cache,
};
pub use path::{
    canonicalize_path, path_matches, CANONICAL_CACHE_CAPACITY, CANONICAL_PATHS,
    PATH_REGEX_CACHE_CAPACITY,
};

use crate::debug::emit;

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
pub fn find_taint_path(fir: &FileIR, _source: &str, _sink: &str) -> Option<Vec<usize>> {
    let dfg = fir.dfg.as_ref()?;

    fn is_unsanitized(fir: &FileIR, name: &str) -> bool {
        fir.symbols.get(name).is_none_or(|s| !s.sanitized)
    }

    let mut id_to_idx = HashMap::new();
    for (i, node) in dfg.nodes.iter().enumerate() {
        id_to_idx.insert(node.id, i);
    }
    let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut indegree: HashMap<usize, usize> = HashMap::new();
    for &(from, to) in &dfg.edges {
        if let (Some(&f), Some(&t)) = (id_to_idx.get(&from), id_to_idx.get(&to)) {
            adj.entry(f).or_default().push(t);
            *indegree.entry(t).or_default() += 1;
        }
    }

    let mut queue: VecDeque<(usize, Vec<usize>)> = VecDeque::new();
    let mut visited = HashSet::new();

    for (idx, node) in dfg.nodes.iter().enumerate() {
        if matches!(node.kind, ir::DFNodeKind::Def)
            && indegree.get(&idx).copied().unwrap_or(0) == 0
            && is_unsanitized(fir, &node.name)
        {
            queue.push_back((idx, vec![idx]));
            visited.insert(idx);
        }
    }

    while let Some((current, path)) = queue.pop_front() {
        let cur_node = &dfg.nodes[current];
        if matches!(cur_node.kind, ir::DFNodeKind::Use) && is_unsanitized(fir, &cur_node.name) {
            return Some(path);
        }

        if let Some(neigh) = adj.get(&current) {
            for &next in neigh {
                if visited.contains(&next) || !is_unsanitized(fir, &dfg.nodes[next].name) {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(next);
                visited.insert(next);
                queue.push_back((next, next_path));
            }
        }
    }
    None
}

pub use hash::analyze_files_cached;

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
fn warmup_wasm_rules(rules: &RuleSet) {
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

#[derive(Default)]
struct CacheStats {
    hits: AtomicUsize,
    misses: AtomicUsize,
}

type RuleCacheKey = (PathBuf, String);
type RuleCacheValue = Vec<Finding>;

static RULE_CACHE: OnceLock<RwLock<HashMap<RuleCacheKey, RuleCacheValue>>> = OnceLock::new();
static RULE_CACHE_ORDER: OnceLock<RwLock<VecDeque<RuleCacheKey>>> = OnceLock::new();
static RULE_CACHE_STATS: OnceLock<CacheStats> = OnceLock::new();

#[cfg(test)]
pub(crate) const RULE_CACHE_CAPACITY: usize = 3;
#[cfg(not(test))]
pub(crate) const RULE_CACHE_CAPACITY: usize = 1024;

fn rule_cache_stats_inner() -> (usize, usize) {
    let stats = RULE_CACHE_STATS.get_or_init(Default::default);
    (
        stats.hits.load(Ordering::Relaxed),
        stats.misses.load(Ordering::Relaxed),
    )
}

pub fn reset_rule_cache() {
    if let Some(map) = RULE_CACHE.get() {
        map.write().unwrap_or_else(|e| e.into_inner()).clear();
    }
    if let Some(ord) = RULE_CACHE_ORDER.get() {
        ord.write().unwrap_or_else(|e| e.into_inner()).clear();
    }
    if let Some(stats) = RULE_CACHE_STATS.get() {
        stats.hits.store(0, Ordering::Relaxed);
        stats.misses.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub fn rule_cache_stats() -> (usize, usize) {
    rule_cache_stats_inner()
}

fn eval_rule(file: &FileIR, rule: &CompiledRule) -> Vec<Finding> {
    debug!(
        "eval_rule: Starting evaluation of rule '{}' for file '{}'",
        rule.id, file.file_path
    );
    let cache = RULE_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    let order = RULE_CACHE_ORDER.get_or_init(|| RwLock::new(VecDeque::new()));
    let stats = RULE_CACHE_STATS.get_or_init(Default::default);
    let key = (PathBuf::from(&file.file_path), rule.id.clone());

    if let Some(cached) = cache
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
    {
        stats.hits.fetch_add(1, Ordering::Relaxed);
        let mut ord = order.write().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = ord.iter().position(|k| k == &key) {
            ord.remove(pos);
        }
        ord.push_back(key);
        return cached;
    }

    stats.misses.fetch_add(1, Ordering::Relaxed);
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
    let mut map = cache.write().unwrap_or_else(|e| e.into_inner());
    let mut ord = order.write().unwrap_or_else(|e| e.into_inner());
    map.insert(key.clone(), res.clone());
    ord.push_back(key);
    if ord.len() > RULE_CACHE_CAPACITY {
        if let Some(oldest) = ord.pop_front() {
            map.remove(&oldest);
        }
    }
    debug!(
        "eval_rule: Completed evaluation of rule '{}' for file '{}'",
        rule.id, file.file_path
    );
    res
}

fn regex_ranges(source: &str, regs: &[Regex]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for re in regs {
        for m in re.find_iter(source) {
            ranges.push((m.start(), m.end()));
        }
    }
    ranges
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

static ASSIGN_LHS_RE: OnceLock<Regex> = OnceLock::new();

fn derive_assignment_lhs(source: &str, pos: usize) -> Option<String> {
    let line_start = source[..pos].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    let prefix = &source[line_start..pos];
    if prefix.trim().is_empty() {
        return None;
    }
    let re = ASSIGN_LHS_RE.get_or_init(|| {
        Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?::[A-Za-z_][A-Za-z0-9_]*)?\s*=\s*$")
            .expect("valid assignment regex")
    });
    re.captures(prefix)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
}

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

fn analyze_file_inner(file: &FileIR, rules: &RuleSet) -> Vec<Finding> {
    init_tokio();
    debug!(
        "Analyzing file '{}' with {} rules",
        file.file_path,
        rules.rules.len()
    );
    debug!("Starting rule evaluation for file '{}'", file.file_path);
    let findings: Vec<Finding> = rules
        .rules
        .iter()
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

fn analyze_files_inner(
    files: &[(String, &FileIR)],
    rules: &RuleSet,
) -> Vec<(String, Vec<Finding>)> {
    debug!(
        "analyze_files_inner: Starting file processing for {} files",
        files.len()
    );
    let results: Vec<(String, Vec<Finding>)> = files
        .iter()
        .map(|(h, f)| {
            debug!("analyze_files_inner: Processing file '{}'", h);
            let findings = analyze_file_inner(f, rules);
            debug!(
                "analyze_files_inner: Completed processing file '{}', found {} findings",
                h,
                findings.len()
            );
            (h.clone(), findings)
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
    analyze_files_with_config(files, rules, &EngineConfig::default(), cache, None)
}

#[derive(Debug, Clone, Default)]
pub struct EngineConfig {
    pub file_timeout: Option<Duration>,
    pub rule_timeout: Option<Duration>,
    pub baseline: Option<HashSet<BaselineEntry>>,
    pub suppress_comment: Option<String>,
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

pub fn analyze_files_with_config(
    files: &[FileIR],
    rules: &RuleSet,
    cfg: &EngineConfig,
    mut cache: Option<&mut AnalysisCache>,
    mut metrics: Option<&mut EngineMetrics>,
) -> Vec<Finding> {
    dataflow::set_call_graph(dataflow::CallGraph::build(files));
    warmup_wasm_rules(rules);
    debug!(
        "Starting analysis with config of {} files with {} rules",
        files.len(),
        rules.rules.len()
    );
    let mut cached = Vec::new();
    let mut to_analyze = Vec::new();
    for f in files {
        let h = cache::hash_file(f);
        if let Some(c) = cache.as_ref().and_then(|c| c.get(&h)) {
            cached.extend(c.clone());
        } else {
            to_analyze.push((h, f));
        }
    }

    let mut findings =
        if cfg.file_timeout.is_none() && cfg.rule_timeout.is_none() && metrics.is_none() {
            analyze_files_inner(&to_analyze, rules)
                .into_iter()
                .flat_map(|(h, fs)| {
                    if let Some(c) = cache.as_deref_mut() {
                        c.insert(h, fs.clone());
                    }
                    fs.into_iter()
                })
                .collect()
        } else {
            let mut out = Vec::new();
            for (idx, (h, f)) in to_analyze.into_iter().enumerate() {
                debug!(
                    "Config analysis: processing file {}/{}: {}",
                    idx + 1,
                    files.len(),
                    f.file_path
                );
                let mut res = analyze_file_with_config_inner(f, rules, cfg, metrics.as_deref_mut());
                if let Some(c) = cache.as_deref_mut() {
                    c.insert(h, res.clone());
                }
                out.append(&mut res);
            }
            out
        };
    findings.extend(cached);

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
) -> Vec<Finding>
where
    I: IntoIterator<Item = FileIR>,
{
    warmup_wasm_rules(rules);
    let mut findings = Vec::new();
    debug!(
        "Starting streaming analysis with {} rules",
        rules.rules.len()
    );
    let mut count = 0usize;
    for f in files.into_iter() {
        count += 1;
        debug!(
            "Streaming analysis: processing file {}: {}",
            count, f.file_path
        );
        dataflow::set_call_graph(dataflow::CallGraph::build(std::slice::from_ref(&f)));
        let h = cache::hash_file(&f);
        if let Some(c) = cache.as_ref().and_then(|c| c.get(&h)) {
            findings.extend(c.clone());
        } else {
            let mut res = analyze_file_with_config_inner(&f, rules, cfg, metrics.as_deref_mut());
            if cfg.suppress_comment.is_some() {
                res.retain(|fi| !f.suppressed.contains(&fi.line));
            }
            if let Some(c) = cache.as_deref_mut() {
                c.insert(h, res.clone());
            }
            findings.extend(res);
        }
    }
    debug!("Streaming analysis completed for {} files", count);
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
    rules: &RuleSet,
    cfg: &EngineConfig,
    mut metrics: Option<&mut EngineMetrics>,
) -> Vec<Finding> {
    init_tokio();
    let start = Instant::now();
    let mut out = Vec::new();
    let pool = thread_pool();
    let file_arc = if cfg.rule_timeout.is_some() {
        Some(Arc::new(file.clone()))
    } else {
        None
    };
    for r in &rules.rules {
        if let Some(ft) = cfg.file_timeout {
            if start.elapsed() >= ft {
                break;
            }
        }
        debug!("Evaluating rule '{}' on file '{}'", r.id, file.file_path);
        let rule_start = Instant::now();
        let findings = if let Some(rt) = cfg.rule_timeout {
            if rt.is_zero() {
                Vec::new()
            } else {
                // Evaluate rule with timeout via worker thread and channel
                let (tx, rx) = mpsc::channel();
                let file_cloned =
                    Arc::clone(file_arc.as_ref().expect("rule timeout implies shared file"));
                let rule_cloned = Arc::new(r.clone());
                pool.spawn(move || {
                    let res = eval_rule(&file_cloned, &rule_cloned);
                    let _ = tx.send(res);
                });
                rx.recv_timeout(rt).unwrap_or_default()
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
    dataflow::set_call_graph(dataflow::CallGraph::build(std::slice::from_ref(file)));
    analyze_file_with_config_inner(file, rules, cfg, metrics)
}

pub fn analyze_file(file: &FileIR, rules: &RuleSet) -> Vec<Finding> {
    dataflow::set_call_graph(dataflow::CallGraph::build(std::slice::from_ref(file)));
    analyze_file_inner(file, rules)
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
    let rule_eval_start = Instant::now();
    #[cfg(test)]
    if rule.id == "slow.rule" {
        std::thread::sleep(Duration::from_millis(100));
    }
    let canonical_path = canonicalize_path(&file.file_path);
    let canonical = canonical_path.to_string_lossy();
    let findings = match &rule.matcher {
        MatcherKind::TextRegex(re, orig) => {
            debug!(rule=%rule.id, file=%file.file_path, kind="TextRegex", fancy=re.is_fancy(), pat=%orig.chars().take(120).collect::<String>());
            let source = file.source.as_deref().unwrap_or("");
            let mut findings: Vec<Finding> = source
                .lines()
                .enumerate()
                .filter_map(|(idx, line)| {
                    if re.is_match(line) {
                        let line_num = idx + 1;
                        let id = blake3::hash(
                            format!("{}:{}:{}:{}", rule.id, canonical, line_num, 1).as_bytes(),
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
                            column: 1,
                            excerpt: line.to_string(),
                            message: rule.message.clone(),
                            remediation: rule.remediation.clone(),
                            fix: rule.fix.clone(),
                        })
                    } else {
                        None
                    }
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
        MatcherKind::TextRegexMulti {
            allow,
            deny,
            inside,
            not_inside,
        } => {
            debug!(rule=%rule.id, file=%file.file_path, kind="TextRegexMulti", allow=allow.len(), deny=deny.is_some(), inside=inside.len(), not_inside=not_inside.len());
            let source = file.source.as_deref().unwrap_or("");
            let mut findings = Vec::new();
            let inside_ranges = regex_ranges_any(source, inside);
            let not_inside_ranges = regex_ranges_any(source, not_inside);
            let aliases = use_aliases(file);
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
                        message: rule.message.clone(),
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
                let mut t = dataflow::TaintTracker::new(&graph);
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
                    debug!(
                        rule = %rule.id,
                        file = %file.file_path,
                        tp_idx,
                        kind = "taint.sources.focus.inside",
                        "Inside patterns matched without capturing focus metavariable"
                    );
                }
                let inside_ranges: Vec<(usize, usize)> =
                    inside_matches.iter().map(|(s, e, _)| (*s, *e)).collect();
                debug!("TaintRule: Computing not_inside ranges for source {} for rule '{}' and file '{}'", tp_idx, rule.id, file.file_path);
                let not_inside_ranges = regex_ranges_any(source_text, &tp.not_inside);
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
                                if let Some(sym) = symbol {
                                    let (line, column) = line_col_at(source_text, ms);
                                    if !source_syms.iter().any(|(existing, l, c)| {
                                        existing == &sym && *l == line && *c == column
                                    }) {
                                        source_syms.push((sym, line, column));
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
                            if let Some(sym) = symbol {
                                let (line, column) = line_col_at(source_text, ms);
                                if !source_syms.iter().any(|(existing, l, c)| {
                                    existing == &sym && *l == line && *c == column
                                }) {
                                    source_syms.push((sym, line, column));
                                }
                            }
                        }
                    }
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
            let has_flow = tracker.as_ref().map(|t| t.has_flow()).unwrap_or(true);
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
            // Helper function to extract variable names from sink text
            fn extract_sink_variables(text: &str) -> Vec<String> {
                let mut vars = Vec::new();
                let mut chars = text.chars().peekable();

                while let Some(ch) = chars.next() {
                    if ch == '$' {
                        let mut var_name = String::new();
                        while let Some(&next_ch) = chars.peek() {
                            if next_ch.is_alphanumeric() || next_ch == '_' {
                                var_name.push(chars.next().unwrap());
                            } else {
                                break;
                            }
                        }
                        if !var_name.is_empty() {
                            vars.push(var_name);
                        }
                    }
                }
                vars
            }

            // Helper function to check if any variables in sink are unsanitized
            fn has_unsanitized_sink_vars(file: &FileIR, sink_text: &str) -> bool {
                let sink_vars = extract_sink_variables(sink_text);
                sink_vars
                    .iter()
                    .any(|var| file.symbols.get(var).map(|s| !s.sanitized).unwrap_or(true))
            }

            let mut findings = Vec::new();
            for (sym, _, _) in &source_syms {
                for (sink_text, line, column, excerpt) in &sink_hits {
                    // Skip if all variables in the sink are sanitized
                    if !has_unsanitized_sink_vars(file, sink_text) {
                        debug!(
                            "Skipping sink at line {} because all variables are sanitized: {}",
                            line, sink_text
                        );
                        continue;
                    }

                    if find_taint_path(file, sym, sink_text).is_some() {
                        let id = blake3::hash(
                            format!("{}:{}:{}:{}", rule.id, canonical, line, column).as_bytes(),
                        )
                        .to_hex()
                        .to_string();
                        let severity = if reclass_syms.contains(sym) {
                            Severity::Low
                        } else {
                            rule.severity
                        };
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
                                    format!("{}:{}:0:0", rule.id, canonical).as_bytes(),
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
                let id = blake3::hash(format!("{}:{}:0:0", rule.id, canonical).as_bytes())
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
                    let id = blake3::hash(format!("{}:{}:0:0", rule.id, canonical).as_bytes())
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
                let _ = mv; // metavariables currently unused
                matches.push(AstMatch {
                    line: node.meta.line,
                    column: node.meta.column,
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
