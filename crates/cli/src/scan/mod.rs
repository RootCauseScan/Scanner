use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value as JsonValue;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, warn};

use crate::args::ScanArgs;
use crate::config::{config_dir, load_config, save_config};
use crate::output::{self, Format};
use crate::{default_excludes, is_excluded, load_ignore_patterns, ui};

use engine::plugin::PluginManager;
use engine::{rules_fingerprint, AnalysisCache, Finding};
use ir::FileIR;
use loader::{visit, Severity};
use plugin_core::{discover_plugins, FileSpec, RepoDiscoverParams};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct ScanOutcome {
    pub should_fail_ci: bool,
}

impl ScanOutcome {
    pub const fn exit_code(self) -> i32 {
        if self.should_fail_ci {
            1
        } else {
            0
        }
    }
}

// Rules functionality moved to src/rules/
fn apply_fix(f: &Finding, fix: &str) -> Result<()> {
    let mut content = fs::read_to_string(&f.file)?;
    let lines: Vec<&str> = content.split_inclusive('\n').collect();

    if f.line == 0 || f.line > lines.len() {
        bail!("invalid location");
    }
    let line = lines[f.line - 1];
    let line_without_newline = line.strip_suffix('\n').unwrap_or(line);
    let line_chars = line_without_newline.chars().count();
    if f.column == 0 || f.column > line_chars {
        bail!("invalid location");
    }

    let mut idx = 0;
    for l in lines.iter().take(f.line - 1) {
        idx += l.len();
    }

    let column_byte_offset = line_without_newline
        .char_indices()
        .map(|(i, _)| i)
        .nth(f.column - 1)
        .ok_or_else(|| anyhow::anyhow!("invalid location"))?;
    idx += column_byte_offset;

    let excerpt_chars = f.excerpt.chars().count();
    let end = content[idx..]
        .char_indices()
        .nth(excerpt_chars)
        .map_or(content.len(), |(i, _)| idx + i);
    if end > content.len() || !content.is_char_boundary(idx) || !content.is_char_boundary(end) {
        bail!("invalid location");
    }
    if content.get(idx..end) != Some(f.excerpt.as_str()) {
        bail!("fix range does not match finding excerpt");
    }

    let mut replacement = fix.to_string();
    if let Some(pos) = fix.find("...") {
        let inner = f
            .excerpt
            .split_once('(')
            .and_then(|(_, rest)| rest.rsplit_once(')'))
            .map(|(s, _)| s)
            .unwrap_or("");
        replacement.replace_range(pos..pos + 3, inner);
    }
    content.replace_range(idx..end, &replacement);
    fs::write(&f.file, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_finding(file: PathBuf, line: usize, column: usize, excerpt: &str) -> Finding {
        Finding {
            id: "test-id".to_string(),
            rule_id: "test.rule".to_string(),
            rule_file: None,
            severity: Severity::Low,
            file,
            line,
            column,
            excerpt: excerpt.to_string(),
            message: "test message".to_string(),
            remediation: None,
            fix: None,
        }
    }

    fn write_temp_file(content: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("valid system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rootcause_apply_fix_{}_{}.txt",
            std::process::id(),
            unique
        ));
        fs::write(&path, content).expect("write temp file");
        path
    }

    #[test]
    fn apply_fix_handles_multibyte_with_non_first_column() {
        let path = write_temp_file("foo áé🙂bar\n");
        let finding = test_finding(path.clone(), 1, 5, "áé🙂");

        apply_fix(&finding, "XYZ").expect("apply fix succeeds");

        let updated = fs::read_to_string(&path).expect("read updated file");
        assert_eq!(updated, "foo XYZbar\n");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_fix_fails_when_excerpt_does_not_match_range() {
        let path = write_temp_file("Año 🙂 seguro\n");
        let finding = test_finding(path.clone(), 1, 3, "NOPE");

        let err = apply_fix(&finding, "OK").expect_err("must fail on mismatch");
        assert!(err.to_string().contains("excerpt"));

        let unchanged = fs::read_to_string(&path).expect("read unchanged file");
        assert_eq!(unchanged, "Año 🙂 seguro\n");
        let _ = fs::remove_file(path);
    }
}

#[derive(Debug, Clone)]
pub struct InputFile {
    path: PathBuf,
    content_b64: Option<String>,
    language: Option<String>,
    notes: Vec<String>,
}

pub fn read_file_cached<'a>(
    path: &Path,
    cache: &'a mut HashMap<PathBuf, Vec<u8>>,
) -> Option<&'a [u8]> {
    if let Entry::Vacant(e) = cache.entry(path.to_path_buf()) {
        if let Ok(bytes) = fs::read(path) {
            e.insert(bytes);
        } else {
            return None;
        }
    }
    cache.get(path).map(|v| v.as_slice())
}

#[allow(private_interfaces)]
pub fn update_files_from_transform(
    files: &mut Vec<InputFile>,
    index: &mut HashMap<PathBuf, usize>,
    result: &JsonValue,
) {
    if let Some(arr) = result.get("files").and_then(|v| v.as_array()) {
        for f in arr {
            let Some(path) = f.get("path").and_then(|v| v.as_str()) else {
                continue;
            };
            let path_buf = PathBuf::from(path);
            let content = f
                .get("content_b64")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let language = f
                .get("language")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let notes = f
                .get("notes")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|n| n.as_str().map(|s| s.to_string()))
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default();
            if let Some(&idx) = index.get(&path_buf) {
                let existing = &mut files[idx];
                existing.content_b64 = content.clone();
                existing.language = language.clone();
                existing.notes = notes.clone();
            } else {
                files.push(InputFile {
                    path: path_buf.clone(),
                    content_b64: content.clone(),
                    language: language.clone(),
                    notes: notes.clone(),
                });
                index.insert(path_buf, files.len() - 1);
            }
        }
    }
}

fn append_analysis_error_log(kind: &str, details: &str, args: &ScanArgs, files_analyzed: usize) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cwd = std::env::current_dir()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "<unavailable>".to_string());
    let command_args = std::env::args().collect::<Vec<_>>().join(" ");
    let plugin_paths = if args.plugins.is_empty() {
        "<none>".to_string()
    } else {
        args.plugins
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    let context = format!(
        "kind={kind}\n{}\nprocess.pid={}\nprocess.cwd={cwd}\nprocess.argv={command_args}\nenv.RUST_BACKTRACE={}\nscan.path={}\nscan.rules={}\nscan.plugins={plugin_paths}\nscan.plugin_config={}\nscan.fail_on={}\nscan.timeout_operation_ms={}\nscan.max_file_size={}\nscan.threads={}\nscan.files_analyzed={files_analyzed}\nscan.output_format={:?}",
        details.trim_end(),
        std::process::id(),
        std::env::var("RUST_BACKTRACE").unwrap_or_else(|_| "<unset>".to_string()),
        args.path.display(),
        args.rules.display(),
        args.plugin_config
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        args.fail_on
            .map(|sev| sev.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        args.timeout_operation_ms
            .map(|t| t.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        args.max_file_size,
        args.threads,
        args.format,
    );

    error!("{context}");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("rootcause.error.log")
    {
        let _ = writeln!(file, "[{timestamp}]\n{context}\n---");
    }
}

fn collect_scan_languages(files: &[InputFile]) -> HashSet<String> {
    let mut languages = HashSet::new();
    for f in files {
        let language = f
            .language
            .as_deref()
            .map(str::to_string)
            .or_else(|| parsers::detect_type(&f.path).map(str::to_string));
        if let Some(language) = language {
            languages.insert(language.trim().to_ascii_lowercase());
        }
    }
    languages
}

fn parse_transformed_content(
    path: &Path,
    content: &str,
    language_hint: Option<&str>,
    suppress_comment: Option<&str>,
) -> Option<FileIR> {
    let language = language_hint
        .map(|s| s.to_string())
        .or_else(|| parsers::detect_type(path).map(|s| s.to_string()))?;
    let suppressed = suppress_comment.map_or_else(HashSet::new, |c| {
        content
            .lines()
            .enumerate()
            .filter_map(|(idx, line)| line.contains(c).then_some(idx + 1))
            .collect::<HashSet<_>>()
    });
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), language.clone());
    let res: anyhow::Result<()> = match language.as_str() {
        "dockerfile" => {
            parsers::parse_dockerfile(content, &mut fir);
            Ok(())
        }
        "yaml" => parsers::parse_yaml(content, &mut fir),
        "json" => parsers::parse_json(content, &mut fir),
        "hcl" => {
            parsers::parse_hcl(content, &mut fir);
            Ok(())
        }
        "typescript" => {
            parsers::parse_typescript(content, &mut fir);
            Ok(())
        }
        "javascript" => {
            parsers::parse_javascript(content, &mut fir);
            Ok(())
        }
        "python" => parsers::languages::python::parse_python(content, &mut fir),
        "go" => {
            parsers::parse_go(content, &mut fir);
            Ok(())
        }
        "ruby" => {
            parsers::parse_ruby(content, &mut fir);
            Ok(())
        }
        "rust" => parsers::parse_rust(content, &mut fir),
        "java" => parsers::parse_java(content, &mut fir),
        "php" => parsers::parse_php(content, &mut fir),
        _ => Ok(()),
    };
    if res.is_err() || fir.symbol_types.contains_key("__parse_error__") {
        return None;
    }
    fir.source = Some(content.to_string());
    fir.suppressed = suppressed;
    Some(fir)
}

fn init_tracing(level: LevelFilter) {
    if let Err(err) = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init()
    {
        debug!(error = %err, "Global tracing subscriber already initialized");
    }
}

pub fn run_scan(mut args: ScanArgs) -> anyhow::Result<ScanOutcome> {
    let user_cfg = load_config().context("failed to load configuration")?;
    let mut plugin_configs: HashMap<String, JsonValue> = if let Some(ref path) = args.plugin_config
    {
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read plugin config: {}", path.display()))?;
        serde_json::from_str(&data)
            .with_context(|| format!("failed to parse plugin config: {}", path.display()))?
    } else {
        HashMap::new()
    };
    for opt in &args.plugin_opts {
        let (name_key, value) = opt
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!(format!("invalid plugin option: {opt}")))?;
        let (name, key) = name_key
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!(format!("invalid plugin option: {opt}")))?;
        let entry = plugin_configs
            .entry(name.to_string())
            .or_insert_with(|| JsonValue::Object(serde_json::Map::new()));
        if let JsonValue::Object(map) = entry {
            map.insert(key.to_string(), JsonValue::String(value.to_string()));
        }
    }
    for (name, pc) in &user_cfg.plugins {
        if !pc.params.is_empty() {
            if let Ok(JsonValue::Object(cfg_map)) = serde_json::to_value(&pc.params) {
                let entry = plugin_configs
                    .entry(name.clone())
                    .or_insert_with(|| JsonValue::Object(serde_json::Map::new()));
                if let JsonValue::Object(map) = entry {
                    for (k, v) in cfg_map {
                        map.entry(k).or_insert(v);
                    }
                }
            }
        }
    }
    let manager = PluginManager::load(&args.plugins, &plugin_configs, &args.path, &args.rules)?;

    // Verify that all plugins respond and collect their names.
    let mut ready_plugins = Vec::new();
    let all_plugins: Vec<_> = manager
        .transformers()
        .iter()
        .chain(manager.analyzers().iter())
        .chain(manager.reporters().iter())
        .collect();

    if !all_plugins.is_empty() {
        info!("Verifying plugins...");
        for plugin in all_plugins {
            let name = plugin.name();
            info!("Pinging plugin '{}'...", name);

            match plugin.ping() {
                Ok(_) => {
                    info!("Plugin '{}' loaded successfully", name);
                    ready_plugins.push(name.to_string());
                }
                Err(e) => {
                    error!("Plugin '{}' failed to respond: {}", name, e);
                }
            }
        }
    }

    let infos = discover_plugins(&args.plugins)?;
    let plugin_names: Vec<String> = infos
        .iter()
        .map(|i| {
            i.manifest
                .name
                .clone()
                .unwrap_or_else(|| i.path.display().to_string())
        })
        .collect();
    info!(count = plugin_names.len(), plugins = %plugin_names.join(", "), "Plugins loaded");
    let analyzer_names: Vec<String> = infos
        .iter()
        .filter(|i| i.manifest.capabilities.iter().any(|c| c == "analyze"))
        .map(|i| {
            i.manifest
                .name
                .clone()
                .unwrap_or_else(|| i.path.display().to_string())
        })
        .collect();
    let mut analyzer_counts = vec![0usize; analyzer_names.len()];
    let level = if args.quiet {
        LevelFilter::OFF
    } else if args.debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    init_tracing(level);

    if args.debug && !args.quiet {
        debug!("Debug mode enabled");
    }

    // Always show header in text format, regardless of quiet mode
    if args.format == Format::Text || !args.quiet {
        ui::print_header();
        ui::print_plugin_status(&ready_plugins);
    }

    let path = args.path.canonicalize()?;
    info!(target = %path.display(), "Scan started");
    debug!(path = %path.display(), max_file_size = args.max_file_size, "Scanning path");
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()
    {
        error!("Failed to build global thread pool: {e}");
    }

    if !args.rules.exists() {
        let stdin_is_tty = std::io::stdin().is_terminal();
        let stdout_is_tty = std::io::stdout().is_terminal();
        let should_download = if args.download_rules {
            true
        } else if stdin_is_tty && stdout_is_tty {
            println!("Rules directory '{}' not found.", args.rules.display());
            print!("Do you want to download the official rules package now? [y/N]: ");
            std::io::stdout()
                .flush()
                .context("failed to flush stdout")?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            let answer = answer.trim().to_lowercase();
            matches!(answer.as_str(), "y" | "yes" | "s" | "si")
        } else {
            bail!(
                "rules directory '{}' not found in non-interactive mode; rerun with --download-rules to install official rules automatically",
                args.rules.display()
            );
        };

        if !should_download {
            bail!("rules directory not found; aborting scan");
        }

        // Clone official rules to ~/.config/rootcause/rules/official/
        let official_rules_dir = config_dir().join("rules").join("official");
        let status = std::process::Command::new("git")
            .arg("clone")
            .arg("https://github.com/rootcausescan/rules")
            .arg(&official_rules_dir)
            .status()
            .context("failed to clone rules repository")?;
        if !status.success() {
            bail!("failed to clone rules repository");
        }

        // Create manifest.toml for the official ruleset
        let manifest_path = official_rules_dir.join("manifest.toml");
        let manifest_content = r#"name = "Official RootCause Rules"
author = "RootCause Team"
version = "1.0.0"
origin = "https://github.com/rootcausescan/rules"
git_url = "https://github.com/rootcausescan/rules.git"
description = "Official security rules for RootCause SAST tool covering Python, Rust, Docker, YAML, and more"
maintainer = "RootCause Security Team <contact@rootcause.dev>"
"#;
        std::fs::write(&manifest_path, manifest_content)
            .context("failed to create manifest.toml")?;

        // Update config.toml to include the official ruleset
        let mut cfg = load_config().context("failed to load configuration")?;
        if !cfg.rules.rule_dirs.contains(&official_rules_dir) {
            cfg.rules.rule_dirs.push(official_rules_dir.clone());
            save_config(&cfg)?;
        }

        // Now use the official rules directory
        args.rules = official_rules_dir;
    }

    // Collect file paths (core collector)
    let mut files: Vec<InputFile> = Vec::new();
    let mut file_index: HashMap<PathBuf, usize> = HashMap::new();
    let mut patterns = args.exclude.clone();
    if !args.no_default_exclude {
        patterns.extend(default_excludes());
    }
    patterns.extend(load_ignore_patterns(&path));
    visit(
        &path,
        &|p| is_excluded(p, &patterns, args.max_file_size),
        &mut |p| {
            if parsers::detect_type(p).is_some() {
                let path_buf = p.to_path_buf();
                let idx = files.len();
                files.push(InputFile {
                    path: path_buf.clone(),
                    content_b64: None,
                    language: parsers::detect_type(p).map(str::to_string),
                    notes: Vec::new(),
                });
                file_index.insert(path_buf, idx);
            }
            Ok(())
        },
    )?;
    // Run discover plugins before analysis to augment the file list
    if !manager.discoverers().is_empty() {
        let mut discovered = 0usize;
        for d in manager.discoverers() {
            let params = RepoDiscoverParams {
                path: path.to_string_lossy().into_owned(),
                extensions: vec![],
                max_depth: None,
            };
            match d.discover(params) {
                Ok(res) => {
                    // Merge discovered files into files/index
                    for f in res.files {
                        // Normalize to absolute canonical path to deduplicate with loader paths
                        let mut p = PathBuf::from(&f.path);
                        if p.is_relative() {
                            p = path.join(&p);
                        }
                        let p = p.canonicalize().unwrap_or(p);
                        if file_index.contains_key(&p) {
                            continue;
                        }
                        let idx = files.len();
                        files.push(InputFile {
                            path: p.clone(),
                            content_b64: f.content_b64,
                            language: f.language,
                            notes: Vec::new(),
                        });
                        file_index.insert(p, idx);
                        discovered += 1;
                    }
                    if !res.metrics.is_null() && args.debug {
                        debug!(plugin = d.name(), metrics = %res.metrics, "Discover metrics");
                    }
                }
                Err(e) => {
                    warn!(plugin = d.name(), error = %e, "Discover failed");
                }
            }
        }
        info!(
            count = discovered,
            total = files.len(),
            "Discoverers augmented files"
        );
    }

    let scan_languages = collect_scan_languages(&files);

    let mut ruleset = loader::load_rules(&args.rules)?;

    // Only load extra rules from the configuration if we're using the default directory
    // and the rules path is a directory (not a single file)
    let default_rules_dir = config_dir().join("rules");
    if !args.rules_provided && args.rules == default_rules_dir && args.rules.is_dir() {
        let cfg_rule_dirs: Vec<PathBuf> = user_cfg
            .rules
            .rule_dirs
            .iter()
            .map(|p| {
                if p.is_relative() {
                    config_dir().join(p)
                } else {
                    p.clone()
                }
            })
            .collect();
        for dir in &cfg_rule_dirs {
            if dir.exists() && dir != &args.rules {
                let extra = loader::load_rules(dir)?;
                ruleset.rules.extend(extra.rules);
            }
        }
    }

    // If we're loading a single file, don't load any additional rules
    if !args.rules.is_dir() {
        // Reset and only load the specified file
        ruleset.rules.clear();
        ruleset = loader::load_rules(&args.rules)?;
    }
    // Load rules exposed by plugins with the `rules` capability
    // Only load plugin rules if we're using a directory (not a single file)
    if args.rules.is_dir() {
        for plugin in &infos {
            if plugin.manifest.capabilities.iter().any(|c| c == "rules") {
                let rules_path = plugin.path.join("rules");
                if rules_path.is_dir() {
                    let plugin_rules = loader::load_rules(&rules_path)?;
                    let added = plugin_rules.rules.len();
                    ruleset.rules.extend(plugin_rules.rules);
                    let plugin_name = plugin
                        .manifest
                        .name
                        .clone()
                        .unwrap_or_else(|| plugin.path.display().to_string());
                    info!(plugin = %plugin_name, count = added, "Plugin rules loaded");
                }
            }
        }
    }

    let rules_before_filter = ruleset.rules.len();
    ruleset.rules.retain(|rule| {
        rule.languages.iter().any(|lang| {
            lang.eq_ignore_ascii_case("generic")
                || scan_languages.contains(&lang.to_ascii_lowercase())
        })
    });
    info!(
        count = ruleset.rules.len(),
        skipped = rules_before_filter.saturating_sub(ruleset.rules.len()),
        languages = scan_languages.len(),
        "Rules loaded"
    );
    debug!(rules = ruleset.rules.len(), path = %args.rules.display(), "Rules loaded");

    info!(files = files.len(), "Files queued");
    debug!(
        files = files.len(),
        excludes = patterns.len(),
        "Files queued"
    );
    let baseline = if let Some(path) = &args.baseline {
        Some(engine::load_baseline(path)?)
    } else {
        None
    };
    let timeout_operation_ms = args
        .timeout_operation_ms
        .or(user_cfg.scan.timeout_operation_ms)
        .unwrap_or(5_000);
    let analysis_errors = Arc::new(Mutex::new(Vec::new()));
    let cfg = engine::EngineConfig {
        file_timeout: None,
        rule_timeout: Some(std::time::Duration::from_millis(timeout_operation_ms)),
        baseline,
        suppress_comment: Some(args.suppress_comment.clone()),
        analysis_errors: Some(Arc::clone(&analysis_errors)),
    };
    let mut metrics = engine::EngineMetrics::default();
    let mut metrics_opt = if args.metrics.is_some() {
        Some(&mut metrics)
    } else {
        None
    };
    let cache_path = args.cache_dir.clone().or_else(|| {
        let p = if user_cfg.cache.cache_dir.is_relative() {
            config_dir().join(&user_cfg.cache.cache_dir)
        } else {
            user_cfg.cache.cache_dir.clone()
        };
        Some(p)
    });
    let mut cache = if let Some(ref path) = cache_path {
        AnalysisCache::load(path)
    } else {
        AnalysisCache::default()
    };
    let current_rules_hash = rules_fingerprint(&ruleset);
    if cache.rules_hash() != Some(current_rules_hash.as_str()) {
        cache.clear();
    }
    cache.set_rules_hash(current_rules_hash);
    let mut cache_opt = if cache_path.is_some() {
        Some(&mut cache)
    } else {
        None
    };
    let mut plugin_findings: Vec<Finding> = Vec::new();
    let start_time = std::time::Instant::now();
    let mut total_files = files.len();
    let progress = if args.quiet {
        None
    } else {
        ui::ProgressBar::new(ruleset.rules.len(), total_files).map(|bar| Arc::new(Mutex::new(bar)))
    };
    let progress_callback: Option<Arc<dyn Fn(usize) + Send + Sync + 'static>> =
        progress.as_ref().map(|handle| {
            let handle = Arc::clone(handle);
            Arc::new(move |completed: usize| {
                if let Ok(mut bar) = handle.lock() {
                    bar.increment_files(completed);
                }
            }) as Arc<dyn Fn(usize) + Send + Sync + 'static>
        });
    let mut failed_files = 0usize;
    let mut file_cache: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    let findings = if args.stream {
        let mut parsed_files = Vec::new();
        let analyzer_counts_ref = &mut analyzer_counts;
        let mut idx = 0;
        while idx < files.len() {
            let path = files[idx].path.clone();
            debug!(
                "Processing file {}/{}: {}",
                idx + 1,
                files.len(),
                path.display()
            );
            for t in manager.transformers() {
                let mut spec = FileSpec {
                    path: path.to_string_lossy().into_owned(),
                    ..Default::default()
                };
                if t.needs_content() || !t.reads_fs() {
                    if let Some(bytes) = read_file_cached(&path, &mut file_cache) {
                        spec.content_b64 = Some(general_purpose::STANDARD.encode(bytes));
                    }
                }
                if let Ok(result) = t.transform::<JsonValue>(vec![spec]) {
                    if args.debug {
                        debug!(
                            "Plugin transform result: {}",
                            serde_json::to_string_pretty(&result).unwrap_or_default()
                        );
                    }
                    let before = files.len();
                    update_files_from_transform(&mut files, &mut file_index, &result);
                    let added = files.len().saturating_sub(before);
                    if added > 0 {
                        total_files += added;
                        if let Some(pb) = &progress {
                            if let Ok(mut guard) = pb.lock() {
                                guard.extend_total_files(added);
                            }
                        }
                    }
                }
            }
            debug!("Transformers completed for file: {}", path.display());
            // Check if file was transformed and use transformed content
            let fir = if let Some(&idx_tf) = file_index.get(&path) {
                if let Some(content_b64) = &files[idx_tf].content_b64 {
                    if let Ok(content_bytes) = general_purpose::STANDARD.decode(content_b64) {
                        if let Ok(content) = String::from_utf8(content_bytes) {
                            let language_hint = files[idx_tf].language.as_deref();
                            parse_transformed_content(
                                &path,
                                &content,
                                language_hint,
                                Some(&args.suppress_comment),
                            )
                            .or_else(|| {
                                parsers::parse_file(&path, Some(&args.suppress_comment), None)
                                    .ok()
                                    .flatten()
                            })
                        } else {
                            parsers::parse_file(&path, Some(&args.suppress_comment), None)
                                .ok()
                                .flatten()
                        }
                    } else {
                        parsers::parse_file(&path, Some(&args.suppress_comment), None)
                            .ok()
                            .flatten()
                    }
                } else {
                    parsers::parse_file(&path, Some(&args.suppress_comment), None)
                        .ok()
                        .flatten()
                }
            } else {
                parsers::parse_file(&path, Some(&args.suppress_comment), None)
                    .ok()
                    .flatten()
            };
            debug!("File parsing completed for: {}", path.display());

            match fir {
                Some(fir) => {
                    debug!("Starting analyzer processing for file: {}", path.display());
                    for (idx_a, a) in manager.analyzers().iter().enumerate() {
                        debug!("Running analyzer {} on file: {}", a.name(), path.display());
                        let mut spec = FileSpec {
                            path: fir.file_path.clone(),
                            ..Default::default()
                        };
                        if a.needs_content() || !a.reads_fs() {
                            // Use transformed content if available, otherwise read from file
                            if let Some(&idx_tf) = file_index.get(&path) {
                                if let Some(content_b64) = &files[idx_tf].content_b64 {
                                    spec.content_b64 = Some(content_b64.clone());
                                } else if let Some(bytes) = read_file_cached(&path, &mut file_cache)
                                {
                                    spec.content_b64 =
                                        Some(general_purpose::STANDARD.encode(bytes));
                                }
                            } else if let Some(bytes) = read_file_cached(&path, &mut file_cache) {
                                spec.content_b64 = Some(general_purpose::STANDARD.encode(bytes));
                            }
                        }
                        if let Ok(mut res) = a.analyze::<Vec<Finding>>(vec![spec]) {
                            analyzer_counts_ref[idx_a] += res.len();
                            plugin_findings.append(&mut res);
                        }
                    }
                    debug!("Analyzer processing completed for file: {}", path.display());
                    parsed_files.push(fir.clone());
                }
                None => {
                    debug!("File parsing failed for: {}", path.display());
                    failed_files += 1;
                    if let Some(pb) = &progress {
                        if let Ok(mut guard) = pb.lock() {
                            guard.increment_files(1);
                        }
                    }
                }
            }
            if let Some(&idx_f) = file_index.get(&path) {
                files[idx_f].content_b64 = None;
                files[idx_f].notes.clear();
            }
            file_cache.remove(&path);
            debug!(
                "Completed processing file {}/{}: {}",
                idx + 1,
                files.len(),
                path.display()
            );
            idx += 1;
        }
        let findings = engine::analyze_files_streaming(
            parsed_files.clone(),
            &ruleset,
            &cfg,
            cache_opt.as_deref_mut(),
            metrics_opt,
            progress_callback.as_ref(),
        );
        engine::merge_plugin_findings(&parsed_files, findings, plugin_findings, &cfg)
    } else {
        let mut files_ir = Vec::new();
        let mut chunk_paths = Vec::new();
        let mut findings_acc = Vec::new();
        let mut idx = 0;
        while idx < files.len() {
            let path = files[idx].path.clone();
            debug!(
                "Processing file {}/{}: {}",
                idx + 1,
                files.len(),
                path.display()
            );
            for t in manager.transformers() {
                let mut spec = FileSpec {
                    path: path.to_string_lossy().into_owned(),
                    ..Default::default()
                };
                if t.needs_content() || !t.reads_fs() {
                    if let Some(bytes) = read_file_cached(&path, &mut file_cache) {
                        spec.content_b64 = Some(general_purpose::STANDARD.encode(bytes));
                    }
                }
                if let Ok(result) = t.transform::<JsonValue>(vec![spec]) {
                    if args.debug {
                        debug!(
                            "Plugin transform result: {}",
                            serde_json::to_string_pretty(&result).unwrap_or_default()
                        );
                    }
                    let before = files.len();
                    update_files_from_transform(&mut files, &mut file_index, &result);
                    let added = files.len().saturating_sub(before);
                    if added > 0 {
                        total_files += added;
                        if let Some(pb) = &progress {
                            if let Ok(mut guard) = pb.lock() {
                                guard.extend_total_files(added);
                            }
                        }
                    }
                }
            }
            debug!("Transformers completed for file: {}", path.display());
            // Check if file was transformed and use transformed content
            let fir = if let Some(&idx_tf) = file_index.get(&path) {
                if let Some(content_b64) = &files[idx_tf].content_b64 {
                    if let Ok(content_bytes) = general_purpose::STANDARD.decode(content_b64) {
                        if let Ok(content) = String::from_utf8(content_bytes) {
                            let language_hint = files[idx_tf].language.as_deref();
                            match parse_transformed_content(
                                &path,
                                &content,
                                language_hint,
                                Some(&args.suppress_comment),
                            ) {
                                Some(fir) => {
                                    if let Some(m) = metrics_opt.as_deref_mut() {
                                        m.parser.files_parsed += 1;
                                    }
                                    Some(fir)
                                }
                                None => parsers::parse_file(
                                    &path,
                                    Some(&args.suppress_comment),
                                    metrics_opt.as_deref_mut().map(|m| &mut m.parser),
                                )
                                .ok()
                                .flatten(),
                            }
                        } else {
                            parsers::parse_file(
                                &path,
                                Some(&args.suppress_comment),
                                metrics_opt.as_deref_mut().map(|m| &mut m.parser),
                            )
                            .ok()
                            .flatten()
                        }
                    } else {
                        parsers::parse_file(
                            &path,
                            Some(&args.suppress_comment),
                            metrics_opt.as_deref_mut().map(|m| &mut m.parser),
                        )
                        .ok()
                        .flatten()
                    }
                } else {
                    parsers::parse_file(
                        &path,
                        Some(&args.suppress_comment),
                        metrics_opt.as_deref_mut().map(|m| &mut m.parser),
                    )
                    .ok()
                    .flatten()
                }
            } else {
                parsers::parse_file(
                    &path,
                    Some(&args.suppress_comment),
                    metrics_opt.as_deref_mut().map(|m| &mut m.parser),
                )
                .ok()
                .flatten()
            };

            match fir {
                Some(fir) => {
                    debug!("Starting analyzer processing for file: {}", path.display());
                    for (idx_a, a) in manager.analyzers().iter().enumerate() {
                        debug!("Running analyzer {} on file: {}", a.name(), path.display());
                        let mut spec = FileSpec {
                            path: fir.file_path.clone(),
                            ..Default::default()
                        };
                        if a.needs_content() || !a.reads_fs() {
                            // Use transformed content if available, otherwise read from file
                            if let Some(&idx_tf) = file_index.get(&path) {
                                if let Some(content_b64) = &files[idx_tf].content_b64 {
                                    spec.content_b64 = Some(content_b64.clone());
                                } else if let Some(bytes) = read_file_cached(&path, &mut file_cache)
                                {
                                    spec.content_b64 =
                                        Some(general_purpose::STANDARD.encode(bytes));
                                }
                            } else if let Some(bytes) = read_file_cached(&path, &mut file_cache) {
                                spec.content_b64 = Some(general_purpose::STANDARD.encode(bytes));
                            }
                        }
                        if let Ok(mut res) = a.analyze::<Vec<Finding>>(vec![spec]) {
                            analyzer_counts[idx_a] += res.len();
                            plugin_findings.append(&mut res);
                        }
                    }
                    files_ir.push(fir);
                    chunk_paths.push(path.clone());
                }
                None => {
                    failed_files += 1;
                    if let Some(pb) = &progress {
                        if let Ok(mut guard) = pb.lock() {
                            guard.increment_files(1);
                        }
                    }
                }
            }

            if files_ir.len() == args.chunk_size {
                #[allow(clippy::needless_option_as_deref)]
                let chunk_findings = engine::analyze_files_with_config(
                    &files_ir,
                    &ruleset,
                    &cfg,
                    cache_opt.as_deref_mut(),
                    metrics_opt.as_deref_mut(),
                    progress_callback.as_ref(),
                );
                findings_acc.extend(engine::merge_plugin_findings(
                    &files_ir,
                    chunk_findings,
                    plugin_findings,
                    &cfg,
                ));
                for p in &chunk_paths {
                    if let Some(&idx_f) = file_index.get(p) {
                        files[idx_f].content_b64 = None;
                        files[idx_f].notes.clear();
                    }
                    file_cache.remove(p);
                }
                files_ir.clear();
                chunk_paths.clear();
                plugin_findings = Vec::new();
            }
            idx += 1;
        }
        if !files_ir.is_empty() {
            #[allow(clippy::needless_option_as_deref)]
            let chunk_findings = engine::analyze_files_with_config(
                &files_ir,
                &ruleset,
                &cfg,
                cache_opt.as_deref_mut(),
                metrics_opt.as_deref_mut(),
                progress_callback.as_ref(),
            );
            findings_acc.extend(engine::merge_plugin_findings(
                &files_ir,
                chunk_findings,
                plugin_findings,
                &cfg,
            ));
            for p in &chunk_paths {
                if let Some(&idx_f) = file_index.get(p) {
                    files[idx_f].content_b64 = None;
                    files[idx_f].notes.clear();
                }
                file_cache.remove(p);
            }
        }
        findings_acc
    };
    if let Some(pb) = &progress {
        if let Ok(mut guard) = pb.lock() {
            guard.finish();
        }
    }
    if let Some(path) = &cache_path {
        cache.save(path);
    }
    for (name, count) in analyzer_names.iter().zip(&analyzer_counts) {
        debug!(
            plugin = name.as_str(),
            findings = *count,
            "Plugin findings merged"
        );
    }
    if !manager.reporters().is_empty() {
        let mut ok = 0;
        let report_findings = serde_json::to_value(&findings)?;
        let report_metrics = serde_json::to_value(&metrics)?;
        for r in manager.reporters() {
            match r.report::<JsonValue>(report_findings.clone(), report_metrics.clone()) {
                Ok(resp) => {
                    ok += 1;
                    if args.debug {
                        debug!(?resp, "Reporter response");
                    }
                }
                Err(e) => error!("Reporter error: {e}"),
            }
        }
        info!(ok, total = manager.reporters().len(), "Reporters executed");
    }
    let duration_ms = start_time.elapsed().as_millis() as u64;
    let max_sev = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Low);
    if let Some(path) = &args.write_baseline {
        engine::write_baseline(path, &findings)?;
    }
    let plugin_summaries = infos
        .iter()
        .map(|i| reporters::PluginSummary {
            name: i
                .manifest
                .name
                .clone()
                .unwrap_or_else(|| i.path.display().to_string()),
            version: i.manifest.version.clone(),
            capabilities: i.manifest.capabilities.clone(),
        })
        .collect();
    if let Ok(errors) = analysis_errors.lock() {
        for error in errors.iter() {
            match error {
                engine::AnalysisError::RuleTimeout {
                    rule_id,
                    file_path,
                    timeout_ms,
                } => {
                    append_analysis_error_log(
                        "analysis_timeout",
                        &format!("rule_id={rule_id}\nfile={file_path}\ntimeout_ms={timeout_ms}"),
                        &args,
                        total_files,
                    );
                }
                engine::AnalysisError::RulePanic { rule_id, file_path } => {
                    append_analysis_error_log(
                        "analysis_panic",
                        &format!("rule_id={rule_id}\nfile={file_path}\nreason=panic"),
                        &args,
                        total_files,
                    );
                }
            }
        }
    }

    let scan_info = reporters::ScanInfo {
        rules_loaded: ruleset.rules.len(),
        files_analyzed: total_files,
        duration_ms,
        failed_files,
        plugins: plugin_summaries,
    };
    if args.apply_fixes {
        for f in &findings {
            if let Some(fx) = &f.fix {
                if let Err(e) = apply_fix(f, fx) {
                    warn!("Failed to apply fix for {}: {e}", f.file.display());
                }
            }
        }
    }
    output::print_findings(&findings, args.format, &scan_info)?;
    if let Some(path) = &args.metrics {
        let data = serde_json::to_string_pretty(&metrics)?;
        if path.as_os_str() == "-" {
            if !args.quiet {
                eprintln!("{data}");
            }
        } else {
            fs::write(path, data)?;
        }
    }
    if args.dump_taints && !args.quiet {
        let data = serde_json::to_string_pretty(&engine::all_function_taints())?;
        eprintln!("{data}");
    }
    let should_fail_ci = args.fail_on.is_some_and(|thr| max_sev >= thr);
    info!(findings = findings.len(), "Scan completed");
    Ok(ScanOutcome { should_fail_ci })
}

#[cfg(test)]
mod scan_outcome_tests {
    use super::ScanOutcome;

    #[test]
    fn scan_outcome_exit_code_reflects_fail_on_state() {
        assert_eq!(
            ScanOutcome {
                should_fail_ci: true
            }
            .exit_code(),
            1
        );
        assert_eq!(
            ScanOutcome {
                should_fail_ci: false
            }
            .exit_code(),
            0
        );
    }
}

#[cfg(test)]
mod tracing_tests {
    use super::init_tracing;
    use tracing::level_filters::LevelFilter;

    #[test]
    fn init_tracing_can_be_called_twice_without_panicking() {
        init_tracing(LevelFilter::INFO);
        init_tracing(LevelFilter::DEBUG);
    }
}
