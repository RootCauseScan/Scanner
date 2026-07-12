//! Converters of configuration and code files to the
//! intermediate representation used by the engine.

use anyhow::{anyhow, Context, Result};
use ir::FileIR;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};
use tracing::debug;

#[derive(Debug, Default, Serialize)]
pub struct ParserMetrics {
    pub files_parsed: usize,
    pub cache_hits: usize,
    pub parse_errors: usize,
}

pub mod catalog;
pub mod language;
pub mod languages;
pub use language::{language_for, registry, Language};
pub use languages::*;

/// Builds the data flow graph if it doesn't already exist.
/// For supported languages, it re-parses the code using
/// the corresponding parser.
pub fn build_dfg(fir: &mut FileIR) -> Result<()> {
    if fir.dfg.is_some() {
        return Ok(());
    }
    let src = fir
        .source
        .clone()
        .ok_or_else(|| anyhow!("missing source for {}", fir.file_path))?;
    match language_for(&fir.file_type) {
        Some(lang) => lang.build_dfg(&src, fir),
        None => Ok(()),
    }
}

/// Determines the supported file type from the name/extension.
///
/// # Example
/// ```
/// use parsers::detect_type;
/// assert_eq!(detect_type(std::path::Path::new("Dockerfile")), Some("dockerfile"));
/// ```
pub fn detect_type(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    let detected = if name == "dockerfile" {
        Some("dockerfile")
    } else {
        match ext.as_deref() {
            Some("yaml") | Some("yml") => Some("yaml"),
            Some("json") => Some("json"),
            Some("tf") => Some("hcl"),
            Some("ts") | Some("tsx") => Some("typescript"),
            Some("js") | Some("jsx") => Some("javascript"),
            Some("py") => Some("python"),
            Some("go") => Some("go"),
            Some("rb") => Some("ruby"),
            Some("rs") => Some("rust"),
            Some("java") => Some("java"),
            Some("php") => Some("php"),
            _ => Some("generic"),
        }
    };
    detected
}

/// Canonical language identifiers understood by the scanner.
///
/// Kept next to [`detect_type`] on purpose: any language added there must be
/// reflected here so the CLI `--langs` selector and the rule/file filters
/// stay in sync.
pub const SUPPORTED_LANGUAGES: &[&str] = &[
    "dockerfile",
    "yaml",
    "json",
    "hcl",
    "typescript",
    "javascript",
    "python",
    "go",
    "ruby",
    "rust",
    "java",
    "php",
    "generic",
];

/// Maps a user-provided language name or common alias to its canonical id,
/// or `None` when the name is not recognised.
///
/// # Example
/// ```
/// assert_eq!(parsers::canonical_language("js"), Some("javascript"));
/// assert_eq!(parsers::canonical_language("Java"), Some("java"));
/// assert_eq!(parsers::canonical_language("cobol"), None);
/// ```
pub fn canonical_language(name: &str) -> Option<&'static str> {
    let normalized = name.trim().to_ascii_lowercase();
    let canonical = match normalized.as_str() {
        "dockerfile" | "docker" => "dockerfile",
        "yaml" | "yml" => "yaml",
        "json" => "json",
        "hcl" | "tf" | "terraform" => "hcl",
        "typescript" | "ts" | "tsx" => "typescript",
        "javascript" | "js" | "jsx" => "javascript",
        "python" | "py" => "python",
        "go" | "golang" => "go",
        "ruby" | "rb" => "ruby",
        "rust" | "rs" => "rust",
        "java" => "java",
        "php" => "php",
        "generic" => "generic",
        _ => return None,
    };
    Some(canonical)
}

/// Analiza contenido YAML desde una cadena y genera un [`FileIR`].
///
/// # Example
/// ```
/// use parsers::parse_str;
/// let ir = parse_str("a: 1").unwrap();
/// assert_eq!(ir.nodes[0].path, "a");
/// ```
pub fn parse_str(content: &str) -> anyhow::Result<FileIR> {
    let mut fir = FileIR::new("<memory>".to_string(), "yaml".to_string());
    fir.source = Some(content.to_string());
    parse_yaml(content, &mut fir)?;
    Ok(fir)
}

/// Reads a file and produces its intermediate representation [`FileIR`].
///
/// # Example
/// ```
/// use parsers::parse_file;
/// use std::fs;
/// let path = std::env::temp_dir().join("ex.yaml");
/// fs::write(&path, "a: 1\n# note").unwrap();
/// let ir = parse_file(&path, None, None).unwrap().unwrap();
/// assert_eq!(ir.nodes[0].path, "a");
/// assert!(ir.source.is_some());
/// ```
pub fn parse_file(
    path: &Path,
    suppress_comment: Option<&str>,
    mut metrics: Option<&mut ParserMetrics>,
) -> anyhow::Result<Option<FileIR>> {
    let Some(ftype) = detect_type(path) else {
        debug!(file = %path.display(), "Unsupported file type");
        return Ok(None);
    };
    debug!(file = %path.display(), file_type = ftype, "Parsing file");
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;
    let suppressed = suppress_comment.map_or_else(HashSet::new, |c| {
        content
            .lines()
            .enumerate()
            .filter_map(|(idx, line)| {
                if line.contains(c) {
                    Some(idx + 1)
                } else {
                    None
                }
            })
            .collect()
    });
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut fir = FileIR::new(canonical.to_string_lossy().into_owned(), ftype.to_string());
    let res: anyhow::Result<()> = match language_for(ftype) {
        Some(lang) => lang.parse(&content, &mut fir),
        None => Ok(()),
    };
    if let Err(e) = res {
        if let Some(m) = metrics.as_deref_mut() {
            m.parse_errors += 1;
        }
        return Err(e);
    }
    if fir.symbol_types.contains_key("__parse_error__") {
        if let Some(m) = metrics.as_deref_mut() {
            m.parse_errors += 1;
        }
        return Ok(None);
    }
    if let Some(m) = metrics {
        m.files_parsed += 1;
    }
    fir.source = Some(content);
    fir.suppressed = suppressed;
    Ok(Some(fir))
}

pub fn parse_python_project(root: &Path) -> anyhow::Result<HashMap<String, FileIR>> {
    languages::python::parse_python_project(root)
}

pub fn parse_rust_project_uncached(root: &Path) -> anyhow::Result<HashMap<String, FileIR>> {
    languages::rust::parse_rust_project_uncached(root)
}

#[derive(Serialize, Deserialize)]
struct CachedFile {
    hash: String,
    module: String,
    ir: FileIR,
}

#[derive(Default, Serialize, Deserialize)]
struct CacheData {
    files: HashMap<String, CachedFile>,
}

pub fn parse_python_project_cached(
    root: &Path,
    cache_path: &Path,
    mut metrics: Option<&mut ParserMetrics>,
) -> anyhow::Result<(HashMap<String, FileIR>, usize)> {
    let mut cache: CacheData = fs::read_to_string(cache_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let mut modules = HashMap::new();
    let mut parsed = 0usize;
    let mut stack = vec![root.to_path_buf()];
    let mut seen = HashSet::new();

    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("py") {
                let canonical = path.to_string_lossy().into_owned();
                seen.insert(canonical.clone());
                let content = fs::read_to_string(&path)?;
                let h = blake3::hash(content.as_bytes()).to_hex().to_string();
                if let Some(c) = cache.files.get(&canonical) {
                    if c.hash == h {
                        if let Some(m) = metrics.as_deref_mut() {
                            m.cache_hits += 1;
                        }
                        modules.insert(c.module.clone(), c.ir.clone());
                        continue;
                    }
                }
                let mut fir = FileIR::new(canonical.clone(), "python".into());
                if let Err(e) = languages::python::parse_python(&content, &mut fir) {
                    if let Some(m) = metrics.as_deref_mut() {
                        m.parse_errors += 1;
                    }
                    debug!(file = %canonical, error = ?e, "Failed to parse file");
                    continue;
                }
                if fir.symbol_types.contains_key("__parse_error__") {
                    if let Some(m) = metrics.as_deref_mut() {
                        m.parse_errors += 1;
                    }
                    debug!(file = %canonical, "File contains parse errors");
                    continue;
                }
                if let Some(m) = metrics.as_deref_mut() {
                    m.files_parsed += 1;
                }
                let rel = path.strip_prefix(root).unwrap_or(&path);
                let mut comps: Vec<String> = rel
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect();
                if comps.last().map(|s| s == "__init__.py").unwrap_or(false) {
                    comps.pop();
                }
                if let Some(last) = comps.last_mut() {
                    if last.ends_with(".py") {
                        *last = last.trim_end_matches(".py").to_string();
                    }
                }
                let module = comps.join(".");
                let names: Vec<String> = fir.symbols.keys().cloned().collect();
                for name in names {
                    if fir.symbols.get(&name).and_then(|s| s.def).is_some() {
                        fir.symbol_modules.insert(name, module.clone());
                    }
                }
                modules.insert(module.clone(), fir.clone());
                cache.files.insert(
                    canonical,
                    CachedFile {
                        hash: h,
                        module,
                        ir: fir,
                    },
                );
                parsed += 1;
            }
        }
    }
    cache.files.retain(|k, _| seen.contains(k));
    let cloned = modules.clone();
    for fir in modules.values_mut() {
        crate::languages::python::symbol_table::link_imports(fir, &cloned);
    }
    if let Ok(s) = serde_json::to_string(&cache) {
        let _ = fs::write(cache_path, s);
    }
    Ok((modules, parsed))
}

pub fn parse_rust_project(
    root: &Path,
    cache_path: &Path,
    metrics: Option<&mut ParserMetrics>,
) -> anyhow::Result<(HashMap<String, FileIR>, usize)> {
    languages::rust::parse_rust_project(root, cache_path, metrics)
}

pub fn parse_php_project(
    root: &Path,
    cache_path: &Path,
    metrics: Option<&mut ParserMetrics>,
) -> anyhow::Result<(HashMap<String, FileIR>, usize)> {
    languages::php::parse_php_project(root, cache_path, metrics)
}
