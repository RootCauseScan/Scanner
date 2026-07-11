//! Single source of truth for per-language behavior.
//!
//! Historically the mapping from a `file_type` string to its parser, its
//! on-demand DFG rebuild and its taint catalog was duplicated as `match`
//! arms in several places (`parse_file`, `build_dfg`, the catalog registry
//! and the CLI transform path), which drifted out of sync. The [`Language`]
//! trait and the registry centralize that mapping: adding a language means
//! one `impl` and one registry entry (plus its extension in `detect_type`).

use crate::catalog::Catalog;
use ir::FileIR;

/// Everything the engine needs to know about one language, in one place.
pub trait Language: Sync {
    /// Canonical file-type id (matches [`crate::detect_type`]).
    fn id(&self) -> &'static str;

    /// Parses source into the [`FileIR`] (AST/DFG/symbols as applicable).
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()>;

    /// Rebuilds the data-flow graph on demand. Defaults to a no-op; only
    /// languages that build their DFG via a re-parse override this.
    fn build_dfg(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        let _ = (content, fir);
        Ok(())
    }

    /// Optional taint catalog (sources/sinks/sanitizers).
    fn catalog(&self) -> Option<Catalog> {
        None
    }

    /// Whether `name` is an implicitly-untrusted global input of the language
    /// (e.g. PHP superglobals `$_GET`/`$_POST`). Such names are treated as taint
    /// roots even without an explicit definition. Default: none.
    fn is_untrusted_global(&self, _name: &str) -> bool {
        false
    }

    /// Taint policy for a sink whose variables could not be extracted: `true`
    /// (the default) treats it as potentially unsanitized; languages like PHP,
    /// where sinks are often superglobal-driven, return `false`.
    fn empty_sink_vars_unsanitized(&self) -> bool {
        true
    }
}

// ---- Configuration languages -------------------------------------------------

pub struct Dockerfile;
impl Language for Dockerfile {
    fn id(&self) -> &'static str {
        "dockerfile"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_dockerfile(content, fir);
        Ok(())
    }
}

pub struct Yaml;
impl Language for Yaml {
    fn id(&self) -> &'static str {
        "yaml"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_yaml(content, fir)
    }
}

pub struct Json;
impl Language for Json {
    fn id(&self) -> &'static str {
        "json"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_json(content, fir)
    }
}

pub struct Hcl;
impl Language for Hcl {
    fn id(&self) -> &'static str {
        "hcl"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_hcl(content, fir);
        Ok(())
    }
}

pub struct Generic;
impl Language for Generic {
    fn id(&self) -> &'static str {
        "generic"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_generic(content, fir)
    }
}

// ---- Programming languages ---------------------------------------------------

pub struct TypeScript;
impl Language for TypeScript {
    fn id(&self) -> &'static str {
        "typescript"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_typescript(content, fir);
        Ok(())
    }
    fn catalog(&self) -> Option<Catalog> {
        Some(crate::languages::js_catalog::load_catalog())
    }
}

pub struct JavaScript;
impl Language for JavaScript {
    fn id(&self) -> &'static str {
        "javascript"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_javascript(content, fir);
        Ok(())
    }
    fn catalog(&self) -> Option<Catalog> {
        Some(crate::languages::js_catalog::load_catalog())
    }
}

pub struct Python;
impl Language for Python {
    fn id(&self) -> &'static str {
        "python"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::languages::python::parse_python(content, fir)
    }
    fn build_dfg(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::languages::python::parse_python(content, fir)
    }
    fn catalog(&self) -> Option<Catalog> {
        Some(crate::languages::python::catalog::load_catalog())
    }
}

pub struct Go;
impl Language for Go {
    fn id(&self) -> &'static str {
        "go"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_go(content, fir);
        Ok(())
    }
}

pub struct Ruby;
impl Language for Ruby {
    fn id(&self) -> &'static str {
        "ruby"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_ruby(content, fir);
        Ok(())
    }
}

pub struct Rust;
impl Language for Rust {
    fn id(&self) -> &'static str {
        "rust"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_rust(content, fir)
    }
    fn build_dfg(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_rust(content, fir)
    }
    fn catalog(&self) -> Option<Catalog> {
        Some(crate::languages::rust::catalog::load_catalog())
    }
}

pub struct Java;
impl Language for Java {
    fn id(&self) -> &'static str {
        "java"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_java(content, fir)
    }
    fn build_dfg(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_java(content, fir)
    }
    fn catalog(&self) -> Option<Catalog> {
        Some(crate::languages::java::catalog::load_catalog())
    }
}

pub struct Php;
impl Language for Php {
    fn id(&self) -> &'static str {
        "php"
    }
    fn parse(&self, content: &str, fir: &mut FileIR) -> anyhow::Result<()> {
        crate::parse_php(content, fir)
    }
    fn catalog(&self) -> Option<Catalog> {
        Some(crate::languages::php::catalog::load_catalog())
    }
    fn is_untrusted_global(&self, name: &str) -> bool {
        const PHP_SUPERGLOBALS: &[&str] = &[
            "_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_ENV", "_FILES", "_SESSION",
            "GLOBALS",
        ];
        PHP_SUPERGLOBALS.contains(&name.trim_start_matches('$'))
    }
    fn empty_sink_vars_unsanitized(&self) -> bool {
        false
    }
}

/// The full set of supported languages — the single dispatch table.
static REGISTRY: &[&(dyn Language + Sync)] = &[
    &Dockerfile,
    &Yaml,
    &Json,
    &Hcl,
    &Generic,
    &TypeScript,
    &JavaScript,
    &Python,
    &Go,
    &Ruby,
    &Rust,
    &Java,
    &Php,
];

/// All registered languages (used to build the catalog registry).
pub fn registry() -> &'static [&'static (dyn Language + Sync)] {
    REGISTRY
}

/// Looks up a language by its canonical id.
pub fn language_for(id: &str) -> Option<&'static (dyn Language + Sync)> {
    REGISTRY.iter().copied().find(|lang| lang.id() == id)
}
