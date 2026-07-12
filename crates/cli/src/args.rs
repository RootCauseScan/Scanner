use clap::{parser::ValueSource, Args as ClapArgs, Parser, Subcommand};
use std::path::PathBuf;

use crate::config::config_dir;
use crate::IgnorePattern;
use crate::DEFAULT_MAX_FILE_SIZE;
use loader::Severity;

use crate::output::Format;

fn parse_severity(s: &str) -> Result<Severity, String> {
    s.parse()
}

fn default_rules_path() -> PathBuf {
    config_dir().join("rules")
}

fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

fn parse_threads(s: &str) -> Result<usize, String> {
    let v: usize = s
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    if v == 0 {
        Err("threads must be greater than 0".into())
    } else {
        Ok(v)
    }
}

fn parse_language(s: &str) -> Result<String, String> {
    parsers::canonical_language(s).map(str::to_string).ok_or_else(|| {
        format!(
            "unknown language '{s}'; supported: {}",
            parsers::SUPPORTED_LANGUAGES.join(", ")
        )
    })
}

fn parse_chunk_size(s: &str) -> Result<usize, String> {
    let v: usize = s
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    if v == 0 {
        Err("chunk-size must be greater than 0".into())
    } else {
        Ok(v)
    }
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "🐾 RootCause - Static Analysis Security Testing (SAST) tool for multi-language codebases",
    long_about = "RootCause is a powerful Static Analysis Security Testing (SAST) tool that helps developers find security vulnerabilities, code quality issues, and compliance violations in their codebases.

Features:
• Multi-language support (Python, Rust, JavaScript, Java, Docker, YAML, etc.)
• Customizable rule sets with YAML, JSON, Semgrep, and OPA support (Semgrep rules load automatically)
• Supports advanced Semgrep features like pattern-regex, metavariable-pattern, and taint tracking
• Plugin architecture for extensibility
• Multiple output formats (Text, JSON, SARIF)
• CI/CD integration ready
• Real-time scanning and reporting

Examples:
  rootcause scan .                    # Scan current directory
  rootcause scan src/ --format json   # Scan with JSON output
  rootcause rules install <url>       # Install custom rules
  rootcause plugins list              # List installed plugins",
    subcommand_required = true,
    disable_version_flag = true
)]
pub struct Cli {
    /// Show version information
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    pub version: Option<bool>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Scan code for security vulnerabilities and quality issues
    Scan(ScanArgs),
    /// Manage plugins for extending RootCause functionality
    #[command(subcommand, alias = "plugin")]
    Plugins(PluginCmd),
    /// Manage security rules and rule sets
    #[command(subcommand, alias = "rule")]
    Rules(RulesCmd),
}

pub fn parse_cli() -> Cli {
    use clap::{CommandFactory, FromArgMatches};

    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    if let Some(("scan", scan_matches)) = matches.subcommand() {
        if let Commands::Scan(args) = &mut cli.command {
            if let Some(source) = scan_matches.value_source("rules") {
                if source != ValueSource::DefaultValue {
                    args.rules_provided = true;
                }
            }
        }
    }
    cli
}

#[derive(ClapArgs)]
pub struct ScanArgs {
    /// Path to scan (file or directory)
    pub path: PathBuf,
    /// Path to rules directory or ruleset
    #[arg(long, default_value_os_t = default_rules_path())]
    pub rules: PathBuf,
    /// Restrict the scan to these languages (comma-separated, e.g. `java,php,javascript`).
    /// Common aliases like `js`/`ts`/`py` are accepted. When omitted, every detected
    /// language is scanned. Language-specific rules for the selected languages plus
    /// generic content rules are applied; files of other languages are skipped.
    #[arg(short = 'l', long = "langs", value_delimiter = ',', value_parser = parse_language)]
    pub languages: Vec<String>,
    /// Download official rules automatically when missing
    #[arg(long = "download-rules", hide = true)]
    pub download_rules: bool,
    /// True if `--rules` was explicitly provided.
    #[arg(skip = false)]
    pub rules_provided: bool,
    /// Output format for scan results
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    /// Exit with error code if findings of this severity or higher are found
    #[arg(long = "fail-on", value_parser = parse_severity)]
    pub fail_on: Option<Severity>,
    /// Number of parallel threads to use for scanning
    #[arg(long, default_value_t = default_threads(), value_parser = parse_threads, hide = true)]
    pub threads: usize,
    /// Exclude files matching these patterns (supports regex)
    #[arg(long, value_parser = crate::parse_exclude, value_delimiter = ',')]
    pub exclude: Vec<IgnorePattern>,
    /// Don't use default exclusion patterns
    #[arg(long, hide = true)]
    pub no_default_exclude: bool,
    /// Maximum file size to scan (in bytes)
    #[arg(long, default_value_t = DEFAULT_MAX_FILE_SIZE, hide = true)]
    pub max_file_size: u64,
    /// Timeout per rule-vs-file operation in milliseconds
    #[arg(long, hide = true)]
    pub timeout_operation_ms: Option<u64>,
    /// Write performance metrics to file
    #[arg(long, hide = true)]
    pub metrics: Option<PathBuf>,
    /// Path to baseline file for comparison
    #[arg(long, hide = true)]
    pub baseline: Option<PathBuf>,
    /// Write baseline file with current findings
    #[arg(long = "write-baseline", hide = true)]
    pub write_baseline: Option<PathBuf>,
    /// Load plugins from specified paths
    #[arg(long = "plugin", hide = true)]
    pub plugins: Vec<PathBuf>,
    /// Plugin options as key=value pairs
    #[arg(long = "plugin-opt", hide = true)]
    pub plugin_opts: Vec<String>,
    /// Path to plugin configuration file
    #[arg(long = "plugin-config", hide = true)]
    pub plugin_config: Option<PathBuf>,
    /// Comment pattern to suppress findings
    #[arg(long = "suppress-comment", default_value = "sast-ignore", hide = true)]
    pub suppress_comment: String,
    /// Enable streaming mode for large outputs
    #[arg(long, hide = true)]
    pub stream: bool,
    /// Number of findings to process in each chunk
    #[arg(long, default_value_t = 100, value_parser = parse_chunk_size, hide = true)]
    pub chunk_size: usize,
    /// Dump taint analysis data for debugging
    #[arg(long = "dump-taints", hide = true)]
    pub dump_taints: bool,
    /// Enable debug output
    #[arg(long)]
    pub debug: bool,
    /// Suppress non-essential output
    #[arg(long)]
    pub quiet: bool,
    /// Automatically apply suggested fixes
    #[arg(long = "apply-fixes")]
    pub apply_fixes: bool,
    /// Directory to store cache files
    #[arg(long = "cache-dir", hide = true)]
    pub cache_dir: Option<PathBuf>,
    /// Disable the literal prefilter (evaluate every rule against every file).
    /// Debugging aid to compare results/timings; the prefilter only skips rules
    /// that provably cannot match, so this should not change findings.
    #[arg(long = "no-prefilter", hide = true)]
    pub no_prefilter: bool,
}

#[derive(Subcommand)]
pub enum PluginCmd {
    /// Verify that a plugin works correctly
    Verify {
        /// Path to the plugin directory
        path: PathBuf,
    },
    /// Ping a plugin to verify connectivity
    Ping {
        /// Path to the plugin directory
        path: PathBuf,
    },
    /// Initialise a new plugin from a template
    Init {
        /// Directory where to create the plugin
        dir: PathBuf,
    },
    /// Install a plugin from a local path or remote repository
    Install {
        /// Local path or repository URL of the plugin
        src: String,
    },
    /// List all installed plugins
    List,
    /// Remove an installed plugin
    Remove {
        /// Name of the plugin to remove
        name: String,
    },
    /// Disable an installed plugin
    Disable {
        /// Name of the plugin to disable
        name: String,
    },
    /// Enable a previously disabled plugin
    Enable {
        /// Name of the plugin to enable
        name: String,
    },
    /// Configure plugin parameters
    Config {
        /// Name of the plugin to configure
        name: String,
        /// Parameters to set as `key=value` pairs
        params: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum RulesCmd {
    /// Verify that rules are correctly formatted
    Verify {
        /// Path to the rules directory or file
        path: PathBuf,
        /// Show all files and rules without truncation
        #[arg(long)]
        full: bool,
    },
    /// Inspect a specific rule or all rules from a file
    Inspect {
        /// Rule ID to inspect or path to rule file
        target: String,
        /// Base directory for rule loading (defaults to <rootcause_dir>/rules/)
        #[arg(long, default_value_os_t = default_rules_path())]
        base_dir: PathBuf,
    },
    /// Install a ruleset from a tarball
    Install {
        /// URL or path to the `.tar.gz` archive
        src: String,
        /// Optional name for the ruleset folder (defaults to extracted name)
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Update installed rulesets
    Update {
        /// Optional name of the ruleset to update
        name: Option<String>,
    },
    /// Remove an installed ruleset
    Remove {
        /// Name of the ruleset to remove
        name: String,
    },
    /// List installed rulesets
    List,
}

#[cfg(test)]
mod tests {

    #[test]
    fn parse_severity_rejects_invalid_input() {
        assert!(super::parse_severity("bogus").is_err());
    }
}
