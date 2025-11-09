#![allow(clippy::uninlined_format_args)]

use anyhow::{anyhow, Context, Result};
use colored::*;
use loader::{self, CompiledRule, Severity};
use serde::Deserialize;
use std::{
    collections::HashMap,
    env, fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::config::{config_dir, load_config, save_config};

#[derive(Debug, Clone)]
struct RuleError {
    file_path: String,
    error_message: String,
}

#[derive(Debug, Default)]
struct ErrorCollection {
    errors: Vec<RuleError>,
    duplicate_rules: HashMap<String, Vec<String>>, // rule_id -> list of files
}

impl ErrorCollection {
    fn add_error(&mut self, file_path: String, error_message: String) {
        self.errors.push(RuleError {
            file_path,
            error_message,
        });
    }

    fn add_duplicate_rule(&mut self, rule_id: String, file_path: String) {
        self.duplicate_rules
            .entry(rule_id)
            .or_default()
            .push(file_path);
    }

    fn has_errors(&self) -> bool {
        !self.errors.is_empty() || !self.duplicate_rules.is_empty()
    }

    fn print_errors(&self, full: bool) {
        if !self.errors.is_empty() {
            println!();
            println!("{}", "Errors found:".bright_red().bold());
            for (i, error) in self.errors.iter().enumerate() {
                if full || i < 10 {
                    println!(
                        "  {} {}: {}",
                        "•".bright_red(),
                        error.file_path.bright_white(),
                        error.error_message.bright_red()
                    );
                } else if i == 10 {
                    println!(
                        "  {} {} more errors...",
                        "•".bright_red(),
                        (self.errors.len() - 10).to_string().bright_yellow()
                    );
                    break;
                }
            }
        }

        if !self.duplicate_rules.is_empty() {
            println!();
            println!("{}", "Duplicate rule IDs found:".bright_red().bold());
            for (i, (rule_id, files)) in self.duplicate_rules.iter().enumerate() {
                if full || i < 5 {
                    println!(
                        "  {} Rule ID '{}' found in:",
                        "•".bright_red(),
                        rule_id.bright_white().bold()
                    );
                    for file in files {
                        println!("    - {}", file.bright_cyan());
                    }
                } else if i == 5 {
                    println!(
                        "  {} {} more duplicate rule IDs...",
                        "•".bright_red(),
                        (self.duplicate_rules.len() - 5).to_string().bright_yellow()
                    );
                    break;
                }
            }
        }
    }
}

/// Load rules and collect errors instead of failing on first error
fn load_rules_with_error_collection(path: &Path) -> Result<(loader::RuleSet, ErrorCollection)> {
    let mut error_collection = ErrorCollection::default();

    // Try to load rules normally first
    match loader::load_rules(path) {
        Ok(ruleset) => Ok((ruleset, error_collection)),
        Err(e) => {
            // If we get an error, try to extract information from it
            let error_msg = e.to_string();
            if error_msg.contains("duplicate rule id:") {
                // Extract the rule ID from the error message
                if let Some(rule_id_start) = error_msg.find("duplicate rule id: ") {
                    let rule_id = &error_msg[rule_id_start + 19..];
                    error_collection.add_duplicate_rule(rule_id.to_string(), "unknown".to_string());
                }
            }

            // Try to load rules individually to get more detailed error information
            let mut rs = loader::RuleSet::default();
            load_rules_individually(path, &mut rs, &mut error_collection)?;

            Ok((rs, error_collection))
        }
    }
}

/// Load rules file by file to collect detailed error information
fn load_rules_individually(
    path: &Path,
    rs: &mut loader::RuleSet,
    error_collection: &mut ErrorCollection,
) -> Result<()> {
    use std::collections::HashMap;
    use std::fs;

    fn visit_files<F>(dir: &Path, exclude: &dyn Fn(&Path) -> bool, f: &mut F) -> Result<()>
    where
        F: FnMut(&Path) -> Result<()>,
    {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_path = entry.path();
            if file_path.is_file() {
                f(&file_path)?;
            } else if file_path.is_dir() && !exclude(&file_path) {
                visit_files(&file_path, exclude, f)?;
            }
        }
        Ok(())
    }

    let excl = |p: &Path| {
        p.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == ".git")
            .unwrap_or(false)
    };

    // First pass: collect all rule IDs and their files
    let mut rule_id_to_files: HashMap<String, Vec<String>> = HashMap::new();

    visit_files(path, &excl, &mut |file_path| {
        let name = file_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let relative_path = file_path
            .strip_prefix(path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        if name.ends_with(".yaml") || name.ends_with(".yml") {
            // Try to extract rule IDs from the file without fully parsing
            if let Ok(rule_ids) = extract_rule_ids_from_file(file_path) {
                for rule_id in rule_ids {
                    rule_id_to_files
                        .entry(rule_id)
                        .or_default()
                        .push(relative_path.clone());
                }
            }
        }
        Ok(())
    })?;

    // Check for duplicates
    for (rule_id, files) in &rule_id_to_files {
        if files.len() > 1 {
            for file in files {
                error_collection.add_duplicate_rule(rule_id.clone(), file.clone());
            }
        }
    }

    // Second pass: try to load individual files
    visit_files(path, &excl, &mut |file_path| {
        let name = file_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let relative_path = file_path
            .strip_prefix(path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        if name.ends_with(".yaml") || name.ends_with(".yml") {
            // Try to load this single file using the loader
            match loader::load_rules(file_path) {
                Ok(single_ruleset) => {
                    // Successfully loaded, merge into our ruleset
                    rs.rules.extend(single_ruleset.rules);
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    if !error_msg.contains("duplicate rule id:") {
                        // Only add non-duplicate errors since we already handled duplicates above
                        error_collection.add_error(relative_path, error_msg);
                    }
                }
            }
        }
        Ok(())
    })?;

    Ok(())
}

/// Extract rule IDs from a YAML file without fully parsing it
fn extract_rule_ids_from_file(file_path: &Path) -> Result<Vec<String>> {
    use std::fs;

    let content = fs::read_to_string(file_path)?;
    let mut rule_ids = Vec::new();

    // Simple regex-based extraction of rule IDs
    // Look for patterns like "id: rule-name" in YAML
    let lines: Vec<&str> = content.lines().collect();
    for line in lines.iter() {
        let trimmed = line.trim();
        if trimmed.starts_with("id:") || trimmed.starts_with("- id:") {
            // Extract the ID value
            let id_part = if let Some(stripped) = trimmed.strip_prefix("- id:") {
                stripped
            } else if let Some(stripped) = trimmed.strip_prefix("id:") {
                stripped
            } else {
                continue;
            };

            let id_value = id_part.trim().trim_matches('"').trim_matches('\'');
            if !id_value.is_empty() {
                rule_ids.push(id_value.to_string());
            }
        }
    }

    Ok(rule_ids)
}

pub fn verify_rules(path: &Path, full: bool) -> Result<()> {
    println!("{}", "Verifying rules...".bright_blue().bold());
    println!("Directory: {}", path.display().to_string().bright_white());
    let (rule_files, invalid_files) = scan_rule_files(path)?;
    if !rule_files.is_empty() {
        println!();
        println!("{}", "Rule files found:".bright_cyan().bold());
        for (i, file) in rule_files.iter().enumerate() {
            if full || i < 5 {
                println!("  {} {}", "•".bright_white(), file.bright_white());
            } else if i == 5 {
                println!(
                    "  {} {} more files...",
                    "•".bright_white(),
                    (rule_files.len() - 5).to_string().bright_yellow()
                );
                break;
            }
        }
    }
    if !invalid_files.is_empty() {
        println!();
        println!("{}", "Invalid files found:".bright_yellow().bold());
        for (i, file) in invalid_files.iter().enumerate() {
            if full || i < 3 {
                println!("  {} {}", "•".bright_white(), file.bright_white());
            } else if i == 3 {
                println!(
                    "  {} {} more invalid files...",
                    "•".bright_white(),
                    (invalid_files.len() - 3).to_string().bright_yellow()
                );
                break;
            }
        }
    }
    // Try to load rules and collect errors
    let (rs, error_collection) = load_rules_with_error_collection(path)?;

    // Print error summary
    if error_collection.has_errors() {
        println!();
        println!(
            "{}",
            "Issues found during rule loading:".bright_yellow().bold()
        );
        error_collection.print_errors(full);
    } else {
        println!();
        println!("{}", "Rules loaded successfully".bright_green().bold());
    }
    let rule_count = rs.rules.len();
    if rule_count > 0 {
        println!();
        println!("{}", "Rules loaded:".bright_cyan().bold());
        for (i, rule) in rs.rules.iter().enumerate() {
            if full || i < 5 {
                let severity = format!("{:?}", rule.severity).to_lowercase();
                let severity_color = match rule.severity {
                    Severity::Critical => severity.bright_red(),
                    Severity::High => severity.bright_magenta(),
                    Severity::Medium => severity.bright_yellow(),
                    Severity::Low => severity.bright_blue(),
                    Severity::Info => severity.bright_cyan(),
                    Severity::Error => severity.bright_red(),
                };
                if full {
                    let source_info = if let Some(source) = &rule.source_file {
                        format!(" [from: {}]", source.bright_cyan())
                    } else {
                        String::new()
                    };
                    println!(
                        "  {} {} ({}){}",
                        "•".bright_white(),
                        rule.id.bright_white().bold(),
                        severity_color,
                        source_info
                    );
                } else {
                    println!(
                        "  {} {} ({})",
                        "•".bright_white(),
                        rule.id.bright_white().bold(),
                        severity_color
                    );
                }
            } else if i == 5 {
                println!(
                    "  {} {} more rules...",
                    "•".bright_white(),
                    (rule_count - 5).to_string().bright_yellow()
                );
                break;
            }
        }
    }
    println!();
    println!("{}", "Statistics:".bright_cyan().bold());
    println!(
        "  Rule files: {}",
        rule_files.len().to_string().bright_yellow()
    );
    println!("  Rules loaded: {}", rule_count.to_string().bright_yellow());
    if !invalid_files.is_empty() {
        println!(
            "  Invalid files: {}",
            invalid_files.len().to_string().bright_red()
        );
    }
    if error_collection.has_errors() {
        println!(
            "  Errors found: {}",
            error_collection.errors.len().to_string().bright_red()
        );
        println!(
            "  Duplicate rules: {}",
            error_collection
                .duplicate_rules
                .len()
                .to_string()
                .bright_red()
        );
    }
    if rule_count == 0 {
        println!();
        println!("{}", "No valid rules found".bright_yellow().bold());
        println!(
            "{}",
            "   Verify that the directory contains valid .yaml or .yml files".bright_yellow()
        );
    } else if error_collection.has_errors() {
        println!();
        println!(
            "{}",
            "Verification completed with issues".bright_yellow().bold()
        );
    } else {
        println!();
        println!(
            "{}",
            "Verification completed without errors"
                .bright_green()
                .bold()
        );
    }
    Ok(())
}

pub fn inspect_rules(target: &str, base_dir: &Path) -> Result<()> {
    println!("{}", "Inspecting rules...".bright_blue().bold());
    if target.ends_with(".yaml") || target.ends_with(".yml") || target.ends_with(".json") {
        let file_path = Path::new(target);
        if !file_path.exists() {
            println!("{}", "File not found".bright_red().bold());
            println!("{}", format!("File: {target}").bright_red());
            return Ok(());
        }
        println!("File: {}", file_path.display().to_string().bright_white());
        let rs = match loader::load_rules(file_path) {
            Ok(ruleset) => ruleset,
            Err(e) => {
                println!("{}", "Error loading rules from file".bright_red().bold());
                println!("{}", format!("Error: {e}").bright_red());
                return Err(e);
            }
        };
        if rs.rules.is_empty() {
            println!("{}", "No rules found in file".bright_yellow().bold());
            return Ok(());
        }
        println!("{}", "Rules loaded successfully".bright_green().bold());
        println!();
        for (i, rule) in rs.rules.iter().enumerate() {
            display_rule_details(rule, i + 1, rs.rules.len());
            if i < rs.rules.len() - 1 {
                println!();
            }
        }
    } else {
        let default_rules_dir = base_dir;
        if !default_rules_dir.exists() {
            println!(
                "{}",
                "Default rules directory not found".bright_red().bold()
            );
            println!(
                "{}",
                format!("Directory: {}", default_rules_dir.display()).bright_red()
            );
            return Ok(());
        }
        println!(
            "Searching in: {}",
            default_rules_dir.display().to_string().bright_white()
        );
        println!("Rule ID: {}", target.bright_white().bold());
        let rs = match loader::load_rules(default_rules_dir) {
            Ok(ruleset) => ruleset,
            Err(e) => {
                println!("{}", "Error loading rules".bright_red().bold());
                println!("{}", format!("Error: {e}").bright_red());
                return Err(e);
            }
        };
        let matching_rules: Vec<_> = rs.rules.iter().filter(|rule| rule.id == target).collect();
        if matching_rules.is_empty() {
            println!("{}", "Rule not found".bright_red().bold());
            println!(
                "{}",
                format!("Rule ID '{target}' not found in rules directory").bright_red()
            );
            println!();
            println!("{}", "Available rules:".bright_cyan().bold());
            for rule in rs.rules.iter().take(10) {
                println!("  {} {}", "•".bright_white(), rule.id.bright_white());
            }
            if rs.rules.len() > 10 {
                println!(
                    "  {} {} more rules...",
                    "•".bright_white(),
                    (rs.rules.len() - 10).to_string().bright_yellow()
                );
            }
            return Ok(());
        }
        println!("{}", "Rule found".bright_green().bold());
        println!();
        for (i, rule) in matching_rules.iter().enumerate() {
            display_rule_details(rule, i + 1, matching_rules.len());
            if i < matching_rules.len() - 1 {
                println!();
            }
        }
    }
    Ok(())
}

fn display_rule_details(rule: &CompiledRule, index: usize, total: usize) {
    println!("{}", format!("Rule #{index}").bright_cyan().bold());
    if total > 1 {
        println!(
            "  {} Total rules: {}",
            "•".bright_white(),
            total.to_string().bright_yellow()
        );
    }
    println!(
        "  {} ID: {}",
        "•".bright_white(),
        rule.id.bright_white().bold()
    );
    let severity = format!("{:?}", rule.severity).to_lowercase();
    let severity_color = match rule.severity {
        Severity::Critical => severity.bright_red(),
        Severity::High => severity.bright_magenta(),
        Severity::Medium => severity.bright_yellow(),
        Severity::Low => severity.bright_blue(),
        Severity::Info => severity.bright_cyan(),
        Severity::Error => severity.bright_red(),
    };
    println!("  {} Severity: {}", "•".bright_white(), severity_color);
    println!(
        "  {} Category: {}",
        "•".bright_white(),
        rule.category.bright_white()
    );
    if let Some(source) = &rule.source_file {
        println!("  {} Source: {}", "•".bright_white(), source.bright_cyan());
    }
    if !rule.message.is_empty() {
        println!(
            "  {} Message: {}",
            "•".bright_white(),
            rule.message.bright_white()
        );
    }
    if let Some(remediation) = &rule.remediation {
        println!(
            "  {} Remediation: {}",
            "•".bright_white(),
            remediation.bright_green()
        );
    }
    if let Some(fix) = &rule.fix {
        println!("  {} Fix: {}", "•".bright_white(), fix.bright_green());
    }
    println!(
        "  {} Inter-file: {}",
        "•".bright_white(),
        if rule.interfile {
            "Yes".bright_green()
        } else {
            "No".bright_red()
        }
    );
    println!(
        "  {} Matcher: {}",
        "•".bright_white(),
        match &rule.matcher {
            loader::MatcherKind::TextRegex(_, _) => "Text Regex".bright_blue(),
            loader::MatcherKind::TextRegexMulti { .. } => "Text Regex Multi".bright_blue(),
            loader::MatcherKind::JsonPathEq(_, _) => "JSON Path Equality".bright_magenta(),
            loader::MatcherKind::JsonPathRegex(_, _) => "JSON Path Regex".bright_magenta(),
            loader::MatcherKind::AstQuery(_) => "AST Query".bright_yellow(),
            loader::MatcherKind::AstPattern(_) => "AST Pattern".bright_yellow(),
            loader::MatcherKind::RegoWasm { .. } => "Rego WASM".bright_cyan(),
            loader::MatcherKind::TaintRule { .. } => "Taint Analysis".bright_red(),
        }
    );
}

fn scan_rule_files(path: &Path) -> Result<(Vec<String>, Vec<String>)> {
    let mut rule_files = Vec::new();
    let mut invalid_files = Vec::new();

    fn is_rule_artifact(file_path: &Path) -> bool {
        matches!(
            file_path.extension().and_then(|ext| ext.to_str()),
            Some("yaml" | "yml" | "json" | "wasm")
        )
    }

    fn push_relative(
        file_path: &Path,
        base: &Path,
        rule_files: &mut Vec<String>,
        invalid_files: &mut Vec<String>,
    ) {
        let relative_path = file_path
            .strip_prefix(base)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        if is_rule_artifact(file_path) {
            rule_files.push(relative_path);
        } else {
            invalid_files.push(relative_path);
        }
    }

    fn scan_recursive(
        dir: &Path,
        base: &Path,
        rule_files: &mut Vec<String>,
        invalid_files: &mut Vec<String>,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_path = entry.path();
            if file_path.is_file() {
                push_relative(&file_path, base, rule_files, invalid_files);
            } else if file_path.is_dir()
                && file_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name != ".git")
                    .unwrap_or(true)
            {
                scan_recursive(&file_path, base, rule_files, invalid_files)?;
            }
        }
        Ok(())
    }

    if path.is_dir() {
        scan_recursive(path, path, &mut rule_files, &mut invalid_files)?;
    } else if path.is_file() {
        if is_rule_artifact(path) {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            rule_files.push(file_name);
        } else {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            invalid_files.push(file_name);
        }
    }

    Ok((rule_files, invalid_files))
}

/// Check if colored output should be used
fn use_colored_output() -> bool {
    // Check if NO_COLOR is set (standard environment variable to disable colors)
    if env::var("NO_COLOR").is_ok() {
        return false;
    }

    // Check if TERM indicates a basic terminal
    if let Ok(term) = env::var("TERM") {
        if term == "dumb" || term == "unknown" {
            return false;
        }
    }

    // Check if we're in a CI environment
    if env::var("CI").is_ok() || env::var("CONTINUOUS_INTEGRATION").is_ok() {
        return false;
    }

    // Default to true for modern terminals
    true
}

/// Print a status message with appropriate formatting
fn print_status(tag: &str, message: &str) {
    println!("[{}] {}", tag, message);
}

/// Print a colored message with fallback for basic terminals
fn print_colored(tag: &str, message: &str) {
    if use_colored_output() {
        println!("[{}] {}", tag.bright_blue().bold(), message);
    } else {
        println!("[{}] {}", tag, message);
    }
}

/// Print an error message with appropriate formatting
fn print_error(tag: &str, message: &str) {
    if use_colored_output() {
        println!("[{}] {}", tag.bright_red().bold(), message);
    } else {
        println!("[{}] {}", tag, message);
    }
}

/// Print a success message with appropriate formatting
fn print_success(tag: &str, message: &str) {
    if use_colored_output() {
        println!("[{}] {}", tag.bright_green().bold(), message);
    } else {
        println!("[{}] {}", tag, message);
    }
}

/// Print an info message with appropriate formatting
fn print_info(tag: &str, message: &str) {
    if use_colored_output() {
        println!("[{}] {}", tag.bright_yellow(), message);
    } else {
        println!("[{}] {}", tag, message);
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct Manifest {
    name: String,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    git_url: Option<String>,
}

/// Install a ruleset from various sources (git, tar.gz, or local directory).
pub fn install_ruleset(src: &str, folder_name: Option<&str>) -> Result<()> {
    print_colored("INSTALL", "Installing ruleset...");
    print_status("SOURCE", &format!("Source: {}", src));

    let (ruleset_dir, extracted_name, git_url) = if is_git_url(src) {
        install_from_git(src)?
    } else if src.ends_with(".tar.gz") || src.ends_with(".tgz") {
        install_from_tarball(src)?
    } else {
        install_from_local_dir(src)?
    };

    // Use provided folder name or fall back to extracted name
    let name = folder_name.unwrap_or(&extracted_name);
    let dest_dir = config_dir().join("rules").join(name);
    if dest_dir.exists() {
        print_info("WARN", &format!("Overwriting existing ruleset: {}", name));
        fs::remove_dir_all(&dest_dir)?;
    }

    copy_dir_all(&ruleset_dir, &dest_dir)?;

    // Create or update manifest.toml
    let manifest_path = dest_dir.join("manifest.toml");
    let manifest_content = if manifest_path.exists() {
        // Keep existing manifest if it exists
        fs::read_to_string(&manifest_path)?
    } else {
        // Create basic manifest
        let mut manifest = format!("name = \"{name}\"\n");
        if let Some(git) = &git_url {
            manifest.push_str(&format!("git_url = \"{git}\"\n"));
            manifest.push_str(&format!("origin = \"{git}\"\n"));
        } else {
            manifest.push_str(&format!("origin = \"{src}\"\n"));
        }
        manifest
    };
    fs::write(&manifest_path, manifest_content)?;

    // Update config.toml to include the new ruleset directory
    let mut cfg = load_config().context("failed to load configuration")?;
    let ruleset_path = dest_dir.clone();
    if !cfg.rules.rule_dirs.contains(&ruleset_path) {
        cfg.rules.rule_dirs.push(ruleset_path);
        save_config(&cfg)?;
        print_success("OK", "Configuration updated");
    }

    println!();
    print_success("SUCCESS", "Ruleset installed successfully");
    print_status("NAME", &format!("Name: {}", name));
    print_status("LOCATION", &format!("Location: {}", dest_dir.display()));

    Ok(())
}

fn is_git_url(src: &str) -> bool {
    src.starts_with("git@") || src.starts_with("https://") || src.starts_with("http://")
}

fn install_from_git(src: &str) -> Result<(std::path::PathBuf, String, Option<String>)> {
    print_status("GIT", "Cloning from git repository...");

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before UNIX_EPOCH")?
        .as_secs();
    let tmp_dir = std::env::temp_dir().join(format!("rootcause_git_{ts}"));

    let status = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg(src)
        .arg(&tmp_dir)
        .status()
        .context("failed to run git clone")?;

    if !status.success() {
        return Err(anyhow!("git clone exited with non-zero status"));
    }

    let name = extract_name_from_git_url(src);
    Ok((tmp_dir, name, Some(src.to_string())))
}

fn install_from_tarball(src: &str) -> Result<(std::path::PathBuf, String, Option<String>)> {
    print_status("TAR", "Downloading and extracting tarball...");

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before UNIX_EPOCH")?
        .as_secs();
    let tmp_dir = std::env::temp_dir().join(format!("rootcause_tar_{ts}"));
    fs::create_dir_all(&tmp_dir)?;

    let tar_path = tmp_dir.join("pkg.tar.gz");
    let status = Command::new("curl")
        .arg("-L")
        .arg("-f") // fail on server errors
        .arg(src)
        .arg("-o")
        .arg(&tar_path)
        .status()
        .context("failed to run curl")?;

    if !status.success() {
        return Err(anyhow!("curl exited with non-zero status"));
    }

    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&tar_path)
        .arg("-C")
        .arg(&tmp_dir)
        .status()
        .context("failed to run tar")?;

    if !status.success() {
        return Err(anyhow!("tar exited with non-zero status"));
    }

    let mut extracted = None;
    for entry in fs::read_dir(&tmp_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            extracted = Some(entry.path());
            break;
        }
    }
    let extracted_dir = extracted.unwrap_or_else(|| tmp_dir.clone());

    let name = extract_name_from_tarball_url(src);
    Ok((extracted_dir, name, None))
}

fn install_from_local_dir(src: &str) -> Result<(std::path::PathBuf, String, Option<String>)> {
    print_status("LOCAL", "Copying from local directory...");

    let src_path = Path::new(src);
    if !src_path.exists() {
        return Err(anyhow!("Source directory does not exist: {}", src));
    }

    if !src_path.is_dir() {
        return Err(anyhow!("Source path is not a directory: {}", src));
    }

    let name = src_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ruleset")
        .to_string();

    Ok((src_path.to_path_buf(), name, None))
}

fn extract_name_from_git_url(url: &str) -> String {
    // Extract repository name from git URL
    // Examples: https://github.com/user/repo.git -> repo
    //           git@github.com:user/repo.git -> repo
    let name = if let Some(stripped) = url.strip_suffix(".git") {
        stripped
    } else {
        url
    };

    name.split('/').next_back().unwrap_or("ruleset").to_string()
}

fn extract_name_from_tarball_url(url: &str) -> String {
    let file_name = Path::new(url)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ruleset");

    file_name
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".tgz")
        .to_string()
}

/// Update installed rulesets, optionally filtering by `name`.
pub fn update_ruleset(name: Option<&str>) -> Result<()> {
    print_colored("UPDATE", "Updating rulesets...");

    let rules_root = config_dir().join("rules");
    if !rules_root.exists() {
        print_info("INFO", "No rulesets directory found");
        return Ok(());
    }

    let mut updated_count = 0;
    let mut total_count = 0;

    for entry in fs::read_dir(&rules_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let dir_name = entry.file_name();
        let dir_name = dir_name.to_string_lossy();
        if let Some(target) = name {
            if target != dir_name {
                continue;
            }
        }
        total_count += 1;

        let manifest_path = entry.path().join("manifest.toml");
        let content = match fs::read_to_string(&manifest_path) {
            Ok(c) => c,
            Err(_) => {
                print_info("WARN", &format!("No manifest found for: {}", dir_name));
                continue;
            }
        };
        let manifest: Manifest = match toml::from_str(&content) {
            Ok(m) => m,
            Err(_) => {
                print_info("WARN", &format!("Invalid manifest for: {}", dir_name));
                continue;
            }
        };

        print_status("UPDATE", &format!("Updating: {}", manifest.name));

        if let Some(git_url) = &manifest.git_url {
            // Update from git
            let status = Command::new("git")
                .arg("-C")
                .arg(entry.path())
                .arg("pull")
                .status();

            match status {
                Ok(exit_status) if exit_status.success() => {
                    print_success("OK", &format!("Updated from git: {}", git_url));
                    updated_count += 1;
                }
                Ok(_) => {
                    print_error("ERROR", &format!("Failed to update from git: {}", git_url));
                }
                Err(_) => {
                    print_error("ERROR", &format!("Git not available for: {}", dir_name));
                }
            }
        } else {
            print_info(
                "INFO",
                &format!("No git URL configured for: {}", manifest.name),
            );
        }
    }

    println!();
    if total_count == 0 {
        print_info("INFO", "No rulesets found to update");
    } else {
        print_success(
            "SUCCESS",
            &format!("Updated {updated_count}/{total_count} rulesets"),
        );
    }

    Ok(())
}

/// Remove an installed ruleset and its config entry if present.
pub fn remove_ruleset(name: &str) -> Result<()> {
    print_colored("REMOVE", "Removing ruleset...");
    print_status("RULESET", &format!("Ruleset: {name}"));

    let root = config_dir().join("rules");
    let target = root.join(name);

    if target.exists() {
        println!();
        print_info("WARN", "Removing ruleset files...");
        fs::remove_dir_all(&target)?;
        print_success("OK", "Ruleset directory removed");
    } else {
        println!();
        print_error("ERROR", "Ruleset not found");
        print_error("ERROR", &format!("Ruleset '{name}' not found"));
        println!();
        print_status(
            "TIP",
            "Use 'rootcause rules list' to see installed rulesets",
        );
        return Ok(());
    }

    let mut cfg = load_config().context("failed to load configuration")?;
    let before = cfg.rules.rule_dirs.len();
    cfg.rules.rule_dirs.retain(|p| {
        let abs = if p.is_relative() {
            config_dir().join(p)
        } else {
            p.clone()
        };
        abs != target
    });
    if cfg.rules.rule_dirs.len() != before {
        save_config(&cfg)?;
        print_success("OK", "Configuration updated");
    }

    println!();
    print_success("SUCCESS", "Ruleset removed successfully");
    print_status(
        "LOCATION",
        &format!("Removed location: {}", target.display()),
    );

    Ok(())
}

/// List installed rulesets.
pub fn list_rulesets() -> Result<()> {
    print_colored("LIST", "Listing installed rulesets...");

    let root = config_dir().join("rules");
    if !root.exists() {
        println!();
        print_info("INFO", "No rulesets directory found");
        print_status(
            "TIP",
            "Use 'rootcause rules install <url>' to install a ruleset",
        );
        return Ok(());
    }
    let mut rows = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let manifest_path = path.join("manifest.toml");
        let mut name = entry.file_name().to_string_lossy().to_string();
        let mut author = String::new();
        let mut version = String::new();
        let mut origin = String::new();
        if manifest_path.exists() {
            if let Ok(content) = fs::read_to_string(&manifest_path) {
                if let Ok(m) = toml::from_str::<Manifest>(&content) {
                    name = m.name;
                    author = m.author.unwrap_or_default();
                    version = m.version.unwrap_or_default();
                    origin = m.origin.unwrap_or_default();
                }
            }
        }
        rows.push((name, author, version, origin, path.display().to_string()));
    }
    if rows.is_empty() {
        println!();
        print_info("INFO", "No rulesets installed");
        print_status(
            "TIP",
            "Use 'rootcause rules install <url>' to install a ruleset",
        );
        return Ok(());
    }

    println!();
    let count = rows.len();

    for (name, author, version, origin, path) in rows {
        // Display folder name as header
        if use_colored_output() {
            println!("{}", name.bright_white().bold());
        } else {
            println!("{name}");
        }

        // Display manifest fields with fallback to "Unknown"
        let display_name = if !name.is_empty() {
            name
        } else {
            "Unknown".to_string()
        };
        let display_author = if !author.is_empty() {
            author
        } else {
            "Unknown".to_string()
        };
        let display_version = if !version.is_empty() {
            version
        } else {
            "Unknown".to_string()
        };
        let display_origin = if !origin.is_empty() {
            origin
        } else {
            "Unknown".to_string()
        };

        if use_colored_output() {
            println!("  └─ Name: {}", display_name.bright_cyan());
            println!("  └─ Author: {}", display_author.bright_cyan());
            println!("  └─ Version: {}", display_version.bright_cyan());
            println!("  └─ Origin: {}", display_origin.bright_cyan());
            println!("  └─ Folder: {}", path.bright_cyan());
        } else {
            println!("  + Name: {display_name}");
            println!("  + Author: {display_author}");
            println!("  + Version: {display_version}");
            println!("  + Origin: {display_origin}");
            println!("  + Folder: {path}");
        }
        println!(); // Empty line between entries
    }
    print_success("SUCCESS", &format!("Found {count} ruleset(s)"));
    Ok(())
}
