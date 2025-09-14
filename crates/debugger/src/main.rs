use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use debugger::{EventFormat, FormatterSink};
use engine::{build_cfg, load_rules_with_events, parse_file_with_events, set_debug_sink};
use parsers::build_dfg;

#[derive(Parser)]
#[command(name = "debugger")]
#[command(about = "Debugging tool for IR and rules", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Shows the intermediate representation of a file
    Ir {
        /// Path to the file to process
        file: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Representation to export
        #[arg(long, value_enum, default_value_t = Kind::Ast)]
        kind: Kind,
    },
    /// Shows a compiled rule from a file
    Rule {
        /// Path to the rule file
        file: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Dot,
    Mermaid,
}

#[derive(Copy, Clone, ValueEnum)]
enum Kind {
    Ast,
    Cfg,
    Ssa,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Ir { file, format, kind } => {
            let sink = FormatterSink::new(match format {
                Format::Json => EventFormat::Json,
                _ => EventFormat::Text,
            });
            set_debug_sink(Some(Box::new(sink.clone())));
            show_ir(file, format, kind)?;
            println!("{}", sink.output());
            set_debug_sink(None);
        }
        Commands::Rule { file, format } => {
            let sink = FormatterSink::new(match format {
                Format::Json => EventFormat::Json,
                _ => EventFormat::Text,
            });
            set_debug_sink(Some(Box::new(sink.clone())));
            show_rule(file, format)?;
            println!("{}", sink.output());
            set_debug_sink(None);
        }
    }
    Ok(())
}

fn show_ir(path: PathBuf, format: Format, kind: Kind) -> Result<()> {
    let mut fir = parse_file_with_events(&path, None, None)?
        .ok_or_else(|| anyhow!("unsupported file type"))?;
    match kind {
        Kind::Ast => {
            let ast = fir
                .ast
                .as_ref()
                .ok_or_else(|| anyhow!("AST not available"))?;
            match format {
                Format::Text => println!("{ast:#?}"),
                Format::Json => println!("{}", ast.to_json()?),
                Format::Dot => println!("{}", ast.to_dot()),
                Format::Mermaid => println!("{}", ast.to_mermaid()),
            }
        }
        Kind::Cfg => {
            let cfg = build_cfg(&fir).ok_or_else(|| anyhow!("CFG not available"))?;
            match format {
                Format::Text => println!("{cfg:#?}"),
                Format::Json => println!("{}", cfg.to_json()?),
                Format::Dot => println!("{}", cfg.to_dot()),
                Format::Mermaid => println!("{}", cfg.to_mermaid()),
            }
        }
        Kind::Ssa => {
            build_dfg(&mut fir)?;
            let dfg = fir
                .dfg
                .as_ref()
                .ok_or_else(|| anyhow!("DFG not available"))?;
            match format {
                Format::Text => println!("{dfg:#?}"),
                Format::Json => println!("{}", dfg.to_json()?),
                Format::Dot => println!("{}", dfg.to_dot()),
                Format::Mermaid => println!("{}", dfg.to_mermaid()),
            }
        }
    }
    Ok(())
}

fn show_rule(path: PathBuf, format: Format) -> Result<()> {
    let rs = load_rules_with_events(&path)?;
    let rule = rs.rules.first().ok_or_else(|| anyhow!("no rule found"))?;
    match format {
        Format::Text => {
            println!("{rule:#?}");
        }
        Format::Json => {
            let json = serde_json::json!({
                "id": rule.id,
                "severity": rule.severity,
                "category": rule.category,
                "message": rule.message,
                "remediation": rule.remediation,
                "interfile": rule.interfile,
                "matcher": format!("{matcher:?}", matcher = rule.matcher),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        Format::Dot => {
            println!("digraph Rule {{ label=\"{}\" }}", rule.id);
        }
        Format::Mermaid => {
            println!("graph TD\n    rule[\"{}\"]", rule.id);
        }
    }
    Ok(())
}
