use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use debugger::{callgraph, taint, DebugToolkit, EventFormat, Format};

#[derive(Parser)]
#[command(name = "debugger")]
#[command(about = "Debugging tool for IR and rules", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Clone, Default)]
struct TimelineOpts {
    #[arg(
        long,
        value_enum,
        help = "Show the engine timeline in the selected format",
        value_name = "FORMAT"
    )]
    timeline: Option<EventFormat>,
    #[arg(long, help = "Show a compact per-stage summary of collected events")]
    timeline_summary: bool,
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
        /// Simplified output for presentations
        #[arg(long)]
        simplified: bool,
        #[command(flatten)]
        timeline: TimelineOpts,
    },
    /// Shows a compiled rule from a file
    Rule {
        /// Path to the rule file
        file: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        #[command(flatten)]
        timeline: TimelineOpts,
    },
    /// Taint analysis - inspects the engine taint model for a file
    Taint {
        /// Path to the file to process
        file: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Show detailed taint flow
        #[arg(long)]
        detailed: bool,
        #[command(flatten)]
        timeline: TimelineOpts,
    },
    /// Call graph analysis derived from the IR
    Callgraph {
        /// Path to the file or directory to process
        path: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Show only direct calls
        #[arg(long)]
        direct_only: bool,
        #[command(flatten)]
        timeline: TimelineOpts,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Kind {
    Ast,
    Cfg,
    Ssa,
    Callgraph,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let toolkit = DebugToolkit::new();

    match cli.command {
        Commands::Ir {
            file,
            format,
            kind,
            simplified,
            timeline,
        } => run_ir(&toolkit, file, format, kind, simplified, &timeline)?,
        Commands::Rule {
            file,
            format,
            timeline,
        } => run_rule(&toolkit, file, format, &timeline)?,
        Commands::Taint {
            file,
            format,
            detailed,
            timeline,
        } => run_taint(&toolkit, file, format, detailed, &timeline)?,
        Commands::Callgraph {
            path,
            format,
            direct_only,
            timeline,
        } => run_callgraph(&toolkit, path, format, direct_only, &timeline)?,
    }
    Ok(())
}

fn run_ir(
    toolkit: &DebugToolkit,
    file: PathBuf,
    format: Format,
    kind: Kind,
    simplified: bool,
    timeline: &TimelineOpts,
) -> Result<()> {
    toolkit.reset();
    let inspection = toolkit.inspect_file(&file)?;
    let rendered = match kind {
        Kind::Ast => inspection.format_ast(format, simplified)?,
        Kind::Cfg => inspection.format_cfg(format)?,
        Kind::Ssa => inspection.format_dfg(format)?,
        Kind::Callgraph => {
            let fir = inspection.borrow();
            let analysis = callgraph::analyze_callgraph(&[fir.clone()], false)?;
            callgraph::format_callgraph_analysis(&analysis, format)
        }
    };
    println!("{}", rendered);
    emit_timeline(toolkit, timeline);
    Ok(())
}

fn run_rule(
    toolkit: &DebugToolkit,
    file: PathBuf,
    format: Format,
    timeline: &TimelineOpts,
) -> Result<()> {
    toolkit.reset();
    let inspection = toolkit.inspect_rules(&file)?;
    let rendered = inspection.render(format)?;
    println!("{}", rendered);
    emit_timeline(toolkit, timeline);
    Ok(())
}

fn run_taint(
    toolkit: &DebugToolkit,
    file: PathBuf,
    format: Format,
    detailed: bool,
    timeline: &TimelineOpts,
) -> Result<()> {
    toolkit.reset();
    let inspection = toolkit.inspect_file(&file)?;
    let fir = inspection.borrow();
    let analysis = taint::analyze_taint(&fir, detailed)?;
    drop(fir);
    let rendered = taint::format_taint_analysis(&analysis, format);
    println!("{}", rendered);
    emit_timeline(toolkit, timeline);
    Ok(())
}

fn run_callgraph(
    toolkit: &DebugToolkit,
    path: PathBuf,
    format: Format,
    direct_only: bool,
    timeline: &TimelineOpts,
) -> Result<()> {
    toolkit.reset();
    let mut files = Vec::new();

    if path.is_file() {
        if let Some(fir) = toolkit.parse_raw(&path)? {
            files.push(fir);
        }
    } else if path.is_dir() {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let file_path = entry.path();
            if file_path.is_file() {
                if let Some(fir) = toolkit.parse_raw(&file_path)? {
                    files.push(fir);
                }
            }
        }
    } else {
        return Err(anyhow!("path does not exist: {}", path.display()));
    }

    if files.is_empty() {
        return Err(anyhow!("no supported files found"));
    }

    let analysis = callgraph::analyze_callgraph(&files, direct_only)?;
    let rendered = callgraph::format_callgraph_analysis(&analysis, format);
    println!("{}", rendered);
    emit_timeline(toolkit, timeline);
    Ok(())
}

fn emit_timeline(toolkit: &DebugToolkit, opts: &TimelineOpts) {
    if opts.timeline.is_none() && !opts.timeline_summary {
        return;
    }

    let timeline = toolkit.timeline();
    if timeline.events.is_empty() {
        println!();
        println!("(no engine events were captured for this run)");
        return;
    }

    println!();
    if let Some(format) = opts.timeline {
        println!("=== Pipeline Timeline ===");
        match format {
            EventFormat::Text => print!("{}", timeline.to_text()),
            EventFormat::Json => println!("{}", timeline.to_json_string()),
            EventFormat::Mermaid => println!("{}", timeline.to_mermaid()),
        }
    }

    if opts.timeline_summary {
        println!("=== Pipeline Summary ===");
        for summary in timeline.stage_summary() {
            println!("- {}: {}", summary.stage, summary.count);
        }
    }
}
