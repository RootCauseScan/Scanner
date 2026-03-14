//! Entry point for the command-line interface.
//! Delegates to dedicated modules for argument handling,
//! scanning logic, plugin management and output formatting.

use rootcause::args::{parse_cli, Commands, RulesCmd};
use rootcause::error_log::append_error_log;
use rootcause::plugins::handle_plugin;
use rootcause::rules::{inspect_rules, verify_rules};
use rootcause::rules::{install_ruleset, list_rulesets, remove_ruleset, update_ruleset};
use rootcause::scan::run_scan;
use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;
use std::process::ExitCode;

fn panic_payload_to_string(info: &PanicHookInfo<'_>) -> String {
    if let Some(msg) = info.payload().downcast_ref::<&str>() {
        (*msg).to_string()
    } else if let Some(msg) = info.payload().downcast_ref::<String>() {
        msg.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let message = panic_payload_to_string(info);
        let thread = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string();
        let backtrace = Backtrace::force_capture();
        append_error_log(
            "panic",
            &format!(
                "thread={thread}\nlocation={location}\nmessage={message}\nbacktrace:\n{backtrace}"
            ),
        );
        previous(info);
    }));
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = parse_cli();
    match cli.command {
        Commands::Scan(args) => Ok(ExitCode::from(run_scan(args)?.exit_code() as u8)),
        Commands::Plugins(cmd) => {
            handle_plugin(cmd)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Rules(RulesCmd::Verify { path, full }) => {
            verify_rules(&path, full)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Rules(RulesCmd::Inspect { target, base_dir }) => {
            inspect_rules(&target, &base_dir)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Rules(RulesCmd::Install { src, name }) => {
            install_ruleset(&src, name.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Rules(RulesCmd::Update { name }) => {
            update_ruleset(name.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Rules(RulesCmd::Remove { name }) => {
            remove_ruleset(&name)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Rules(RulesCmd::List) => {
            list_rulesets()?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn main() -> ExitCode {
    install_panic_hook();

    match run() {
        Ok(code) => code,
        Err(err) => {
            let backtrace = Backtrace::force_capture();
            append_error_log("error", &format!("error={err:?}\nbacktrace:\n{backtrace}"));
            eprintln!("Error: {err:?}");
            ExitCode::FAILURE
        }
    }
}
