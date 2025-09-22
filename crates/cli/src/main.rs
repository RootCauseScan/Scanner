//! Entry point for the command-line interface.
//! Delegates to dedicated modules for argument handling,
//! scanning logic, plugin management and output formatting.

use rootcause::args::{parse_cli, Commands, RulesCmd};
use rootcause::plugins::handle_plugin;
use rootcause::rules::{inspect_rules, verify_rules};
use rootcause::rules::{install_ruleset, list_rulesets, remove_ruleset, update_ruleset};
use rootcause::scan::run_scan;

fn main() -> anyhow::Result<()> {
    let cli = parse_cli();
    match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::Plugins(cmd) => handle_plugin(cmd),
        Commands::Rules(RulesCmd::Verify { path, full }) => verify_rules(&path, full),
        Commands::Rules(RulesCmd::Inspect { target, base_dir }) => {
            inspect_rules(&target, &base_dir)
        }
        Commands::Rules(RulesCmd::Install { src, name }) => install_ruleset(&src, name.as_deref()),
        Commands::Rules(RulesCmd::Update { name }) => update_ruleset(name.as_deref()),
        Commands::Rules(RulesCmd::Remove { name }) => remove_ruleset(&name),
        Commands::Rules(RulesCmd::List) => list_rulesets(),
    }
}
