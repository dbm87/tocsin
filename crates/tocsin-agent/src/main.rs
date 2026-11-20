//! `tocsin`: command-line entry point of the reference agent.
//!
//! This first version works on files only: it validates the formats of the
//! specification and evaluates one advisory against one component. Inventory,
//! relays and fallback sources come next (spec roadmap, step 2).

use anyhow::{Context as _, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tocsin_core::advisory::Match;
use tocsin_core::policy::Context;
use tocsin_core::{
    Action, Advisory, Declaration, Exposure, Mitigation, Policy, Purl, Signals, effective_priority,
};

#[derive(Parser)]
#[command(name = "tocsin", version, about = "Tocsin reference agent (prototype)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check that a file follows the Tocsin specification.
    Validate {
        #[command(subcommand)]
        what: Validate,
    },
    /// Evaluate one advisory against one installed component.
    Check(CheckArgs),
}

#[derive(Subcommand)]
enum Validate {
    /// A channel declaration: package.json, tocsin.json, Cargo.toml or pyproject.toml.
    Declaration { file: PathBuf },
    /// An OSV advisory, with or without the `tocsin` extension.
    Advisory { file: PathBuf },
    /// A reaction policy (policy.toml).
    Policy { file: PathBuf },
}

#[derive(Args)]
struct CheckArgs {
    /// Advisory file (OSV JSON).
    #[arg(long)]
    advisory: PathBuf,
    /// Installed component, as a purl with its version (e.g. pkg:npm/lodash@4.17.20).
    #[arg(long)]
    purl: String,
    /// Policy file; the built-in notify-only policy when absent.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// An affected service is exposed to the Internet.
    #[arg(long)]
    internet: bool,
    /// The vulnerability is in the CISA KEV catalog.
    #[arg(long)]
    kev: bool,
    /// EPSS score of the vulnerability (0.0 to 1.0).
    #[arg(long)]
    epss: Option<f64>,
    /// The component is not used by any active service.
    #[arg(long)]
    unused: bool,
    /// The advisory signature was verified (verification itself is not implemented yet).
    #[arg(long)]
    signed: bool,
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
}

fn validate(what: Validate) -> Result<()> {
    match what {
        Validate::Declaration { file } => {
            let input = read(&file)?;
            let name = file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let declaration = match name {
                "Cargo.toml" => Declaration::from_cargo_toml(&input),
                "pyproject.toml" => Declaration::from_pyproject_toml(&input),
                _ => Declaration::from_json_manifest(&input),
            }?;
            println!("valid declaration: feed {}", declaration.feed);
            if !declaration.allows_automatic_actions() {
                println!("note: no `signer`, advisories from this channel can only notify");
            }
        }
        Validate::Advisory { file } => {
            let advisory = Advisory::from_json(&read(&file)?)?;
            match advisory.tocsin() {
                Some(ext) => {
                    println!(
                        "valid advisory {} with tocsin extension (urgency {})",
                        advisory.id, ext.urgency
                    );
                    let unknown = ext
                        .mitigations
                        .iter()
                        .filter(|m| matches!(m, Mitigation::Unknown))
                        .count();
                    if unknown > 0 {
                        println!("note: {unknown} mitigation(s) of unknown type will be ignored");
                    }
                }
                None => println!("valid OSV advisory {} (no tocsin extension)", advisory.id),
            }
        }
        Validate::Policy { file } => {
            let policy = Policy::from_toml(&read(&file)?)?;
            println!("valid policy: {} rule(s)", policy.rules.len());
        }
    }
    Ok(())
}

fn check(args: CheckArgs) -> Result<()> {
    let advisory = Advisory::from_json(&read(&args.advisory)?)?;
    let component: Purl = args.purl.parse()?;
    if component.version.is_none() {
        bail!("the purl must include the installed version, e.g. {component}@1.2.3");
    }
    let policy = match &args.policy {
        Some(path) => Policy::from_toml(&read(path)?)?,
        None => Policy::default_policy(),
    };

    match advisory.matches(&component) {
        Match::NotAffected => {
            println!("{component}: not affected by {}", advisory.id);
            return Ok(());
        }
        Match::Undetermined => {
            println!(
                "{component}: matches {} but the version could not be compared",
                advisory.id
            );
            return Ok(());
        }
        Match::Affected => println!("{component}: AFFECTED by {}", advisory.id),
    }

    let Some(ext) = advisory.tocsin() else {
        println!("no tocsin extension: urgency unknown, notifying");
        return Ok(());
    };
    let signals = Signals {
        in_kev: args.kev,
        exploited: ext.exploited,
        internet_exposed: args.internet,
        network_reachable: ext.network_reachable,
        epss: args.epss,
        used_by_active_service: !args.unused,
        ..Signals::default()
    };
    let Some(priority) = effective_priority(ext.urgency, &signals) else {
        println!("declared not affected (VEX): no notification");
        return Ok(());
    };
    println!("priority: {} (publisher said {})", priority, ext.urgency);

    let ctx = Context {
        priority,
        exposure: if args.internet {
            Exposure::Internet
        } else {
            Exposure::Local
        },
        signed: args.signed,
    };
    let decision = policy.decide(&ctx, &ext.mitigations);
    let rule = decision.rule.as_deref().unwrap_or("built-in default");
    println!("decision: {:?} (rule: {rule})", decision.action);
    if let Some(reason) = decision.downgraded {
        println!("downgraded: {reason}");
    }
    if matches!(decision.action, Action::Mitigate | Action::Propose) {
        let offered = if decision.mitigations.is_empty() {
            &ext.mitigations
        } else {
            &decision.mitigations
        };
        for mitigation in offered {
            println!("  - {}", describe(mitigation));
        }
    }
    if !decision.notify.is_empty() {
        println!("notify: {}", decision.notify.join(", "));
    }
    Ok(())
}

fn describe(mitigation: &Mitigation) -> String {
    match mitigation {
        Mitigation::Upgrade { to } => format!("upgrade to {to}"),
        Mitigation::BlockHttpPath { pattern } => format!("block HTTP path {pattern}"),
        Mitigation::BlockPort { port, protocol } => {
            format!("block port {port}/{}", protocol.as_deref().unwrap_or("tcp"))
        }
        Mitigation::DisableFeature { setting, value } => format!("set {setting} = {value}"),
        Mitigation::RestrictNetwork { scope } => format!("restrict network to {scope}"),
        Mitigation::StopService { .. } => "stop the service (last resort)".into(),
        Mitigation::Unknown => "unknown mitigation type (ignored)".into(),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Validate { what } => validate(what),
        Command::Check(args) => check(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
