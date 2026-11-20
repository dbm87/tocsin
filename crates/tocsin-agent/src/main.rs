//! `tocsin`: command-line entry point of the reference agent.
//!
//! It validates the formats of the specification, inventories a Linux machine
//! and evaluates one advisory against one component. Relays and fallback
//! sources come next (spec roadmap, step 2).

use anyhow::{Context as _, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::{BTreeMap, HashMap};
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
    /// Inventory this Linux machine: components, services, listening ports.
    Inventory(InventoryArgs),
}

#[derive(Args)]
struct InventoryArgs {
    /// Project directory whose lockfiles are read (repeatable).
    #[arg(long = "project", value_name = "DIR")]
    projects: Vec<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Summary)]
    format: Format,
    /// In the summary, also list services with no listening port.
    #[arg(long)]
    all: bool,
    #[arg(long, default_value = "/", hide = true)]
    fs_root: PathBuf,
    #[arg(long, default_value = "/proc", hide = true)]
    proc_root: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Summary,
    Json,
    Cyclonedx,
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

fn inventory(args: InventoryArgs) -> Result<()> {
    let options = tocsin_inventory::Options {
        fs_root: args.fs_root,
        proc_root: args.proc_root,
        projects: args.projects,
        rpm: true,
    };
    let inventory = tocsin_inventory::collect(&options);
    match args.format {
        Format::Json => println!("{}", serde_json::to_string_pretty(&inventory)?),
        Format::Cyclonedx => println!(
            "{}",
            serde_json::to_string_pretty(&tocsin_inventory::cyclonedx::to_cyclonedx(&inventory))?
        ),
        Format::Summary => print_summary(&inventory, args.all),
    }
    Ok(())
}

fn exposure_label(exposure: tocsin_inventory::Exposure) -> &'static str {
    match exposure {
        tocsin_inventory::Exposure::Loopback => "loopback only",
        tocsin_inventory::Exposure::Lan => "local network",
        tocsin_inventory::Exposure::AllInterfaces => "ALL INTERFACES",
        tocsin_inventory::Exposure::Public => "PUBLIC ADDRESS",
    }
}

fn print_summary(inventory: &tocsin_inventory::model::Inventory, all: bool) {
    use tocsin_inventory::model::ServiceKind;

    let host = &inventory.host;
    println!(
        "host: {} ({} {})",
        host.hostname.as_deref().unwrap_or("?"),
        host.os_id.as_deref().unwrap_or("?"),
        host.os_version.as_deref().unwrap_or("")
    );

    let mut by_origin: BTreeMap<&str, usize> = BTreeMap::new();
    for component in &inventory.components {
        *by_origin.entry(component.origin.label()).or_default() += 1;
    }
    let origins: Vec<String> = by_origin
        .iter()
        .map(|(origin, n)| format!("{origin} {n}"))
        .collect();
    let declared = inventory
        .components
        .iter()
        .filter(|c| c.declaration.is_some())
        .count();
    println!(
        "components: {} ({}), {declared} with a declared Tocsin channel",
        inventory.components.len(),
        origins.join(", ")
    );

    let names: HashMap<&str, &str> = inventory
        .components
        .iter()
        .map(|c| (c.purl.as_str(), c.name.as_str()))
        .collect();
    let mut shown: Vec<_> = inventory
        .services
        .iter()
        .filter(|s| all || !s.listening.is_empty() || s.needs_restart())
        .collect();
    shown.sort_by(|a, b| b.exposure().cmp(&a.exposure()).then(a.name.cmp(&b.name)));
    println!(
        "services: {} ({} shown{})",
        inventory.services.len(),
        shown.len(),
        if all {
            ""
        } else {
            ": listening or needing a restart; --all for every service"
        }
    );

    for service in shown {
        let kind = match service.kind {
            ServiceKind::SystemdUnit => "systemd",
            ServiceKind::Container => "container",
            ServiceKind::Process => "process",
        };
        let partial = if service.partial {
            " (partial: run as root)"
        } else {
            ""
        };
        println!("\n{} [{kind}]{partial}", service.name);
        // Most exposed first, TCP before UDP; the full list is in --format json.
        let mut listeners: Vec<_> = service.listening.iter().collect();
        listeners.sort_by(|a, b| {
            b.exposure
                .cmp(&a.exposure)
                .then(a.protocol.cmp(b.protocol))
                .then(a.port.cmp(&b.port))
        });
        const SHOWN_LISTENERS: usize = 5;
        for listener in listeners.iter().take(SHOWN_LISTENERS) {
            let address = if listener.address.contains(':') {
                format!("[{}]", listener.address)
            } else {
                listener.address.clone()
            };
            println!(
                "  listens {}/{address}:{} ({})",
                listener.protocol,
                listener.port,
                exposure_label(listener.exposure)
            );
        }
        if listeners.len() > SHOWN_LISTENERS {
            println!(
                "  … and {} more socket(s), see --format json",
                listeners.len() - SHOWN_LISTENERS
            );
        }
        if service.separate_filesystem {
            println!(
                "  own filesystem (container, Flatpak, Snap): its content is not inventoried yet"
            );
        }
        if !service.uses.is_empty() {
            let mut used: Vec<&str> = service
                .uses
                .iter()
                .map(|u| names.get(u.purl.as_str()).copied().unwrap_or(&u.purl))
                .collect();
            used.dedup();
            let more = used.len().saturating_sub(8);
            let listed = used.iter().take(8).copied().collect::<Vec<_>>().join(", ");
            let more = if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            };
            println!("  uses {} component(s): {listed}{more}", used.len());
        }
        let replaced: Vec<&str> = service
            .uses
            .iter()
            .filter(|u| u.evidence.replaced_on_disk())
            .map(|u| names.get(u.purl.as_str()).copied().unwrap_or(&u.purl))
            .collect();
        if !replaced.is_empty() {
            println!(
                "  RESTART NEEDED: still running replaced files of {}",
                replaced.join(", ")
            );
        }
    }

    if !inventory.warnings.is_empty() {
        println!();
        for warning in &inventory.warnings {
            println!("warning: {warning}");
        }
    }
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
        Command::Inventory(args) => inventory(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
