use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands;
use crate::config::{Config, Paths};
use crate::error::Result;
use crate::output::Style;

#[derive(Debug, Parser)]
#[command(
    name = "apw",
    version,
    about = "Read Apple Passwords on Linux",
    long_about = "Read logins, one-time codes, and Wi-Fi networks from Apple Passwords. \
                  The vault is a local encrypted snapshot; query commands never touch the network."
)]
pub struct Cli {
    /// Print JSON instead of a table. JSON is also used when stdout is a pipe.
    #[arg(long, global = true)]
    pub json: bool,
    /// Do not truncate tables to the terminal width.
    #[arg(long, global = true)]
    pub wide: bool,
    /// Omit table headers.
    #[arg(long, global = true)]
    pub no_header: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign in to iCloud, join the trust, and write the first snapshot.
    Login {
        /// Anisette server base URL.
        #[arg(long)]
        anisette_url: Option<String>,
        /// Apple ID to sign in with.
        #[arg(long)]
        account: Option<String>,
        /// Refresh service URLs from the stored session without signing in again.
        #[arg(long)]
        refresh: bool,
        /// Join the trust in the same run, even when a peer already exists.
        #[arg(long)]
        join: bool,
        /// Do not join the trust after signing in.
        #[arg(long)]
        no_join: bool,
    },
    /// Join the Octagon trust with the escrow passcode.
    Join,
    /// Refresh the snapshot.
    Sync {
        /// Ignore the sync interval.
        #[arg(long)]
        force: bool,
        /// Read a fixture instead of iCloud.
        #[arg(long)]
        fixture: Option<PathBuf>,
    },
    /// Show the account, snapshot age, and entry counts.
    Status,
    /// List logins.
    List {
        /// Filter by name, domain, or username.
        query: Option<String>,
        /// Only entries that are not in a shared group.
        #[arg(long)]
        personal: bool,
        /// Only entries from one group.
        #[arg(long)]
        group: Option<String>,
    },
    /// Print a login or Wi-Fi network.
    Get {
        /// Name, domain, or username.
        query: String,
        /// Only entries with this username.
        #[arg(long)]
        username: Option<String>,
        /// Only entries from one group.
        #[arg(long)]
        group: Option<String>,
        /// Only entries that are not in a shared group.
        #[arg(long)]
        personal: bool,
        /// Print only the password, one per match.
        #[arg(long)]
        password_only: bool,
    },
    /// List Wi-Fi networks.
    Wifi {
        /// Filter by network name.
        query: Option<String>,
    },
    /// List one-time codes, or print the code for a query.
    Otp {
        /// Name, domain, or username. When given, prints just the code.
        query: Option<String>,
    },
    /// Install the systemd user service and timer.
    InstallUnits,
    /// Probe escrow authentication without spending an attempt.
    #[command(hide = true)]
    ProbeEscrow,
    /// Probe the account service map.
    #[command(hide = true)]
    ProbeSettings,
    /// Probe one CloudKit zone.
    #[command(hide = true)]
    ProbeZone { zone: String },
    /// Probe recoverable TLK share function names.
    #[command(hide = true)]
    ProbeTlks,
    /// Re-fetch the service map and CloudKit token.
    #[command(hide = true)]
    ProbeRefresh,
    /// List private and shared CloudKit zones.
    #[command(hide = true)]
    ProbeZones,
    /// Inspect one group zone.
    #[command(hide = true)]
    ProbeGroup { zone: String },
    /// Count snapshot records by kind.
    #[command(hide = true)]
    ProbeStats,
}

pub fn run() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            use clap::error::ErrorKind;
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return 0;
            }
            if std::env::args().any(|arg| arg == "--json") {
                crate::output::print_json_err(&crate::output::failure(
                    &crate::error::Error::Invalid(error.to_string()),
                ));
            } else {
                let _ = error.print();
            }
            return 2;
        }
    };
    match execute(cli) {
        Ok(()) => 0,
        Err(error) => {
            crate::output::print_json_err(&crate::output::failure(&error));
            error.status()
        }
    }
}

fn execute(cli: Cli) -> Result<()> {
    let paths = Paths::resolve()?;
    // Commands that load the snapshot, talk to the network and save it hold a
    // cross-process lock, so the timer and a manual run serialize. `login` and
    // `join` take it here and must not take it again internally.
    let _snapshot_lock = if matches!(
        &cli.command,
        Command::Login { .. }
            | Command::Join
            | Command::Sync { .. }
            | Command::ProbeEscrow
            | Command::ProbeSettings
            | Command::ProbeZone { .. }
            | Command::ProbeTlks
            | Command::ProbeRefresh
            | Command::ProbeZones
            | Command::ProbeGroup { .. }
            | Command::ProbeStats
    ) {
        Some(crate::config::lock_snapshot(&paths)?)
    } else {
        None
    };
    let mut config = Config::load(&paths)?;
    let table_command = matches!(
        &cli.command,
        Command::List { .. } | Command::Get { .. } | Command::Wifi { .. } | Command::Otp { .. }
    );
    let mut style = Style::new(cli.json, cli.wide, cli.no_header);
    if table_command && !style.explicit_json && (cli.wide || cli.no_header) {
        style.json = false;
    }
    let otp_query = matches!(&cli.command, Command::Otp { query: Some(_) });

    match cli.command {
        Command::Login {
            anisette_url,
            account,
            refresh,
            join,
            no_join,
        } => commands::login::run(
            &paths,
            &mut config,
            anisette_url,
            account,
            refresh,
            join,
            no_join,
            style.json,
        ),
        Command::Join => commands::join::run(&paths, &mut config, style.json),
        Command::Sync { force, fixture } => {
            commands::sync::run(&paths, &mut config, force, fixture, style.json)
        }
        Command::Status => commands::status::run(&paths, &config, style),
        Command::List {
            query,
            personal,
            group,
        } => commands::pw::list(
            &paths,
            &mut config,
            query.as_deref(),
            personal,
            group.as_deref(),
            style,
        ),
        Command::Get {
            query,
            username,
            group,
            personal,
            password_only,
        } => {
            let mut style = style;
            // `--password-only` is for scripts: keep it text even through a pipe.
            if password_only && !style.explicit_json {
                style.json = false;
            }
            commands::pw::get(
                &paths,
                &mut config,
                &query,
                username.as_deref(),
                group.as_deref(),
                personal,
                password_only,
                style,
            )
        }
        Command::Wifi { query } => commands::pw::wifi(&paths, &mut config, query.as_deref(), style),
        Command::Otp { query } => {
            let mut style = style;
            // `$(apw otp x)` must be a code, not JSON.
            if otp_query && !style.explicit_json {
                style.json = false;
            }
            commands::otp::run(&paths, &mut config, query.as_deref(), style)
        }
        Command::InstallUnits => commands::units::run(&paths, &config, style.json),
        Command::ProbeEscrow => commands::probe::escrow(&paths, &mut config, style.json),
        Command::ProbeSettings => commands::probe::settings(&paths, &mut config, style.json),
        Command::ProbeZone { zone } => {
            commands::probe::zone(&paths, &mut config, &zone, style.json)
        }
        Command::ProbeTlks => commands::probe::tlks(&paths, &mut config, style.json),
        Command::ProbeRefresh => commands::probe::refresh(&paths, &mut config, style.json),
        Command::ProbeZones => commands::probe::zones(&paths, &mut config, style.json),
        Command::ProbeGroup { zone } => {
            commands::probe::group(&paths, &mut config, &zone, style.json)
        }
        Command::ProbeStats => commands::probe::stats(&paths, &mut config, style.json),
    }
}
