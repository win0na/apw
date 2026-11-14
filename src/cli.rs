use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands;
use crate::config::{Config, Paths};
use crate::error::Result;

#[derive(Debug, Parser)]
#[command(
    name = "apw",
    version,
    about = "Read Apple Passwords on Linux",
    long_about = "Read logins and one-time codes from Apple Passwords. The vault is a local \
                  encrypted snapshot; query commands never touch the network."
)]
pub struct Cli {
    /// Print the JSON envelope instead of a table.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign in to iCloud and write the first snapshot.
    Login {
        /// Anisette server base URL.
        #[arg(long)]
        anisette_url: Option<String>,
        /// Apple ID to sign in with.
        #[arg(long)]
        account: Option<String>,
    },
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
    /// Read logins.
    Pw {
        #[command(subcommand)]
        command: PwCommand,
    },
    /// Read one-time codes.
    Otp {
        #[command(subcommand)]
        command: OtpCommand,
    },
    /// Install the systemd user service and timer.
    InstallUnits,
}

#[derive(Debug, Subcommand)]
pub enum PwCommand {
    /// List logins, optionally filtered by a domain, title, or username.
    List { query: Option<String> },
    /// Print the password for a domain, title, or username.
    Get {
        query: String,
        #[arg(long)]
        username: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum OtpCommand {
    /// List one-time codes, optionally filtered.
    List { query: Option<String> },
    /// Print the current one-time code.
    Get { query: String },
}

pub fn run() -> i32 {
    let cli = Cli::parse();
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
    let mut config = Config::load(&paths)?;

    match cli.command {
        Command::Login {
            anisette_url,
            account,
        } => commands::login::run(&paths, &mut config, anisette_url, account, cli.json),
        Command::Sync { force, fixture } => {
            commands::sync::run(&paths, &mut config, force, fixture, cli.json)
        }
        Command::Status => commands::status::run(&paths, &config, cli.json),
        Command::Pw { command } => match command {
            PwCommand::List { query } => {
                commands::pw::list(&paths, &mut config, query.as_deref(), cli.json)
            }
            PwCommand::Get { query, username } => {
                commands::pw::get(&paths, &mut config, &query, username.as_deref(), cli.json)
            }
        },
        Command::Otp { command } => match command {
            OtpCommand::List { query } => {
                commands::otp::list(&paths, &mut config, query.as_deref(), cli.json)
            }
            OtpCommand::Get { query } => commands::otp::get(&paths, &mut config, &query, cli.json),
        },
        Command::InstallUnits => commands::units::run(&paths, &config, cli.json),
    }
}
