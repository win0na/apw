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
    /// List notes.
    Notes {
        /// Filter by name or body.
        query: Option<String>,
    },
    /// List one-time codes, or print the code for a query.
    Otp {
        /// Name, domain, or username. When given, prints just the code.
        query: Option<String>,
    },
    /// Add a new item to the local snapshot.
    Add {
        #[command(subcommand)]
        item: AddItem,
    },
    /// Import passkeys from a CXF export.
    Passkey {
        #[command(subcommand)]
        action: PasskeyAction,
    },
    /// Edit a login in the local snapshot.
    ///
    /// Pass a query, or select the entry with `--id`:
    /// `apw edit --id <uuid> --title x`.
    /// A stored site or username cannot be changed here; delete the entry and
    /// add it again instead.
    Edit {
        /// Name, domain, or username. Optional when --id is given.
        query: Option<String>,
        /// Select the entry by record id.
        #[arg(long)]
        id: Option<String>,
        /// Set the name. An empty value clears it.
        #[arg(long)]
        title: Option<String>,
        /// Set the notes.
        #[arg(long)]
        notes: Option<String>,
        /// Remove the notes.
        #[arg(long)]
        clear_notes: bool,
        /// Set the one-time-code secret from an otpauth URI or bare base32.
        #[arg(long)]
        totp: Option<String>,
        /// Remove the one-time code.
        #[arg(long)]
        clear_totp: bool,
        /// Read the new password from the first line of stdin.
        #[arg(long)]
        password_stdin: bool,
        /// Replace the password with a generated one.
        #[arg(long)]
        generate: bool,
        /// Show what would change without saving.
        #[arg(long)]
        dry_run: bool,
    },
    /// Move a login to Recently Deleted.
    ///
    /// Pass a query, or select the entry with `--id`:
    /// `apw rm --id <uuid> --yes`. The entry can be restored on any device for
    /// 30 days.
    Rm {
        /// Name, domain, or username. Optional when --id is given.
        query: Option<String>,
        /// Select the entry by record id.
        #[arg(long)]
        id: Option<String>,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
        /// Show what would change without saving.
        #[arg(long)]
        dry_run: bool,
    },
    /// List items in Recently Deleted.
    ///
    /// The trash is filled by `apw sync`. An item deleted with `apw rm` appears
    /// here once the delete has been pushed.
    Trash {
        /// Filter by name, domain, or username.
        query: Option<String>,
    },
    /// Restore an item from Recently Deleted.
    ///
    /// Undoes a move to Recently Deleted. Works only for a record that is still
    /// in the trash and was synced into the vault, or for a delete that has not
    /// been pushed yet.
    Restore {
        /// Name, domain, or username. Optional when --id is given.
        query: Option<String>,
        /// Select the item by record id.
        #[arg(long)]
        id: Option<String>,
        /// Show what would be restored without saving.
        #[arg(long)]
        dry_run: bool,
    },
    /// List changes that have not been pushed yet.
    Pending,
    /// Keep or drop a pending change.
    Resolve {
        /// Pending op id, as shown by `apw pending`.
        id: String,
        /// Keep the op and try it again even if it was blocked.
        #[arg(long)]
        local: bool,
        /// Drop the op without pushing it.
        #[arg(long)]
        remote: bool,
    },
    /// List password groups and add or remove their items.
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Install the systemd user service and timer.
    InstallUnits,
    /// Probe escrow authentication without spending an attempt.
    #[command(hide = true)]
    ProbeEscrow,
    /// Probe the account service map.
    #[command(hide = true)]
    ProbeSettings,
    /// Print a zone's PCS protection sizes.
    #[command(hide = true)]
    ProbeZoneInfo { zone: String },
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
    /// Print one CloudKit record's fields.
    #[command(hide = true)]
    ProbeRecord { zone: String, name: String },
    /// Print the redacted key structure of stored item plists.
    #[command(hide = true)]
    ProbeStructure {
        /// Limit to one kind: login, note, wifi, passkey.
        kind: Option<String>,
        /// How many entries to print (default 3).
        #[arg(long, default_value_t = 3)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
pub enum GroupAction {
    /// List the groups this account owns.
    List,
    /// Show one group and the items in it.
    Show {
        /// Group name, zone, or UUID.
        group: String,
    },
    /// Add one personal login to a group.
    Add {
        /// Group name, zone, or UUID.
        group: String,
        /// Name, domain, or username of the login to add.
        query: Option<String>,
        /// Select the entry by record id.
        #[arg(long)]
        id: Option<String>,
        /// Show what would be added without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove one shared item from a group.
    Remove {
        /// Group name, zone, or UUID.
        group: String,
        /// Item record name, or an entry id or query from the last sync.
        item: String,
        /// Confirm the permanent deletion.
        #[arg(long)]
        yes: bool,
        /// Show what would be removed without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum AddItem {
    /// Add a login.
    Login {
        /// Site host or URL.
        url: String,
        /// Account username.
        #[arg(long)]
        username: Option<String>,
        /// Name shown in `apw list`.
        #[arg(long)]
        title: Option<String>,
        /// Notes for the entry.
        #[arg(long)]
        notes: Option<String>,
        /// Set the one-time-code secret from an otpauth URI or bare base32.
        #[arg(long)]
        totp: Option<String>,
        /// Read the password from the first line of stdin.
        #[arg(long)]
        password_stdin: bool,
        /// Generate a 20-character password.
        #[arg(long)]
        generate: bool,
        /// Show what would be added without saving.
        #[arg(long)]
        dry_run: bool,
    },
    /// Add a Wi-Fi network.
    Wifi {
        /// Network name (SSID).
        ssid: String,
        /// Read the password from the first line of stdin.
        #[arg(long)]
        password_stdin: bool,
        /// Generate a 20-character password.
        #[arg(long)]
        generate: bool,
        /// Show what would be added without saving.
        #[arg(long)]
        dry_run: bool,
    },
    /// Add a note.
    Note {
        /// Note title.
        title: String,
        /// Note body.
        #[arg(long)]
        body: Option<String>,
        /// Read the body from stdin.
        #[arg(long)]
        body_stdin: bool,
        /// Show what would be added without saving.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum PasskeyAction {
    /// Import passkeys from a CXF export.
    Import {
        /// CXF 1.0 JSON export.
        file: PathBuf,
        /// Show what would be imported without saving.
        #[arg(long)]
        dry_run: bool,
    },
    /// Export passkeys to a CXF file.
    Export {
        /// CXF 1.0 JSON file to write.
        file: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
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
            | Command::Add { .. }
            | Command::Edit { .. }
            | Command::Rm { .. }
            | Command::Restore { .. }
            | Command::Resolve { .. }
            | Command::Group { .. }
            | Command::Passkey { .. }
            | Command::ProbeEscrow
            | Command::ProbeSettings
            | Command::ProbeZoneInfo { .. }
            | Command::ProbeRefresh
            | Command::ProbeZones
            | Command::ProbeGroup { .. }
            | Command::ProbeStats
            | Command::ProbeStructure { .. }
    ) {
        Some(crate::config::lock_snapshot(&paths)?)
    } else {
        None
    };
    let mut config = Config::load(&paths)?;
    let table_command = matches!(
        &cli.command,
        Command::List { .. }
            | Command::Get { .. }
            | Command::Wifi { .. }
            | Command::Notes { .. }
            | Command::Otp { .. }
            | Command::Trash { .. }
            | Command::Pending
            | Command::Group {
                action: GroupAction::List | GroupAction::Show { .. },
            }
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
        Command::Notes { query } => {
            commands::pw::notes(&paths, &mut config, query.as_deref(), style)
        }
        Command::Otp { query } => {
            let mut style = style;
            // `$(apw otp x)` must be a code, not JSON.
            if otp_query && !style.explicit_json {
                style.json = false;
            }
            commands::otp::run(&paths, &mut config, query.as_deref(), style)
        }
        Command::InstallUnits => commands::units::run(&paths, &config, style.json),
        Command::Add { item } => match item {
            AddItem::Login {
                url,
                username,
                title,
                notes,
                totp,
                password_stdin,
                generate,
                dry_run,
            } => commands::write::add_login(
                &paths,
                &mut config,
                &url,
                username.as_deref(),
                title.as_deref(),
                notes.as_deref(),
                totp.as_deref(),
                password_stdin,
                generate,
                dry_run,
                style,
            ),
            AddItem::Wifi {
                ssid,
                password_stdin,
                generate,
                dry_run,
            } => commands::write::add_wifi(
                &paths,
                &mut config,
                &ssid,
                password_stdin,
                generate,
                dry_run,
                style,
            ),
            AddItem::Note {
                title,
                body,
                body_stdin,
                dry_run,
            } => commands::write::add_note(
                &paths,
                &mut config,
                &title,
                body.as_deref(),
                body_stdin,
                dry_run,
                style,
            ),
        },
        Command::Passkey { action } => match action {
            PasskeyAction::Import { file, dry_run } => {
                commands::passkey::import(&paths, &mut config, &file, dry_run, style)
            }
            PasskeyAction::Export { file, force } => {
                commands::passkey::export(&paths, &mut config, &file, force, style)
            }
        },
        Command::Edit {
            query,
            id,
            title,
            notes,
            clear_notes,
            totp,
            clear_totp,
            password_stdin,
            generate,
            dry_run,
        } => commands::write::edit(
            &paths,
            &mut config,
            query.as_deref(),
            id.as_deref(),
            title.as_deref(),
            notes.as_deref(),
            clear_notes,
            password_stdin,
            generate,
            totp.as_deref(),
            clear_totp,
            dry_run,
            style,
        ),
        Command::Rm {
            query,
            id,
            yes,
            dry_run,
        } => commands::write::rm(
            &paths,
            &mut config,
            query.as_deref(),
            id.as_deref(),
            yes,
            dry_run,
            style,
        ),
        Command::Pending => commands::write::pending(&paths, &mut config, style),
        Command::Trash { query } => {
            commands::write::trash_list(&paths, &mut config, query.as_deref(), style)
        }
        Command::Restore { query, id, dry_run } => commands::write::restore(
            &paths,
            &mut config,
            query.as_deref(),
            id.as_deref(),
            dry_run,
            style,
        ),
        Command::Resolve { id, local, remote } => {
            commands::write::resolve(&paths, &mut config, &id, local, remote, style)
        }
        Command::Group { action } => match action {
            GroupAction::List => commands::group::list(&paths, &mut config, style),
            GroupAction::Show { group } => {
                commands::group::show(&paths, &mut config, &group, style)
            }
            GroupAction::Add {
                group,
                query,
                id,
                dry_run,
            } => commands::group::add(
                &paths,
                &mut config,
                &group,
                query.as_deref(),
                id.as_deref(),
                dry_run,
                style,
            ),
            GroupAction::Remove {
                group,
                item,
                yes,
                dry_run,
            } => commands::group::remove(&paths, &mut config, &group, &item, yes, dry_run, style),
        },
        Command::ProbeEscrow => commands::probe::escrow(&paths, &mut config, style.json),
        Command::ProbeSettings => commands::probe::settings(&paths, &mut config, style.json),
        Command::ProbeZoneInfo { zone } => {
            commands::probe::zoneinfo(&paths, &mut config, &zone, style.json)
        }
        Command::ProbeRefresh => commands::probe::refresh(&paths, &mut config, style.json),
        Command::ProbeZones => commands::probe::zones(&paths, &mut config, style.json),
        Command::ProbeGroup { zone } => {
            commands::probe::group(&paths, &mut config, &zone, style.json)
        }
        Command::ProbeStats => commands::probe::stats(&paths, &mut config, style.json),
        Command::ProbeRecord { zone, name } => {
            commands::probe::record(&paths, &mut config, &zone, &name, style.json)
        }
        Command::ProbeStructure { kind, limit } => {
            commands::probe::structure(&paths, &mut config, kind.as_deref(), limit, style.json)
        }
    }
}
