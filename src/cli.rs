use crate::{
    browser,
    model::{self, Credential, Metadata, OAuthConfig, Tokens},
    oauth,
    vault::{Vault, read_bounded, remove_source},
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::OpenOptions,
    io::{Cursor, Write},
    path::PathBuf,
    process::Command,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "agent-creds",
    version,
    about = "Agent Credentials — keep credentials out of routine agent context"
)]
pub struct Cli {
    /// Isolated vault directory; defaults to the OS local application data directory.
    #[arg(long, global = true)]
    pub vault_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args)]
pub struct Destination {
    pub name: String,
    #[arg(long)]
    pub env: Option<String>,
    /// Explicitly overwrite an existing entry.
    #[arg(long)]
    pub replace: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Read a UTF-8 secret file and encrypt it; remove the source unless --keep.
    Store {
        #[command(flatten)]
        destination: Destination,
        #[arg(long)]
        from_file: PathBuf,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        keep: bool,
    },
    /// Import dotenv values without shell evaluation; retain source by default.
    ImportEnv {
        file: PathBuf,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long, value_delimiter = ',')]
        exclude: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        shred_source: bool,
    },
    /// Export a blank dotenv template; never export credential values.
    Template {
        #[arg(long)]
        out: PathBuf,
    },
    /// Open an isolated browser and wait for one named cookie at the target URL.
    CookieScrape {
        #[command(flatten)]
        destination: Destination,
        #[arg(long)]
        url: String,
        #[arg(long)]
        cookie: String,
        #[arg(long, default_value = "auto")]
        browser: String,
        #[arg(long)]
        browser_path: Option<PathBuf>,
        /// Maximum wait in seconds (1–3600).
        #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..=3600))]
        timeout: u64,
        #[arg(long)]
        no_banner: bool,
        /// Store name=value rather than just the cookie value.
        #[arg(long)]
        header: bool,
        /// Explicit expiry; otherwise use the cookie's Expires attribute.
        #[arg(long)]
        expires: Option<String>,
    },
    /// Configure, authorize or refresh a generic OAuth client.
    #[command(name = "oauth")]
    OAuth {
        #[command(subcommand)]
        command: OAuthCommand,
    },
    /// Inject selected credentials only into a child process. No shell expansion.
    Exec {
        #[arg(value_delimiter = ',', num_args = 1, required = true)]
        names: Vec<String>,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    /// Show cached metadata without decrypting credentials or making network calls.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List entry names without decrypting credentials.
    List,
    /// Remove an encrypted entry.
    Rm { name: String },
}

#[derive(Subcommand)]
pub enum OAuthCommand {
    /// Encrypt a provider-neutral JSON client configuration from a file.
    Configure {
        #[command(flatten)]
        destination: Destination,
        #[arg(long)]
        from_file: PathBuf,
        #[arg(long)]
        keep: bool,
    },
    /// Authorize with PKCE in the system browser and save tokens.
    Login {
        name: String,
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=3600))]
        timeout: u64,
    },
    /// Refresh now; persist rotated refresh tokens before returning.
    Refresh { name: String },
    /// Import an existing refresh token from a file, exchange it and save the result.
    ImportRefresh {
        name: String,
        #[arg(long)]
        from_file: PathBuf,
        #[arg(long)]
        keep: bool,
    },
}

fn metadata(
    destination: &Destination,
    kind: &str,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> Result<Metadata> {
    model::valid_name(&destination.name)?;
    Ok(Metadata {
        name: destination.name.clone(),
        env: model::environment(&destination.name, destination.env.as_deref())?,
        kind: kind.into(),
        expires_at,
        updated_at: Utc::now(),
    })
}

fn preflight(vault: &Vault, destination: &Destination) -> Result<()> {
    model::valid_name(&destination.name)?;
    model::environment(&destination.name, destination.env.as_deref())?;
    ensure!(
        destination.replace || !vault.exists(&destination.name)?,
        "entry already exists; use --replace explicitly"
    );
    Ok(())
}

fn secret_file(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let bytes = read_bounded(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("secret file must contain UTF-8 text"))?;
    // Remove a text file's final newline, preserving all other whitespace.
    let value = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    ensure!(
        !value.is_empty() && !value.contains('\0'),
        "secret must be nonempty and contain no NUL bytes"
    );
    Ok(Zeroizing::new(value.to_owned()))
}

pub fn run(cli: Cli) -> Result<i32> {
    let vault = Vault::open(cli.vault_dir.as_deref())?;
    match cli.command {
        Commands::Store {
            destination,
            from_file,
            expires,
            keep,
        } => {
            preflight(&vault, &destination)?;
            vault.validate_source(&from_file)?;
            let metadata = metadata(&destination, "secret", model::expiry(expires.as_deref())?)?;
            let value = secret_file(&from_file)?;
            vault.save(
                &metadata,
                &Credential::Secret {
                    value: value.to_string(),
                },
                destination.replace,
            )?;
            if !keep {
                remove_source(&from_file)?;
            }
            println!("Stored {} → {}", metadata.name, metadata.env);
        }
        Commands::ImportEnv {
            file,
            prefix,
            exclude,
            expires,
            dry_run,
            replace,
            shred_source,
        } => {
            vault.validate_source(&file)?;
            let data = read_bounded(&file)?;
            let entries = parse_env(&data)?;
            let expires_at = model::expiry(expires.as_deref())?;
            let mut plan = Vec::new();
            let mut names = HashSet::new();
            for (key, value) in entries {
                if prefix.as_ref().is_some_and(|p| !key.starts_with(p)) || exclude.contains(&key) {
                    continue;
                }
                let destination = Destination {
                    name: key.to_ascii_lowercase().replace('_', "-"),
                    env: Some(key),
                    replace,
                };
                ensure!(
                    names.insert(destination.name.clone()),
                    "dotenv keys produce duplicate entry names"
                );
                preflight(&vault, &destination)?;
                plan.push((metadata(&destination, "secret", expires_at)?, value));
            }
            ensure!(
                !plan.is_empty(),
                "no nonempty dotenv values matched the selection"
            );
            for (meta, _) in &plan {
                println!("{} → {}", meta.name, meta.env);
            }
            if dry_run {
                println!("Dry run; no changes made.");
                return Ok(0);
            }
            // Every input and collision is checked before the first write. On an
            // I/O failure, earlier entries may be saved; source remains intact.
            for (meta, value) in plan {
                vault.save(
                    &meta,
                    &Credential::Secret {
                        value: value.to_string(),
                    },
                    replace,
                )?;
            }
            if shred_source {
                remove_source(&file)?;
            }
            println!(
                "Import complete; source {}.",
                if shred_source { "removed" } else { "retained" }
            );
        }
        Commands::Template { out } => {
            let records = vault.list()?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out)
                .context("cannot create template; output must not already exist")?;
            writeln!(
                file,
                "# Agent Credentials — blank values only\n# Fill locally, then: agent-creds import-env <file> --shred-source"
            )?;
            let mut envs = HashSet::new();
            for record in records {
                if record.kind != "oauth" && envs.insert(record.env.clone()) {
                    writeln!(file, "{}=", record.env)?;
                }
            }
            file.sync_all()?;
            println!("Created blank template.");
        }
        Commands::CookieScrape {
            destination,
            url,
            cookie,
            browser,
            browser_path,
            timeout,
            no_banner,
            header,
            expires,
        } => {
            preflight(&vault, &destination)?;
            let explicit_expiry = model::expiry(expires.as_deref())?;
            let captured = browser::scrape(&browser::Options {
                url: &url,
                cookie: &cookie,
                browser: &browser,
                executable: browser_path.as_deref(),
                timeout: Duration::from_secs(timeout),
                no_banner,
                header,
            })?;
            let meta = metadata(
                &destination,
                "cookie",
                explicit_expiry.or(captured.expires_at),
            )?;
            if meta.expires_at.is_none() {
                eprintln!(
                    "Cookie has no declared expiry; server-side validity is unknown. Use --expires to set a local deadline."
                );
            }
            vault.save(
                &meta,
                &Credential::Secret {
                    value: captured.value,
                },
                destination.replace,
            )?;
            println!("Captured {} → {}", meta.name, meta.env);
        }
        Commands::OAuth { command } => match command {
            OAuthCommand::Configure {
                destination,
                from_file,
                keep,
            } => {
                preflight(&vault, &destination)?;
                vault.validate_source(&from_file)?;
                let bytes = read_bounded(&from_file)?;
                let config: Box<OAuthConfig> = serde_json::from_slice(&bytes).map_err(|_| {
                    anyhow::anyhow!("invalid OAuth configuration JSON; details suppressed")
                })?;
                oauth::validate(&config)?;
                let meta = metadata(&destination, "oauth", None)?;
                vault.save(
                    &meta,
                    &Credential::OAuth {
                        config,
                        tokens: None,
                    },
                    destination.replace,
                )?;
                if !keep {
                    remove_source(&from_file)?;
                }
                println!("Configured {}; run oauth login to authorize.", meta.name);
            }
            OAuthCommand::Login { name, timeout } => {
                let (mut meta, credential) = vault.load(&name)?;
                let Credential::OAuth { config, .. } = credential else {
                    anyhow::bail!("entry is not an OAuth client")
                };
                let tokens = oauth::login(&config, Duration::from_secs(timeout))?;
                meta.expires_at = tokens.expires_at;
                meta.updated_at = Utc::now();
                vault.save(
                    &meta,
                    &Credential::OAuth {
                        config,
                        tokens: Some(tokens),
                    },
                    true,
                )?;
                println!("Authorized {}.", meta.name);
            }
            OAuthCommand::Refresh { name } => {
                let (meta, credential) = vault.load(&name)?;
                refresh_entry(&vault, meta, credential)?;
                println!("Refreshed {name}.");
            }
            OAuthCommand::ImportRefresh {
                name,
                from_file,
                keep,
            } => {
                vault.validate_source(&from_file)?;
                let (meta, credential) = vault.load(&name)?;
                let Credential::OAuth { config, .. } = credential else {
                    anyhow::bail!("entry is not an OAuth client")
                };
                let refresh = secret_file(&from_file)?;
                refresh_entry(
                    &vault,
                    meta,
                    Credential::OAuth {
                        config,
                        tokens: Some(Tokens {
                            access_token: String::new(),
                            refresh_token: Some(refresh.to_string()),
                            expires_at: None,
                        }),
                    },
                )?;
                if !keep {
                    remove_source(&from_file)?;
                }
                println!("Imported and exchanged refresh token for {name}.");
            }
        },
        Commands::Exec { names, command } => {
            let mut child = Command::new(&command[0]);
            child.args(&command[1..]);
            let mut used = HashSet::new();
            for name in names {
                let (mut meta, mut credential) = vault.load(&name)?;
                model::environment(&name, Some(&meta.env))?;
                ensure!(
                    used.insert(meta.env.to_ascii_uppercase()),
                    "selected entries map to the same environment variable"
                );
                if let Credential::OAuth { tokens, .. } = &credential {
                    let tokens = tokens.as_ref().context("OAuth login required")?;
                    // Unknown expiry is not guessed. Refresh on every execution
                    // if a refresh token exists; otherwise require a new login.
                    if tokens
                        .expires_at
                        .is_none_or(|e| e <= Utc::now() + chrono::Duration::seconds(60))
                    {
                        (meta, credential) = refresh_entry(&vault, meta, credential)?;
                    }
                }
                ensure!(
                    meta.expires_at.is_none_or(|e| e > Utc::now()),
                    "credential expired; store or capture it again"
                );
                let value = match credential {
                    Credential::Secret { value } => value,
                    Credential::OAuth { tokens, .. } => {
                        tokens.context("OAuth login required")?.access_token
                    }
                };
                ensure!(
                    !value.contains('\0'),
                    "credential cannot be injected into an environment"
                );
                child.env(&meta.env, value);
            }
            // The child may itself invoke the broker. Release the lock before
            // launching it; all token rotations have already been persisted.
            drop(vault);
            let status = child
                .status()
                .map_err(|_| anyhow::anyhow!("cannot launch child process"))?;
            return Ok(status.code().unwrap_or(1));
        }
        Commands::Status { json } => {
            let records = vault.list()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
            } else {
                for meta in records {
                    let state = match meta.expires_at {
                        Some(date) if date <= Utc::now() => "expired",
                        Some(_) => "within recorded expiry",
                        None if meta.kind == "oauth" => "login required / expiry unknown",
                        None => "expiry unknown",
                    };
                    println!("{}\t{}\t{}\t{state}", meta.name, meta.kind, meta.env);
                }
            }
        }
        Commands::List => {
            for meta in vault.list()? {
                println!("{}", meta.name);
            }
        }
        Commands::Rm { name } => {
            vault.remove(&name)?;
            println!("Removed {name}.");
        }
    }
    Ok(0)
}

fn refresh_entry(
    vault: &Vault,
    mut meta: Metadata,
    credential: Credential,
) -> Result<(Metadata, Credential)> {
    let Credential::OAuth { config, tokens } = credential else {
        anyhow::bail!("entry is not an OAuth client")
    };
    let tokens = oauth::refresh(&config, &tokens.context("OAuth login required")?)?;
    meta.expires_at = tokens.expires_at;
    meta.updated_at = Utc::now();
    let credential = Credential::OAuth {
        config,
        tokens: Some(tokens),
    };
    vault.save(&meta, &credential, true)?;
    Ok((meta, credential))
}

pub fn parse_env(data: &[u8]) -> Result<Vec<(String, Zeroizing<String>)>> {
    // dotenvy ordinarily expands $VARIABLE from the process environment. Reject
    // interpolation syntax so importing a file cannot pull in unrelated secrets.
    let text =
        std::str::from_utf8(data).map_err(|_| anyhow::anyhow!("dotenv input must be UTF-8"))?;
    ensure!(
        !text.contains('$') && !text.contains('`'),
        "dotenv interpolation and shell syntax are unsupported; use store for literal values containing $ or backticks"
    );
    let mut keys = HashSet::new();
    let mut entries = Vec::new();
    for pair in dotenvy::from_read_iter(Cursor::new(text.trim_start_matches('\u{feff}'))) {
        let (key, value) =
            pair.map_err(|_| anyhow::anyhow!("invalid dotenv syntax; details suppressed"))?;
        model::environment("", Some(&key))?;
        ensure!(keys.insert(key.clone()), "duplicate dotenv variable");
        ensure!(
            !value.contains('\0'),
            "dotenv values cannot contain NUL bytes"
        );
        if !value.is_empty() {
            entries.push((key, Zeroizing::new(value)));
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn documented_oauth_command_name_is_accepted() {
        assert!(Cli::try_parse_from(["agent-creds", "oauth", "refresh", "example"]).is_ok());
    }
    #[test]
    fn dotenv_rejects_duplicates_interpolation_and_malformed_input() {
        assert!(parse_env(b"TOKEN=$OTHER").is_err());
        assert!(parse_env(b"TOKEN=a\nTOKEN=b").is_err());
        assert!(parse_env(b"not an assignment").is_err());
        let pairs = parse_env(b"\xef\xbb\xbfexport TOKEN='a=b#c'\nEMPTY=\nOTHER=value # comment\n")
            .unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(&*pairs[0].1, "a=b#c");
    }
    #[test]
    fn child_arguments_survive_with_or_without_separator() {
        for args in [
            vec![
                "agent-creds",
                "exec",
                "a,b",
                "--",
                "program",
                "--only",
                "foo",
                "--execute",
            ],
            vec![
                "agent-creds",
                "exec",
                "a,b",
                "program",
                "--only",
                "foo",
                "--execute",
            ],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            let Commands::Exec { names, command } = cli.command else {
                panic!()
            };
            assert_eq!(names, ["a", "b"]);
            assert_eq!(command, ["program", "--only", "foo", "--execute"]);
        }
    }
}
