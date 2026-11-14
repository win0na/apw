use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::output;

pub fn run(
    paths: &Paths,
    config: &mut Config,
    anisette_url: Option<String>,
    account: Option<String>,
    json: bool,
) -> Result<()> {
    if let Some(url) = anisette_url {
        config.anisette_url = Some(url);
    }
    if let Some(account) = account {
        config.account = Some(account);
    }

    let Some(url) = config.anisette_url() else {
        return Err(Error::Invalid(
            "set --anisette-url or APW_ANISETTE_URL".into(),
        ));
    };

    config.save(paths)?;

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!([{
            "anisette_url": url,
            "account": config.account,
            "config": paths.config_file,
        }])));
    } else {
        println!("anisette URL saved to {}", paths.config_file.display());
    }

    Err(Error::Message(
        "live login is not implemented in this build; it arrives with the auth backend".into(),
    ))
}
