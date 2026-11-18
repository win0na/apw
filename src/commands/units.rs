use crate::config::{Config, Paths};
use crate::error::{Error, Result};
use crate::output;

const SERVICE: &str = include_str!("../../packaging/systemd/apw-sync.service");
const TIMER: &str = include_str!("../../packaging/systemd/apw-sync.timer");

pub fn run(paths: &Paths, _config: &Config, json: bool) -> Result<()> {
    let exe = std::env::current_exe()?;
    let config_root = paths
        .config_dir
        .parent()
        .ok_or_else(|| Error::Message("cannot locate the config root".into()))?;
    let unit_dir = config_root.join("systemd/user");
    std::fs::create_dir_all(&unit_dir)?;

    let service = SERVICE.replace("@APW@", &exe.display().to_string());
    let service_path = unit_dir.join("apw-sync.service");
    let timer_path = unit_dir.join("apw-sync.timer");
    std::fs::write(&service_path, service)?;
    std::fs::write(&timer_path, TIMER)?;

    let hint = "systemctl --user daemon-reload && systemctl --user enable --now apw-sync.timer";

    if output::use_json(json) {
        output::print_json(&output::success(serde_json::json!({
            "service": service_path,
            "timer": timer_path,
            "enable": hint,
        })));
        return Ok(());
    }

    println!("wrote {}", service_path.display());
    println!("wrote {}", timer_path.display());
    println!("enable with: {hint}");
    Ok(())
}
