use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub port: u16,
    pub data_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen_addr: "127.0.0.1".to_string(),
                port: 8443,
                data_dir: PathBuf::from("data"),
            },
        }
    }
}

pub fn load_config() -> anyhow::Result<Config> {
    let explicit = std::env::var("MCPSHIELD_CONFIG").ok();
    let path_str = explicit.clone().unwrap_or_else(|| "mcpshield.toml".to_string());
    let path = PathBuf::from(&path_str);

    if !path.exists() {
        if explicit.is_some() {
            anyhow::bail!("config file not found: {path_str} (set via MCPSHIELD_CONFIG)");
        }
        eprintln!("warning: no mcpshield.toml found, using built-in defaults");
        return Ok(Config::default());
    }

    let contents = std::fs::read_to_string(&path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
