use std::path::PathBuf;

use drib::config::{ChunkedTemplates, Templates};
use log::Level;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_socket_path")]
    pub socket: PathBuf,
    pub state_dir: PathBuf,
    pub replace: ChunkedTemplates,
    pub update: ChunkedTemplates,

    pub lpm: LpmConfig,

    #[serde(deserialize_with = "parse_log_level", default = "default_log_level")]
    pub log_level: Level,

    #[serde(default)]
    pub remove_rendered_scripts: bool,
}

#[derive(Debug, Deserialize)]
pub struct LpmConfig {
    pub table_format: String,
    pub parameters_script: Templates,
    pub ipv4: LuaFunctions,
    pub ipv6: LuaFunctions,
}

#[derive(Debug, Deserialize)]
pub struct LuaFunctions {
    pub lpm_table_constructor: String,
    pub lpm_get_params_function: String,
}

fn parse_log_level<'de, D>(deserializer: D) -> Result<Level, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/gatekeeper/dyn_cfg.socket")
}

fn default_log_level() -> Level {
    Level::Info
}
