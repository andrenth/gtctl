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

    #[serde(default = "default_estimate_config")]
    pub estimate: EstimateConfig,

    pub lpm: LpmConfig,

    #[serde(deserialize_with = "parse_log_level", default = "default_log_level")]
    pub log_level: Level,

    #[serde(default)]
    pub remove_rendered_scripts: bool,
}

#[derive(Debug, Deserialize)]
pub struct EstimateConfig {
    #[serde(default = "default_scaling_factor")]
    #[serde(deserialize_with = "parse_scaling_factor")]
    pub rules_scaling_factor: usize,
    #[serde(default = "default_scaling_factor")]
    #[serde(deserialize_with = "parse_scaling_factor")]
    pub tbl8s_scaling_factor: usize,
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

fn default_estimate_config() -> EstimateConfig {
    EstimateConfig {
        rules_scaling_factor: default_scaling_factor(),
        tbl8s_scaling_factor: default_scaling_factor(),
    }
}

fn default_scaling_factor() -> usize {
    1
}

fn parse_scaling_factor<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(deserializer)?;
    match s.parse() {
        Ok(0) => Err(serde::de::Error::custom("scaling factor must be positive")),
        Ok(n) => Ok(n),
        Err(e) => Err(serde::de::Error::custom(e)),
    }
}
