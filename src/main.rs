use std::cmp::Ord;
use std::collections::BTreeSet;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{crate_name, crate_version, ArgGroup, Clap};
use drib::aggregate::{self, Entry};
use drib::config::Templates;
use drib::net::Net;
use drib::output::{self, Bootstrap, Changes, Diff};
use futures::stream;
use ipnet::{Ipv4Net, Ipv6Net};
use log::{debug, info, warn, Level};
use serde::Serialize;
use tokio::signal::unix::{signal, SignalKind};
use tokio::stream::StreamExt;
use tokio::{
    fs::{self, File},
    io::{self, AsyncBufReadExt, BufReader},
};

use gtctl::{
    config::{Config, LuaFunctions},
    dyncfg,
    params::{self, CurrentParams, Params},
    util::safe_write,
};

const CUR_AGGREGATE: &'static str = "aggreate.cur";
const OLD_AGGREGATE: &'static str = "aggreate.old";

#[derive(Debug, Clap)]
#[clap(name = crate_name!(), version = crate_version!())]
struct Opts {
    #[clap(subcommand)]
    command: Cmd,
}

#[derive(Debug, Clone, Clap)]
enum Cmd {
    Dyncfg(Dyncfg),
    Estimate(Estimate),
}

#[derive(Debug, Clone, Clap)]
struct Dyncfg {
    #[clap(
        short,
        long,
        name = "FILE",
        default_value = "/etc/gtctl/gtctl.conf",
        parse(from_os_str)
    )]
    config: PathBuf,
    #[clap(short, long, name = "AGGREGATE", parse(from_os_str))]
    aggregate: PathBuf,
}

#[derive(Debug, Clone, Clap)]
#[clap(group = ArgGroup::new("estimate").required(true).multiple(true))]
struct Estimate {
    #[clap(
        short = "4",
        long,
        name = "IPV4-PREFIXES",
        parse(from_os_str),
        group = "estimate"
    )]
    ipv4_prefixes: Option<PathBuf>,
    #[clap(
        short = "6",
        long,
        name = "IPV6-PREFIXES",
        parse(from_os_str),
        group = "estimate"
    )]
    ipv6_prefixes: Option<PathBuf>,
}

#[derive(Debug, Eq, PartialEq)]
enum Mode {
    Replace,
    Update,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opts = Opts::parse();

    match opts.command {
        Cmd::Dyncfg(flags) => {
            let config = load_config(&flags.config)?;
            setup_logger(&config.log_level);
            ignore_signals().await?;
            // Current path already exists: must be
            // a remain from an interrupted execution.
            // Run the diff to the previous version.
            let cur_path = config.state_dir.join(CUR_AGGREGATE);
            if Path::new(&cur_path).exists() {
                warn!("found preexisting current aggregate file; processing");
                dyn_cfg(&cur_path, &config).await?;
            }
            dyn_cfg(&flags.aggregate, &config).await?;
        }
        Cmd::Estimate(flags) => {
            if let Some(path) = flags.ipv4_prefixes {
                let prefixes: BTreeSet<Ipv4Net> = load_prefixes(&path).await?;
                let params = params::estimate_ipv4(&prefixes);
                println!("ipv4: {}", params);
            }
            if let Some(path) = flags.ipv6_prefixes {
                let prefixes: BTreeSet<Ipv6Net> = load_prefixes(&path).await?;
                let params = params::estimate_ipv6(&prefixes);
                println!("ipv6: {}", params);
            }
        }
    }

    Ok(())
}

async fn ignore_signals() -> Result<(), io::Error> {
    let mut signals = stream::select_all(vec![
        signal(SignalKind::alarm())?,
        signal(SignalKind::child())?,
        signal(SignalKind::hangup())?,
        signal(SignalKind::interrupt())?,
        signal(SignalKind::io())?,
        signal(SignalKind::pipe())?,
        signal(SignalKind::quit())?,
        signal(SignalKind::terminate())?,
        signal(SignalKind::user_defined1())?,
        signal(SignalKind::user_defined2())?,
        signal(SignalKind::window_change())?,
    ]);

    tokio::spawn(async move {
        while let Some(()) = signals.next().await {
            info!("got signal");
        }
    });

    Ok(())
}

fn load_config(path: impl AsRef<Path>) -> Result<Config, anyhow::Error> {
    let path = path.as_ref();
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read '{}'", path.display()))?;
    let config: Config = serde_yaml::from_str(&data).context("configuration deserialize failed")?;
    Ok(config)
}

async fn dyn_cfg(new_path: impl AsRef<Path>, config: &Config) -> Result<(), anyhow::Error> {
    let cur_path = config.state_dir.join(CUR_AGGREGATE);

    fs::copy(&new_path, &cur_path).await.with_context(|| {
        format!(
            "failed to copy new aggregate '{}' to '{}'",
            new_path.as_ref().display(),
            cur_path.display()
        )
    })?;

    let (ipv4_aggregate, ipv6_aggregate) =
        aggregate::deserialize(&cur_path).await.with_context(|| {
            format!(
                "failed to deserialize current aggregate from '{}'",
                cur_path.display()
            )
        })?;
    let new_bootstrap = Bootstrap::new(&ipv4_aggregate, &ipv6_aggregate);

    let old_path = config.state_dir.join(OLD_AGGREGATE);
    let (ipv4_aggregate, ipv6_aggregate) =
        aggregate::deserialize(&old_path).await.with_context(|| {
            format!(
                "failed to deserialize old aggregate from '{}'",
                old_path.display()
            )
        })?;
    let old_bootstrap = Bootstrap::new(&ipv4_aggregate, &ipv6_aggregate);

    for (kind, new_ranges) in &new_bootstrap.ipv4 {
        let empty = BTreeSet::new();
        let old_ranges = old_bootstrap.ipv4.get(kind).unwrap_or(&empty);
        run_ipv4(config, kind, &new_ranges, &old_ranges).await?;
    }

    for (kind, new_ranges) in &new_bootstrap.ipv6 {
        let empty = BTreeSet::new();
        let old_ranges = old_bootstrap.ipv6.get(kind).unwrap_or(&empty);
        run_ipv6(config, kind, &new_ranges, &old_ranges).await?;
    }

    fs::rename(&cur_path, &old_path).await.with_context(|| {
        format!(
            "failed to rename '{}' to '{}'",
            cur_path.display(),
            old_path.display()
        )
    })?;

    Ok(())
}

async fn run_ipv4(
    config: &Config,
    kind: &Option<String>,
    new: &BTreeSet<&Entry<Ipv4Net>>,
    old: &BTreeSet<&Entry<Ipv4Net>>,
) -> Result<(), anyhow::Error> {
    run(
        config,
        &config.lpm.ipv4,
        "ipv4",
        kind,
        &new,
        &old,
        params::estimate_ipv4,
        Diff::ipv4,
    )
    .await
}

async fn run_ipv6(
    config: &Config,
    kind: &Option<String>,
    new: &BTreeSet<&Entry<Ipv6Net>>,
    old: &BTreeSet<&Entry<Ipv6Net>>,
) -> Result<(), anyhow::Error> {
    run(
        config,
        &config.lpm.ipv6,
        "ipv6",
        kind,
        &new,
        &old,
        params::estimate_ipv6,
        Diff::ipv6,
    )
    .await
}

#[derive(Debug, Serialize)]
struct ParametersScriptVariables<'a> {
    lpm_table: &'a str,
    lpm_params_function: &'a str,
}

#[derive(Debug, Serialize)]
struct ReplaceModeVariables<'a, T> {
    params: &'a Params<T>,
    lpm_table: &'a str,
    lpm_table_constructor: &'a str,
}

async fn run<'changes, 'ranges: 'changes, T>(
    config: &Config,
    lua_functions: &LuaFunctions,
    proto: &str,
    kind: &Option<String>,
    new_ranges: &'ranges BTreeSet<&Entry<T>>,
    old_ranges: &'ranges BTreeSet<&Entry<T>>,
    estimate: impl Fn(&BTreeSet<T>) -> Params<T>,
    make_diff: impl Fn(Changes<'changes, T>) -> Diff<'changes>,
) -> Result<(), anyhow::Error>
where
    T: Ord + Serialize + Copy,
{
    let table = replace_vars(&config.lpm.table_format, proto, kind);
    let vars = ParametersScriptVariables {
        lpm_table: &table,
        lpm_params_function: &lua_functions.lpm_get_params_function,
    };

    let script =
        render_parameters_script(&config.lpm.parameters_script, proto, kind, &vars)
            .await
            .with_context(|| {
                format!(
                "failed to render parameters script from '{}' with proto {}, kind {:?}, vars: {:?}",
                &config.lpm.parameters_script.input.display(), proto, kind, vars,
            )
            })?;

    let current_params = params::read(&config.socket, &script)
        .await
        .with_context(|| {
            format!(
                "failed to read lpm parameters from '{}'",
                &config.socket.display()
            )
        })?;

    let set = new_ranges.iter().map(|e| e.range).collect();
    let estimated_params = estimate(&set);

    let scripts = match run_mode(&current_params, &estimated_params) {
        Mode::Replace => {
            info!(
                "replacing table {} with parameters {}",
                table, estimated_params,
            );
            let changes = Changes {
                insert: new_ranges.iter().map(Deref::deref).collect(),
                remove: vec![],
            };
            let diff = make_diff(changes);
            let vars = ReplaceModeVariables {
                params: &estimated_params,
                lpm_table: &table,
                lpm_table_constructor: &lua_functions.lpm_table_constructor,
            };
            let mut replace = config.replace.clone();
            replace.templates.output = replace_vars(&config.replace.templates.output, proto, kind);
            output::render_diff_with_extra(
                &diff,
                &replace.templates.input,
                &replace.templates.output,
                replace.max_ranges_per_file,
                &vars,
            )
            .await
            .context("failed to render replacement script")?
        }
        Mode::Update => {
            info!("updating table {}", table,);
            let insert = new_ranges - old_ranges;
            let remove = old_ranges - new_ranges;
            let changes = Changes {
                insert: insert.into_iter().collect(),
                remove: remove.into_iter().collect(),
            };
            let diff = make_diff(changes);
            let mut update = config.update.clone();
            update.templates.output = replace_vars(&config.update.templates.output, proto, kind);
            output::render_diff(
                &diff,
                &update.templates.input,
                &update.templates.output,
                update.max_ranges_per_file,
            )
            .await
            .context("failed to render update script")?
        }
    };
    debug!("rendered scripts: {:?}", scripts);
    for script in scripts {
        dyncfg::send_config_script(&config.socket, &script)
            .await
            .with_context(|| format!("failed to send script '{}'", script.display()))?;
        if config.remove_rendered_scripts {
            fs::remove_file(script).await?;
        }
    }

    Ok(())
}

fn run_mode<T>(cur: &CurrentParams<T>, est: &Params<T>) -> Mode {
    for c in &cur.0 {
        if (est.num_rules, est.num_tbl8s) > (c.num_rules, c.num_tbl8s) {
            return Mode::Replace;
        }
    }
    Mode::Update
}

#[derive(Debug, Serialize)]
struct ParamsWrapper<'a> {
    ipv4: &'a Params<Ipv4Net>,
    ipv6: &'a Params<Ipv6Net>,
}

async fn render_parameters_script<'a>(
    config: &Templates,
    proto: &str,
    kind: &Option<String>,
    vars: &ParametersScriptVariables<'a>,
) -> Result<PathBuf, anyhow::Error> {
    use tera::{Context, Tera};

    let template = fs::read_to_string(&config.input).await?;
    let mut tera = Tera::default();
    let context = Context::from_serialize(&vars)?;
    let output = PathBuf::from(replace_vars(&config.output, proto, kind));
    let res = tera.render_str(&template, &context)?;

    safe_write(&output, res.as_bytes()).await?;
    Ok(output)
}

fn replace_vars(s: &str, proto: &str, kind: &Option<String>) -> String {
    s.replace("{proto}", proto)
        .replace("{kind}", kind.as_deref().unwrap_or(""))
}

fn setup_logger(level: &Level) {
    use env_logger::{Builder, Target, WriteStyle};

    let mut builder = Builder::new();
    builder.target(Target::Stdout);
    builder.write_style(WriteStyle::Auto);
    builder.filter_module("gtctl", level.to_level_filter());

    builder.init();
}

async fn load_prefixes<T: Net>(path: impl AsRef<Path>) -> Result<BTreeSet<T>, anyhow::Error> {
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut prefixes = BTreeSet::new();
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let prefix = line.parse()?;
        prefixes.insert(prefix);
    }
    Ok(prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_mode() {
        let cur: CurrentParams<()> = CurrentParams(vec![Params::new(10, 10), Params::new(20, 10)]);
        let est = Params::new(15, 15);
        assert_eq!(Mode::Replace, run_mode(&cur, &est));

        let cur: CurrentParams<()> = CurrentParams(vec![Params::new(20, 20), Params::new(15, 10)]);
        let est = Params::new(15, 15);
        assert_eq!(Mode::Replace, run_mode(&cur, &est));

        let cur: CurrentParams<()> = CurrentParams(vec![Params::new(20, 20), Params::new(15, 15)]);
        let est = Params::new(15, 15);
        assert_eq!(Mode::Update, run_mode(&cur, &est));
    }
}
