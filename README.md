# gtctl

## Introduction

gtctl is a tool that renders [Drib](https://github.com/andrenth/drib)'s aggregates into [Gatekeeper](https://github.com/AltraMayor/gatekeeper)'s [Grantor](https://github.com/AltraMayor/gatekeeper/wiki/Functional-Block:-GT) policy scripts and submits them via [dynamic configuration](https://github.com/AltraMayor/gatekeeper/wiki/Functional-Block:-Dynamic-Config).

The submission of policy scripts takes Grantor's [LPM configuration parameters](https://github.com/AltraMayor/gatekeeper/wiki/Functional-Block:-GT#LPM_Configuration_Parameters) into accout, updating or replacing the current policy as needed.

## Installation

### Debian or Ubuntu

*Debian packages will be provided with the first gtctl release*

```sh
$ wget https://
$ sudo dpkg -i ...
```

### From source

*gtctl will be added to crates.io on its first release*

Use Rust's package manager, [cargo](https://github.com/rust-lang/cargo), to install gtctl from source:

```sh
$ cargo install --git https://github.com/andrenth/gtctl
```

## Running

gtctl can be run in two modes: _dyncfg_ and _estimate_.
In dyncfg mode, gtctl will read an aggregate file generated by Drib, compare it to the aggregate used in the previous execution, if any, and render a dynamic configuration script according to a configured template, as detailed below.
Depending on the number of entries in the aggregate file and Gatekeeper's [LPM table parameters](https://github.com/AltraMayor/gatekeeper/wiki/Functional-Block:-GK#LPM_Table), the policy will either be updated or completely replaced.
In estimate mode, gtctl reads text files containing IP ranges in CIDR format (one per line), and outputs LPM parameters suitable for the number of input ranges.

Run in dyncfg mode:

```sh
$ gtctl dyncfg -a /path/to/drib/aggregate
```

Run in estimate mode:

```sh
$ gtctl estimate -4 /path/to/ipv4-ranges -6 /path/to/ipv6-ranges
```

As previously mentioned, the files given to the `-4` and/or `-6` flags consist of IP ranges of the respective protocol version, in CIDR format, one per line.
These can be generated directly from a router's routing table.

For example, if using the [Bird](https://bird.network.cz/) routing daemon, these files can be generated with commands similar to the ones below.

```sh
$ bird show route table my_ipv4_table | grep / | awk '{print $1}' > ipv4-ranges
$ bird show route table my_ipv6_table | grep / | awk '{print $1}' > ipv6-ranges
```

The commands above will read the default configuration file, `/etc/gtctl/gtctl.yaml`.
To specify an alternative configuration file, use the `-c` or `--config` command line flag:

```sh
$ gtctl -c /path/to/config/file.yaml dyncfg -a /path/to/drib/aggregate
$ gtctl -c /path/to/config/file.yaml estimate -4 /path/to/ipv4-ranges -6 /path/to/ipv6-ranges
```

For further details, run `gtctl help`.

## Configuration

#### `socket`

The path to Grantor's dynamic configuration socket (defaults to `/var/run/gatekeeper/dyn_cfg.socket`).

#### `log_level`

gtctl's log level.
Valid values are `error`, `warn`, `info`, `debug` or `trace` (defaults to `info`).

#### `state_dir`

The directory where gtctl stores Drib aggregates across executions.

#### `replace`

This section defines parameters for the generation of policy scripts that replace the current policy.
Three subsettings are expected:

* `input` refers to a template file (see the `Templates` section below for details) used to render the policy replacement scripts.
* `output` specifies the path of the rendered scripts.
* `max_ranges_per_file`, if given, limits the number of ranges rendered in a single output file.

The output path is itself a template, so a number of variables can be used to split the bootstrap output according to protocol (i.e. IPv4 and IPv6), using the `{proto}` variable, and _kind_ (see the documentation below), using the `{kind}` variable.
A third variable, `{i}`, corresponds to the *i*th script being generated, according to the `max_ranges_per_file` parameter.
Once the number of ranges rendered in the replacement script reaches the `max_ranges_per_file` value, a new file will be generated, and the `i` variable will be incremented.
This variable supports an integer modifier that indicates how many digits are used for the index, so, for example, `{3i}` will represent the index with 3 digits, padding it with zeros if necessary.

The file name template for the policy replacement scripts is used for all combinations of protocol and _kinds_.
For example, if your groups configuration defines three different _kinds_, a total of six policy replacement scripts will be generated (three for IPv4 and three for IPv6).
This means that if the `{proto}` and `{kind}` variables are not used in the `output` setting, a given rendered file may overwrite a previously generated one, depending on the contents of the aggregate file.

Example:

```yaml
replace: {
  input: "/etc/gtctl/policy_replace.lua.tpl",
  output: "/var/lib/gtctl/policy_replace_{proto}_{kind}.{2i}.lua",
  max_ranges_per_file: 1500,
}
```

#### `update`

This section defines parameters for the generation of policy scripts that update the current policy.
It supports the same parameters and templating variables as the ones available in the `replace` section.

Example:

```yaml
update: {
  input: "/etc/gtctl/policy_update.lua.tpl",
  output: "/etc/gtctl/policy_update_{proto}_{kind}.{2i}.lua",
  max_ranges_per_file: 1500,
}
```

#### `lpm`

This section is concerned with the generation of dynamic configuration scripts that read LPM parameters from Grantor.

The following settings are supported.

* `table_format`: a template for the name of the LPM tables, supporting the `{proto}` and `{kind}` variables.
* `parameters_script`: a subsection with `input` and `output` settings describing, respectively, the template and output paths for the LPM configuration scripts; The output paths support the `{proto}` and `{kind}` variables.
* `ipv4` and `ipv6`: these subsections contain two settings each: `lpm_table_constructor`, the name of the Lua function that initializes an LPM table, and `lpm_get_params_function`, the name of the Lua function that returns the current LPM parameter settings.

Example:

```yaml
lpm: {
  table_format: "{kind}_lpm_{proto}",

  parameters_script: {
    input: "/etc/gtctl/lpm_params.lua.tpl",
    output: "/var/lib/gtctl/lpm_params_{proto}_{kind}.lua",
  },

  ipv4: {
    lpm_table_constructor: "lpmlib.new_lpm",
    lpm_get_params_function: "lpmlib.lpm_get_paras",
  },

  ipv6: {
    lpm_table_constructor: "lpmlib.new_lpm6",
    lpm_get_params_function: "lpmlib.lpm6_get_paras",
  },
}
```

### Templates

gtctl uses the Rust crate [Tera](https://tera.netlify.app/docs) for its templating, which has a simple and intuitive [syntax](https://tera.netlify.app/docs/#templates) similar do Django templates.

For the `replace` and `update` scripts, gtctl provides the respective `input` templates of the given configuration sections with two global objects, `ipv4` and `ipv6`.
These are collections of `entry` elements of the respective protocol, each containing the following fields:

* `kind`: the kind associated to the range, as [configured in Drib](https://github.com/andrenth/drib#groups-ipv4-and-ipv6-sections).
* `class`: the class associated to the range, also taken from Drib's configuration.
* `range`: the IP range itself.

For the LPM parameters script template, the `lpm_table_constructor` and `lpm_get_params_function` variables defined in the configuration file will be available, along with the `lpm_table` variable, whose contents will be derived from the `table_format` setting in the `lpm` configuration section.

Note that the LPM parameters script template is the same for IPv4 and IPv6, and will be rendered twice, once for each protocol version.

Examples of policy and parameter scripts can be found in the [examples](https://github.com/andrenth/gtctl/tree/master/examples) directory in the gtctl repository.
