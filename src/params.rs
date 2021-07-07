use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::marker::PhantomData;
use std::num::ParseIntError;
use std::path::Path;

use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;

use ipnet::{Ipv4Net, Ipv6Net};
use serde::de::DeserializeOwned;

use crate::dyncfg;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Params<T> {
    pub num_rules: usize,
    pub num_tbl8s: usize,
    phantom: PhantomData<T>,
}

impl<T> Params<T> {
    pub fn new(num_rules: usize, num_tbl8s: usize) -> Params<T> {
        Params {
            num_rules,
            num_tbl8s,
            phantom: PhantomData,
        }
    }
}

impl<T> fmt::Display for Params<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rules={}, tbl8s={}", self.num_rules, self.num_tbl8s)
    }
}

pub fn estimate_ipv4(nets: &BTreeSet<Ipv4Net>) -> Params<Ipv4Net> {
    estimate_params(nets, lpm_add_tables)
}

pub fn estimate_ipv6(nets: &BTreeSet<Ipv6Net>) -> Params<Ipv6Net> {
    estimate_params(nets, lpm6_add_tables)
}

fn estimate_params<T, F>(nets: &BTreeSet<T>, f: F) -> Params<T>
where
    T: Ord + DeserializeOwned,
    F: Fn(&T, &mut HashSet<T>) -> usize,
{
    let mut num_rules = 0;
    let mut num_tbl8s = 0;
    let mut prefixes = HashSet::new();

    for net in nets {
        num_rules += 1;
        num_tbl8s += f(&net, &mut prefixes);
    }

    Params::new(num_rules, num_tbl8s)
}

fn lpm_add_tables(net: &Ipv4Net, prefixes: &mut HashSet<Ipv4Net>) -> usize {
    if net.prefix_len() <= 24 {
        return 0;
    }

    // For a prefix with length longer than 24, one tbl8
    // is needed according to the addition description in
    // DPDK LPM library:
    // https://doc.dpdk.org/guides/prog_guide/lpm_lib.html#addition
    //
    // unwrap is safe because the prefix length is always 24.
    let prefix = Ipv4Net::new(net.addr(), 24).unwrap().trunc();
    if prefixes.contains(&prefix) {
        return 0;
    }
    prefixes.insert(prefix);
    1
}

fn lpm6_add_tables(net: &Ipv6Net, prefixes: &mut HashSet<Ipv6Net>) -> usize {
    let mut depth = 24;
    let mut ret = 0;

    let addr = net.addr();
    let prefix_len = net.prefix_len();

    while depth < prefix_len {
        // unwrap is safe because `depth` is smaller than `prefix_len`,
        // which comes from a valid Ipv6Net.
        let prefix = Ipv6Net::new(addr, depth).unwrap().trunc();
        if !prefixes.contains(&prefix) {
            prefixes.insert(prefix);
            ret += 1;
        }
        depth += 8;
    }

    ret
}

#[derive(Debug)]
pub struct CurrentParams<T>(pub Vec<Params<T>>);

pub async fn read<T>(
    socket: impl AsRef<Path>,
    script: impl AsRef<Path>,
) -> Result<CurrentParams<T>, Error> {
    let res = dyncfg::send_config_script(&socket, &script).await?;
    let params = parse_params(&res)?;
    Ok(params)
}

fn parse_params<T>(s: &str) -> Result<CurrentParams<T>, ParseError> {
    Ok(CurrentParams(parse_lines(s)?))
}

fn parse_lines<T>(s: &str) -> Result<Vec<Params<T>>, ParseError> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"^\s*(\d+):\s*(\d+),\s*(\d+)\s*$"#).unwrap();
    }

    let mut v = Vec::new();

    for line in s.lines() {
        if let Some(caps) = RE.captures(line) {
            let id: usize = caps
                .get(1)
                .expect("BUG: nothing captured at 1")
                .as_str()
                .parse()?;
            let p1 = caps
                .get(2)
                .expect("BUG: nothing captured at 2")
                .as_str()
                .parse()?;
            let p2 = caps
                .get(3)
                .expect("BUG: nothing captured at 3")
                .as_str()
                .parse()?;
            v.push((id, p1, p2));
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        return Err(ParseError::Line(line.to_owned()));
    }

    if v.is_empty() {
        return Err(ParseError::Empty);
    }
    v.sort_by_key(|(id, _, _)| *id);
    Ok(v.iter().map(|(_, nr, nt)| Params::new(*nr, *nt)).collect())
}

#[derive(Debug)]
pub enum Error {
    Dyncfg(dyncfg::Error),
    Parse(ParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Dyncfg(e) => write!(f, "dyncfg error: {}", e),
            Error::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Dyncfg(e) => Some(e),
            Error::Parse(e) => Some(e),
        }
    }
}

impl From<dyncfg::Error> for Error {
    fn from(e: dyncfg::Error) -> Error {
        Error::Dyncfg(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Error {
        Error::Parse(e)
    }
}

#[derive(Debug)]
pub enum ParseError {
    Empty,
    Line(String),
    ParseInt(ParseIntError),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "dyncfg returned an empty response"),
            ParseError::Line(s) => write!(f, "dyncfg returned an unexpected line: {}", s),
            ParseError::ParseInt(e) => write!(f, "failed to parse int in dyncfg response: {}", e),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Empty => None,
            ParseError::Line(_) => None,
            ParseError::ParseInt(e) => Some(e),
        }
    }
}

impl From<ParseIntError> for ParseError {
    fn from(e: ParseIntError) -> ParseError {
        ParseError::ParseInt(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lines() {
        let lines = "";
        assert!(parse_lines::<()>(lines).is_err());

        let lines = "foo";
        assert!(parse_lines::<()>(lines).is_err());

        let lines = "99:101,102";
        assert_eq!(
            vec![Params::new(101, 102)],
            parse_lines::<()>(lines).unwrap()
        );

        let lines = r#"
            0: 1, 2
            2: 5, 6
            1: 3, 4
        "#;

        assert_eq!(
            vec![Params::new(1, 2), Params::new(3, 4), Params::new(5, 6)],
            parse_lines::<()>(lines).unwrap()
        );
    }
}
