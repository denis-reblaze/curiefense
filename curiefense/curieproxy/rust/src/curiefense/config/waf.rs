use crate::curiefense::config::raw::{
    RawWAFEntryMatch, RawWAFProfile, RawWAFProperties, WAFSignature,
};
use crate::Logs;

use hyperscan::prelude::{pattern, Builder, CompileFlags, Pattern, Patterns, VectoredDatabase};
use hyperscan::Vectored;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;

#[derive(Debug, Clone)]
pub struct Section<A> {
    pub headers: A,
    pub cookies: A,
    pub args: A,
}

// TODO: undefined data structures
#[derive(Debug, Clone)]
pub struct WAFProfile {
    pub id: String,
    pub name: String,
    pub ignore_alphanum: bool,
    pub sections: Section<WAFSection>,
}

impl WAFProfile {
    pub fn default() -> Self {
        WAFProfile {
            id: "__default__".to_string(),
            name: "default waf".to_string(),
            ignore_alphanum: true,
            sections: Section {
                headers: WAFSection {
                    max_count: 42,
                    max_length: 1024,
                    names: HashMap::new(),
                    regex: Vec::new(),
                },
                args: WAFSection {
                    max_count: 512,
                    max_length: 1024,
                    names: HashMap::new(),
                    regex: Vec::new(),
                },
                cookies: WAFSection {
                    max_count: 42,
                    max_length: 1024,
                    names: HashMap::new(),
                    regex: Vec::new(),
                },
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct WAFSection {
    pub max_count: usize,
    pub max_length: usize,
    pub names: HashMap<String, WAFEntryMatch>,
    pub regex: Vec<(Regex, WAFEntryMatch)>,
}

#[derive(Debug, Clone)]
pub struct WAFEntryMatch {
    pub reg: Option<Regex>,
    pub restrict: bool,
    pub exclusions: HashSet<String>,
}

#[derive(Debug, Clone, Eq, Serialize, PartialEq, Copy)]
#[serde(rename_all = "snake_case")]
pub enum SectionIdx {
    Headers,
    Cookies,
    Args,
}

impl<A> Section<A> {
    pub fn get(&self, idx: SectionIdx) -> &A {
        match idx {
            SectionIdx::Headers => &self.headers,
            SectionIdx::Cookies => &self.cookies,
            SectionIdx::Args => &self.args,
        }
    }

    pub fn at(&mut self, idx: SectionIdx) -> &mut A {
        match idx {
            SectionIdx::Headers => &mut self.headers,
            SectionIdx::Cookies => &mut self.cookies,
            SectionIdx::Args => &mut self.args,
        }
    }
}

impl<A> Default for Section<A>
where
    A: Default,
{
    fn default() -> Self {
        Section {
            headers: Default::default(),
            cookies: Default::default(),
            args: Default::default(),
        }
    }
}

pub struct WAFSignatures {
    pub db: VectoredDatabase,
    pub ids: Vec<WAFSignature>,
}

impl WAFSignatures {
    pub fn empty() -> Self {
        let pattern: Pattern = pattern! { "^TEST$" };
        WAFSignatures {
            db: pattern.build().unwrap(),
            ids: Vec::new(),
        }
    }
}

fn mk_entry_match(em: RawWAFEntryMatch) -> anyhow::Result<(String, WAFEntryMatch)> {
    Ok((
        em.key,
        WAFEntryMatch {
            restrict: em.restrict,
            exclusions: em
                .exclusions
                .into_iter()
                .map(|mp| mp.into_iter().map(|(a, _)| a))
                .flatten()
                .collect(),
            reg: em.reg.map(|s| Regex::new(&s)).transpose()?, // lol not Haskell
        },
    ))
}

fn mk_section(
    props: RawWAFProperties,
    max_length: usize,
    max_count: usize,
) -> anyhow::Result<WAFSection> {
    let mnames: anyhow::Result<HashMap<String, WAFEntryMatch>> =
        props.names.into_iter().map(mk_entry_match).collect();
    let mregex: anyhow::Result<Vec<(Regex, WAFEntryMatch)>> = props
        .regex
        .into_iter()
        .map(|e| {
            let (s, v) = mk_entry_match(e)?;
            let re = Regex::new(&s)?;
            Ok((re, v))
        })
        .collect();
    Ok(WAFSection {
        max_count,
        max_length,
        names: mnames?,
        regex: mregex?,
    })
}

fn convert_entry(entry: RawWAFProfile) -> anyhow::Result<(String, WAFProfile)> {
    Ok((
        entry.id.clone(),
        WAFProfile {
            id: entry.id,
            name: entry.name,
            ignore_alphanum: entry.ignore_alphanum,
            sections: Section {
                headers: mk_section(
                    entry.headers,
                    entry.max_header_length,
                    entry.max_headers_count,
                )?,
                cookies: mk_section(
                    entry.cookies,
                    entry.max_cookie_length,
                    entry.max_cookies_count,
                )?,
                args: mk_section(entry.args, entry.max_arg_length, entry.max_args_count)?,
            },
        },
    ))
}

impl WAFProfile {
    pub fn resolve(logs: &mut Logs, raw: Vec<RawWAFProfile>) -> HashMap<String, WAFProfile> {
        let mut out = HashMap::new();
        for rp in raw {
            let id = rp.id.clone();
            match convert_entry(rp) {
                Ok((k, v)) => {
                    out.insert(k, v);
                }
                Err(rr) => logs.error(format!("waf id {}: {}", id, rr)),
            }
        }
        out
    }
}

fn convert_signature(entry: &WAFSignature) -> anyhow::Result<Pattern> {
    Pattern::with_flags(
        &entry.operand,
        CompileFlags::MULTILINE | CompileFlags::DOTALL | CompileFlags::CASELESS,
    )
}

pub fn resolve_signatures(raws: Vec<WAFSignature>) -> anyhow::Result<WAFSignatures> {
    let patterns: anyhow::Result<Vec<Pattern>> = raws.iter().map(convert_signature).collect();
    let ptrns: Patterns = Patterns::from_iter(patterns?);
    Ok(WAFSignatures {
        db: ptrns.build::<Vectored>()?,
        ids: raws,
    })
}
