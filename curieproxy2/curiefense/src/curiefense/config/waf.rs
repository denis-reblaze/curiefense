use crate::curiefense::config::raw::{
    RawWAFEntryMatch, RawWAFProfile, RawWAFProperties, WAFSignature,
};
use hyperscan::prelude::{Builder, CompileFlags, Pattern, Patterns, VectoredDatabase};
use hyperscan::Vectored;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Section<A> {
    pub headers: A,
    pub cookies: A,
    pub args: A,
}

// TODO: undefined data structures
#[derive(Debug, Clone)]
pub struct WAFProfile {
    pub name: String,
    pub ignore_alphanum: bool,
    pub sections: Section<WAFSection>,
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
    pub mask: bool,
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

fn mk_entry_match(em: RawWAFEntryMatch) -> anyhow::Result<(String, WAFEntryMatch)> {
    Ok((
        em.key,
        WAFEntryMatch {
            restrict: em.restrict,
            mask: em.mask,
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
            // this is a bit annoying because the errors are converted into an identical type
            // somebody better at rust would probably make it nicer
            mk_entry_match(e)
                .map_err(anyhow::Error::from)
                .and_then(|(s, v)| {
                    Regex::new(&s)
                        .map_err(anyhow::Error::from)
                        .map(|re| (re, v))
                })
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
        entry.id,
        WAFProfile {
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
    pub fn resolve(raw: Vec<RawWAFProfile>) -> anyhow::Result<HashMap<String, WAFProfile>> {
        raw.into_iter().map(convert_entry).collect()
    }
}

fn convert_signature(entry: &WAFSignature) -> anyhow::Result<Pattern> {
    Ok(Pattern::with_flags(
        &entry.operand,
        CompileFlags::MULTILINE | CompileFlags::DOTALL | CompileFlags::CASELESS,
    )?)
}

pub fn resolve_signatures(raws: Vec<WAFSignature>) -> anyhow::Result<WAFSignatures> {
    let patterns: anyhow::Result<Vec<Pattern>> = raws.iter().map(convert_signature).collect();
    let ptrns: Patterns = Patterns::from_iter(patterns?);
    Ok(WAFSignatures {
        db: ptrns.build::<Vectored>()?,
        ids: raws,
    })
}
