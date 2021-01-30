use hyperscan::Matching;
use libinjection::{sqli, xss};
use std::collections::{HashMap, HashSet};

use crate::curiefense::config::waf::{
    Section, SectionIdx, WAFEntryMatch, WAFProfile, WAFSection, WAFSignatures,
};
use crate::curiefense::interface::{Action, ActionType};
use crate::RequestInfo;

#[derive(Debug, Clone)]
pub struct WAFMatched {
    pub section: SectionIdx,
    pub name: String,
    pub value: String,
}

impl WAFMatched {
    fn new(section: SectionIdx, name: String, value: String) -> Self {
        WAFMatched {
            section,
            name,
            value,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WAFMatch {
    pub matched: WAFMatched,
    pub ids: Vec<u32>,
}

#[derive(Debug, Clone)]
pub enum WAFBlock {
    TooManyEntries(SectionIdx),
    EntryTooLarge(SectionIdx, String),
    Mismatch(WAFMatched),
    SQLi(WAFMatched, String), // fingerprint
    XSS(WAFMatched),
    Policies(Vec<WAFMatch>),
}

impl WAFBlock {
    pub fn to_action(&self) -> Action {
        Action {
            atype: ActionType::Block,
            ban: false,
            status: 503,
            headers: HashMap::new(),
            initiator: "WAF".to_string(),
            reason: "denied".to_string(),
            content: "Access denied".to_string(),
        }
    }
}

struct Omitted {
    entries: Section<HashSet<String>>,
    exclusions: Section<HashMap<String, HashSet<String>>>,
}

impl Default for Omitted {
    fn default() -> Self {
        Omitted {
            entries: Default::default(),
            exclusions: Default::default(),
        }
    }
}

/// Runs the WAF part of curiefense
///
/// TODO:
/// * resolve hyperscan matches into policies
/// * handle excluded waf policies
pub fn waf_check(
    rinfo: &RequestInfo,
    profile: &WAFProfile,
    hsdb: std::sync::RwLockReadGuard<Option<WAFSignatures>>,
) -> Result<(), WAFBlock> {
    use SectionIdx::*;
    let mut omit = Default::default();

    let getsection = |idx| match idx {
        Headers => &rinfo.headers,
        Cookies => &rinfo.cookies,
        Args => &rinfo.rinfo.qinfo.args,
    };

    // check section profiles
    for idx in &[Headers, Cookies, Args] {
        section_check(
            *idx,
            profile.sections.get(*idx),
            getsection(*idx),
            profile.ignore_alphanum,
            &mut omit,
        )?;
    }

    let mut hca_keys: HashMap<String, (SectionIdx, String)> = HashMap::new();

    // run libinjection on non-whitelisted sections
    for idx in &[Headers, Cookies, Args] {
        injection_check(*idx, getsection(*idx), &omit, &mut hca_keys)?;
    }

    // finally, hyperscan check
    match hyperscan(hca_keys, hsdb, &omit.exclusions) {
        Err(rr) => {
            println!("Hyperscan failed {}", rr);
            Ok(())
        }
        Ok(None) => Ok(()),
        Ok(Some(block)) => Err(block),
    }
}

/// checks a section (headers, args, cookies) against the policy
fn section_check(
    idx: SectionIdx,
    section: &WAFSection,
    params: &HashMap<String, String>,
    ignore_alphanum: bool,
    omit: &mut Omitted,
) -> Result<(), WAFBlock> {
    if params.len() >= section.max_count {
        return Err(WAFBlock::TooManyEntries(idx));
    }

    for (name, value) in params {
        if value.len() >= section.max_length {
            return Err(WAFBlock::EntryTooLarge(idx, name.clone()));
        }

        // automatically ignored
        if ignore_alphanum && value.chars().all(|c| c.is_ascii_alphanumeric()) {
            omit.entries.at(idx).insert(name.clone());
            continue;
        }

        // logic for checking an entry
        let mut check_entry = |name_entry: &WAFEntryMatch| {
            let matched = if let Some(re) = &name_entry.reg {
                re.is_match(value)
            } else {
                false
            };
            if matched {
                omit.entries.at(idx).insert(name.clone());
            } else if name_entry.restrict {
                return Err(WAFBlock::Mismatch(WAFMatched::new(
                    idx,
                    name.clone(),
                    value.clone(),
                )));
            } else if !name_entry.exclusions.is_empty() {
                omit.exclusions
                    .at(idx)
                    .insert(name.clone(), name_entry.exclusions.clone());
            }
            Ok(())
        };

        // check name rules
        for entry in section.names.get(name).iter() {
            check_entry(entry)?;
        }

        // // check regex rules
        for entry in section
            .regex
            .iter()
            .filter_map(|(re, v)| if re.is_match(name) { Some(v) } else { None })
        {
            check_entry(entry)?;
        }
    }

    Ok(())
}

fn injection_check(
    idx: SectionIdx,
    params: &HashMap<String, String>,
    omit: &Omitted,
    hca_keys: &mut HashMap<String, (SectionIdx, String)>,
) -> Result<(), WAFBlock> {
    for (name, value) in params {
        if !omit.entries.get(idx).contains(name) {
            if !omit
                .exclusions
                .get(idx)
                .get(name)
                .map(|st| st.contains("libinjection"))
                .unwrap_or(false)
            {
                if let Some((b, fp)) = sqli(value) {
                    if b {
                        return Err(WAFBlock::SQLi(
                            WAFMatched::new(idx, name.clone(), value.clone()),
                            fp,
                        ));
                    }
                }
                if let Some(b) = xss(value) {
                    if b {
                        return Err(WAFBlock::XSS(WAFMatched::new(
                            idx,
                            name.clone(),
                            value.clone(),
                        )));
                    }
                }
            }

            hca_keys.insert(value.clone(), (idx, name.clone()));
        }
    }

    Ok(())
}

fn hyperscan(
    hca_keys: HashMap<String, (SectionIdx, String)>,
    hsdb: std::sync::RwLockReadGuard<Option<WAFSignatures>>,
    exclusions: &Section<HashMap<String, HashSet<String>>>,
) -> anyhow::Result<Option<WAFBlock>> {
    let sigs = match &*hsdb {
        None => return Err(anyhow::anyhow!("Hyperscan database not loaded")),
        Some(x) => x,
    };
    let scratch = sigs.db.alloc_scratch()?;
    let to_scan = hca_keys.keys().map(|s| s.as_bytes());
    let mut found = false;
    sigs.db.scan(to_scan, &scratch, |_, _, _, _| {
        found = true;
        Matching::Continue
    })?;
    if !found {
        return Ok(None);
    }

    let mut matches = Vec::new();

    // something matched! but what?
    for (k, (sid, name)) in hca_keys {
        let mut ids = Vec::new();
        sigs.db.scan(&[k.as_bytes()], &scratch, |id, _, _, _| {
            // TODO this is really ugly, the string hashmap should be converted into a numeric id, or it should be a string in the first place?
            match sigs.ids.get(id as usize) {
                None => println!("INVALID INDEX ??? {}", id),
                Some(real_id) => {
                    if exclusions
                        .get(sid)
                        .get(&name)
                        .map(|ex| ex.contains(&format!("{}", real_id)))
                        != Some(true)
                    {
                        ids.push(*real_id);
                    }
                }
            }
            Matching::Continue
        })?;
        if !ids.is_empty() {
            matches.push(WAFMatch {
                matched: WAFMatched::new(sid, name, k),
                ids,
            })
        }
    }
    Ok(if matches.is_empty() {
        None
    } else {
        Some(WAFBlock::Policies(matches))
    })
}
