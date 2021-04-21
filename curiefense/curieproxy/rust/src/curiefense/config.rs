pub mod flow;
pub mod hostmap;
pub mod limit;
pub mod profiling;
pub mod raw;
pub mod utils;
pub mod waf;

use anyhow::anyhow;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::SystemTime;

use flow::{flow_resolve, FlowElement, SequenceKey};
use hostmap::{HostMap, UrlMap};
use limit::{limit_order, Limit};
use profiling::ProfilingSection;
use raw::{
    ACLProfile, RawFlowEntry, RawHostMap, RawLimit, RawProfilingSection, RawUrlMap, RawWAFProfile,
};
use utils::Matching;
use waf::{resolve_signatures, WAFProfile, WAFSignatures};

lazy_static! {
    pub static ref CONFIG: RwLock<Config> = RwLock::new(Config::empty());
    pub static ref HSDB: RwLock<Option<WAFSignatures>> = RwLock::new(None);
}

pub fn with_config<R, F>(basepath: &str, f: F) -> (Option<R>, Vec<anyhow::Error>)
where
    F: FnOnce(&Config) -> R,
{
    let ((newconfig, newhsdb), mut errs) = match CONFIG.read() {
        Ok(cfg) => match cfg.reload(basepath) {
            (None, nerrs) => return (Some(f(&cfg)), nerrs),
            (Some(cfginfo), nerrs) => (cfginfo, nerrs),
        },
        Err(rr) =>
        // read failed :(
        {
            return (None, vec![anyhow!("{}", rr)])
        }
    };
    let r = f(&newconfig);
    match CONFIG.write() {
        Ok(mut w) => *w = newconfig,
        Err(rr) => errs.push(anyhow!("{}", rr)),
    };
    match HSDB.write() {
        Ok(mut dbw) => *dbw = Some(newhsdb),
        Err(rr) => errs.push(anyhow!("{}", rr)),
    };
    (Some(r), errs)
}

pub fn with_config_default_path<R, F>(f: F) -> (Option<R>, Vec<anyhow::Error>)
where
    F: FnOnce(&Config) -> R,
{
    with_config("/config/current/config", f)
}

#[derive(Debug, Clone)]
pub struct Config {
    pub urlmaps: Vec<Matching<HostMap>>,
    pub profiling: Vec<ProfilingSection>,
    pub default: Option<HostMap>,
    pub last_mod: SystemTime,
    pub container_name: Option<String>,
    pub flows: HashMap<SequenceKey, Vec<FlowElement>>,
}

fn from_map<V: Clone>(mp: &HashMap<String, V>, k: &str) -> anyhow::Result<V> {
    mp.get(k)
        .cloned()
        .ok_or_else(|| anyhow!("id not found: {}", k))
}

impl Config {
    fn resolve_url_maps(
        rawmaps: Vec<RawUrlMap>,
        limits: &HashMap<String, Limit>,
        acls: &HashMap<String, ACLProfile>,
        wafprofiles: &HashMap<String, WAFProfile>,
    ) -> (Vec<Matching<UrlMap>>, Option<UrlMap>, Vec<anyhow::Error>) {
        let mut default: Option<UrlMap> = None;
        let mut entries: Vec<Matching<UrlMap>> = Vec::new();
        let mut errs = Vec::new();

        for rawmap in rawmaps {
            let acl_profile: ACLProfile = match acls.get(&rawmap.acl_profile) {
                Some(p) => p.clone(),
                None => {
                    errs.push(anyhow!("Unknown ACL profile {}", &rawmap.acl_profile));
                    ACLProfile::default()
                }
            };
            let waf_profile: WAFProfile = match wafprofiles.get(&rawmap.waf_profile) {
                Some(p) => p.clone(),
                None => {
                    errs.push(anyhow!("Unknown WAF profile {}", &rawmap.waf_profile));
                    WAFProfile::default()
                }
            };
            let mut olimits: Vec<Limit> = Vec::new();
            for lid in rawmap.limit_ids {
                match from_map(&limits, &lid) {
                    Ok(lm) => olimits.push(lm),
                    Err(rr) => errs.push(rr),
                }
            }
            // limits 0 are tried first, than in decreasing order of the limit field
            olimits.sort_unstable_by(limit_order);
            let mapname = rawmap.name.clone();
            let urlmap = UrlMap {
                acl_active: rawmap.acl_active,
                acl_profile,
                waf_active: rawmap.waf_active,
                waf_profile,
                limits: olimits,
                name: rawmap.name,
            };
            if rawmap.match_ == "__default__" {
                default = Some(urlmap);
            } else {
                match Regex::new(&rawmap.match_) {
                    Err(rr) => errs.push(anyhow!(
                        "Invalid regex {} in entry {}: {}",
                        &rawmap.match_,
                        &mapname,
                        rr
                    )),
                    Ok(matcher) => entries.push(Matching {
                        matcher,
                        inner: urlmap,
                    }),
                };
            }
        }

        (entries, default, errs)
    }

    fn resolve(
        last_mod: SystemTime,
        rawmaps: Vec<RawHostMap>,
        rawlimits: Vec<RawLimit>,
        rawprofiling: Vec<RawProfilingSection>,
        rawacls: Vec<ACLProfile>,
        rawwafprofiles: Vec<RawWAFProfile>,
        container_name: Option<String>,
        rawflows: Vec<RawFlowEntry>,
    ) -> (Config, Vec<anyhow::Error>) {
        let mut default: Option<HostMap> = None;
        let mut urlmaps: Vec<Matching<HostMap>> = Vec::new();
        let mut errs: Vec<anyhow::Error> = Vec::new();

        let (limits, lerrs) = Limit::resolve(rawlimits);
        errs.extend(lerrs);
        let (wafprofiles, werrs) = WAFProfile::resolve(rawwafprofiles);
        errs.extend(werrs);
        let acls = rawacls.into_iter().map(|a| (a.id.clone(), a)).collect();

        // build the entries while looking for the default entry
        for rawmap in rawmaps {
            let (entries, default_entry, eerrs) =
                Config::resolve_url_maps(rawmap.map, &limits, &acls, &wafprofiles);
            errs.extend(eerrs);
            let mapname = rawmap.name.clone();
            let hostmap = HostMap {
                id: rawmap.id,
                name: rawmap.name,
                entries,
                default: default_entry,
            };
            if rawmap.match_ == "__default__" {
                if default.is_some() {
                    println!("overwriting default entry!");
                }
                default = Some(hostmap);
            } else {
                match Regex::new(&rawmap.match_) {
                    Err(rr) => errs.push(anyhow!(
                        "Invalid regex {} in entry {}: {}",
                        &rawmap.match_,
                        mapname,
                        rr
                    )),
                    Ok(matcher) => urlmaps.push(Matching {
                        matcher,
                        inner: hostmap,
                    }),
                }
            }
        }

        let (profiling, perrs) = ProfilingSection::resolve(rawprofiling);
        errs.extend(perrs);

        let (flows, ferrs) = flow_resolve(rawflows);
        errs.extend(ferrs);

        (
            Config {
                urlmaps,
                default,
                last_mod,
                profiling,
                container_name,
                flows,
            },
            errs,
        )
    }

    fn load_config_file<A: serde::de::DeserializeOwned>(
        base: &Path,
        fname: &str,
        errs: &mut Vec<anyhow::Error>,
    ) -> Vec<A> {
        let mut path = base.to_path_buf();
        path.push(fname);
        let fullpath = path.to_str().unwrap_or(fname).to_string();
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(rr) => {
                errs.push(anyhow!("when loading {}: {}", fullpath, rr));
                return Vec::new();
            }
        };
        let values: Vec<serde_json::Value> =
            match serde_json::from_reader(std::io::BufReader::new(file)) {
                Ok(vs) => vs,
                Err(rr) => {
                    // if it is not a json array, abort early and do not resolve anything
                    errs.push(anyhow!("when loading {}: {}", fullpath, rr));
                    return Vec::new();
                }
            };
        let mut out = Vec::new();
        for value in values {
            // for each entry, try to resolve it as a raw configuration value, failing otherwise
            match serde_json::from_value(value) {
                Err(rr) => errs.push(anyhow!("when loading {}: {}", fullpath, rr)),
                Ok(v) => out.push(v),
            }
        }
        out
    }

    pub fn reload(&self, basepath: &str) -> (Option<(Config, WAFSignatures)>, Vec<anyhow::Error>) {
        let mut errs = Vec::new();

        let last_mod = std::fs::metadata(basepath)
            .and_then(|x| x.modified())
            .unwrap_or_else(|rr| {
                errs.push(anyhow!(
                    "Could not get last modified time for {}: {}",
                    basepath,
                    rr
                ));
                SystemTime::now()
            });
        if self.last_mod == last_mod {
            return (None, errs);
        }

        let mut bjson = PathBuf::from(basepath);
        bjson.push("json");

        let urlmap = Config::load_config_file(&bjson, "urlmap.json", &mut errs);
        let profiling = Config::load_config_file(&bjson, "profiling-lists.json", &mut errs);
        let limits = Config::load_config_file(&bjson, "limits.json", &mut errs);
        let acls = Config::load_config_file(&bjson, "acl-profiles.json", &mut errs);
        let wafprofiles = Config::load_config_file(&bjson, "waf-profiles.json", &mut errs);
        let wafsignatures = Config::load_config_file(&bjson, "waf-signatures.json", &mut errs);
        let flows = Config::load_config_file(&bjson, "flow-control.json", &mut errs);

        let container_name = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string());
        let hsdb = resolve_signatures(wafsignatures).unwrap_or_else(|rr| {
            errs.push(rr);
            WAFSignatures::empty()
        });
        let (config, cerrs) = Config::resolve(
            last_mod,
            urlmap,
            limits,
            profiling,
            acls,
            wafprofiles,
            container_name,
            flows,
        );
        errs.extend(cerrs);
        (Some((config, hsdb)), errs)
    }

    pub fn empty() -> Config {
        Config {
            urlmaps: Vec::new(),
            profiling: Vec::new(),
            last_mod: SystemTime::UNIX_EPOCH,
            default: None,
            container_name: None,
            flows: HashMap::new(),
        }
    }
}
