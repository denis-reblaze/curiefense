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

use hostmap::{HostMap, UrlMap};
use limit::{limit_order, Limit};
use profiling::ProfilingSection;
use raw::{ACLProfile, RawHostMap, RawLimit, RawProfilingSection, RawUrlMap, RawWAFProfile};
use utils::Matching;
use waf::{resolve_signatures, WAFProfile, WAFSignatures};

lazy_static! {
    pub static ref CONFIG: RwLock<Config> = RwLock::new(Config::empty());
    pub static ref HSDB: RwLock<Option<WAFSignatures>> = RwLock::new(None);
}

pub fn get_config(basepath: &str) -> (Config, Vec<anyhow::Error>) {
    // cloned to release the lock - this might be horribly expensive though
    // TODO: somehow work with a reference to that data
    let mut errs = Vec::new();
    let mconfig = match CONFIG.read() {
        Ok(cfg) => cfg.clone(),
        Err(rr) => {
            errs.push(anyhow!("{}", rr));
            Config::empty()
        }
    };
    match mconfig.reload(basepath) {
        (None, nerrs) => {
            errs.extend(nerrs);
            (mconfig, errs)
        }
        (Some((newconfig, hsdb)), nerrs) => {
            errs.extend(nerrs);
            match CONFIG.write() {
                Ok(mut w) => {
                    println!("Updating configuration!");
                    *w = newconfig.clone();
                }
                Err(rr) => errs.push(anyhow!("{}", rr)),
            };
            match HSDB.write() {
                Ok(mut dbw) => *dbw = Some(hsdb),
                Err(rr) => errs.push(anyhow!("{}", rr)),
            };
            (newconfig, errs)
        }
    }
}

pub fn get_config_default_path() -> (Config, Vec<anyhow::Error>) {
    get_config("/config/current/config")
}

#[derive(Debug, Clone)]
pub struct Config {
    pub urlmaps: Vec<Matching<HostMap>>,
    pub profiling: Vec<ProfilingSection>,
    pub default: Option<HostMap>,
    pub last_mod: SystemTime,
    pub container_name: Option<String>,
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

        (
            Config {
                urlmaps,
                default,
                last_mod,
                profiling,
                container_name,
            },
            errs,
        )
    }

    fn load_config_file<A: serde::de::DeserializeOwned>(
        base: &Path,
        fname: &str,
    ) -> anyhow::Result<A> {
        let mut path = base.to_path_buf();
        path.push(fname);
        let fullpath = path.to_str().unwrap_or(fname).to_string();
        let file =
            std::fs::File::open(path).map_err(|rr| anyhow!("when loading {}: {}", fullpath, rr))?;
        serde_json::from_reader(std::io::BufReader::new(file))
            .map_err(|rr| anyhow!("when deserializing {}: {}", fullpath, rr))
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

        let urlmap = Config::load_config_file(&bjson, "urlmap.json").unwrap_or_else(|rr| {
            errs.push(rr);
            Vec::new()
        });
        let profiling =
            Config::load_config_file(&bjson, "profiling-lists.json").unwrap_or_else(|rr| {
                errs.push(rr);
                Vec::new()
            });
        let limits = Config::load_config_file(&bjson, "limits.json").unwrap_or_else(|rr| {
            errs.push(rr);
            Vec::new()
        });
        let acls = Config::load_config_file(&bjson, "acl-profiles.json").unwrap_or_else(|rr| {
            errs.push(rr);
            Vec::new()
        });
        let wafprofiles =
            Config::load_config_file(&bjson, "waf-profiles.json").unwrap_or_else(|rr| {
                errs.push(rr);
                Vec::new()
            });
        let wafsignatures =
            Config::load_config_file(&bjson, "waf-signatures.json").unwrap_or_else(|rr| {
                errs.push(rr);
                Vec::new()
            });
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
        }
    }
}
