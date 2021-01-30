pub mod hostmap;
pub mod limit;
pub mod profiling;
pub mod raw;
pub mod utils;
pub mod waf;

use anyhow::Context;
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use hostmap::{HostMap, UrlMap};
use limit::{limit_order, Limit};
use profiling::ProfilingSection;
use raw::{ACLProfile, RawHostMap, RawLimit, RawProfilingSection, RawUrlMap, RawWAFProfile};
use utils::Matching;
use waf::{resolve_signatures, WAFProfile, WAFSignatures};

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
        .ok_or_else(|| anyhow::anyhow!("id not found: {}", k))
}

impl Config {
    fn resolve_url_maps(
        rawmaps: Vec<RawUrlMap>,
        limits: &HashMap<String, Limit>,
        acls: &HashMap<String, ACLProfile>,
        wafprofiles: &HashMap<String, WAFProfile>,
    ) -> anyhow::Result<(Vec<Matching<UrlMap>>, Option<UrlMap>)> {
        let mut default: Option<UrlMap> = None;
        let mut entries: Vec<Matching<UrlMap>> = Vec::new();

        for rawmap in rawmaps {
            let acl_profile: ACLProfile = acls
                .get(&rawmap.acl_profile)
                .ok_or_else(|| anyhow::anyhow!("Unknown ACL profile {}", &rawmap.acl_profile))?
                .clone();
            let waf_profile: WAFProfile = wafprofiles
                .get(&rawmap.waf_profile)
                .ok_or_else(|| anyhow::anyhow!("Unknown WAF profile {}", &rawmap.waf_profile))?
                .clone();
            let mlimits: anyhow::Result<Vec<Limit>> = rawmap
                .limit_ids
                .iter()
                .map(|i| from_map(&limits, i))
                .collect();
            let mut limits = mlimits?;
            // limits 0 are tried first, than in decreasing order of the limit field
            limits.sort_unstable_by(limit_order);
            let urlmap = UrlMap {
                acl_active: rawmap.acl_active,
                acl_profile,
                waf_active: rawmap.waf_active,
                waf_profile,
                limits,
                name: rawmap.name,
            };
            if rawmap.match_ == "__default__" {
                default = Some(urlmap);
            } else {
                entries.push(Matching {
                    matcher: Regex::new(&rawmap.match_)?,
                    inner: urlmap,
                });
            }
        }

        Ok((entries, default))
    }

    fn resolve(
        last_mod: SystemTime,
        rawmaps: Vec<RawHostMap>,
        rawlimits: Vec<RawLimit>,
        rawprofiling: Vec<RawProfilingSection>,
        rawacls: Vec<ACLProfile>,
        rawwafprofiles: Vec<RawWAFProfile>,
        container_name: Option<String>,
    ) -> anyhow::Result<Config> {
        let mut default: Option<HostMap> = None;
        let mut urlmaps: Vec<Matching<HostMap>> = Vec::new();

        let limits = Limit::resolve(rawlimits)?;
        let wafprofiles = WAFProfile::resolve(rawwafprofiles)?;
        let acls = rawacls.into_iter().map(|a| (a.id.clone(), a)).collect();

        // build the entries while looking for the default entry
        for rawmap in rawmaps {
            let (entries, default_entry) =
                Config::resolve_url_maps(rawmap.map, &limits, &acls, &wafprofiles)?;
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
                urlmaps.push(Matching {
                    matcher: Regex::new(&rawmap.match_)?,
                    inner: hostmap,
                });
            }
        }

        Ok(Config {
            urlmaps,
            default,
            last_mod,
            profiling: ProfilingSection::resolve(rawprofiling)?,
            container_name,
        })
    }

    fn load_config_file<A: serde::de::DeserializeOwned>(
        base: &PathBuf,
        fname: &str,
    ) -> anyhow::Result<A> {
        let mut path = base.clone();
        path.push(fname);
        let fullpath = path.to_str().unwrap_or(fname).to_string();
        let file =
            std::fs::File::open(path).with_context(|| format!("when loading {}", fullpath))?;
        Ok(serde_json::from_reader(std::io::BufReader::new(file))
            .with_context(|| format!("when deserializing {}", fullpath))?)
    }

    pub fn reload(&self, basepath: &str) -> anyhow::Result<Option<(Config, WAFSignatures)>> {
        let md = std::fs::metadata(basepath)?;
        let last_mod = md.modified()?;
        if self.last_mod == last_mod {
            return Ok(None);
        }

        let mut bjson = PathBuf::from(basepath);
        bjson.push("json");

        let urlmap = Config::load_config_file(&bjson, "urlmap.json")?;
        let profiling = Config::load_config_file(&bjson, "profiling-lists.json")?;
        let limits = Config::load_config_file(&bjson, "limits.json")?;
        let acls = Config::load_config_file(&bjson, "acl-profiles.json")?;
        let wafprofiles = Config::load_config_file(&bjson, "waf-profiles.json")?;
        let wafsignatures = Config::load_config_file(&bjson, "waf-signatures.json")?;
        let container_name = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string());
        let hsdb = resolve_signatures(wafsignatures)?;

        Ok(Some((
            Config::resolve(
                last_mod,
                urlmap,
                limits,
                profiling,
                acls,
                wafprofiles,
                container_name,
            )?,
            hsdb,
        )))
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
