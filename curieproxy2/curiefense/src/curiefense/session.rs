// This module exposes a session based API for the matching system
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::curiefense::config::{get_config_default_path, CONFIG};
use crate::curiefense::interface::Tags;
use crate::curiefense::utils::{EnvoyMeta, GeoIp, QueryInfo, RInfo};
use crate::{match_urlmap, Config, RequestInfo, UrlMap};

// Session stuff, the key is the session id
lazy_static! {
    static ref RAW: RwLock<HashMap<Uuid, serde_json::Value>> = RwLock::new(HashMap::new());
    static ref RINFOS: RwLock<HashMap<Uuid, RequestInfo>> = RwLock::new(HashMap::new());
    static ref TAGS: RwLock<HashMap<Uuid, Tags>> = RwLock::new(HashMap::new());
    static ref URLMAP: RwLock<HashMap<Uuid, UrlMap>> = RwLock::new(HashMap::new());
}

/// json representation of the useful fields in the request map
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JRequestMap {
    headers: HashMap<String, String>,
    cookies: HashMap<String, String>,
    args: HashMap<String, String>,
    attrs: JAttrs,
}

/// json representation of the useful fields in attrs
#[derive(Debug, Deserialize, Serialize, Clone)]
struct JAttrs {
    path: String,
    method: String,
    ip: String,
    query: String,
    authority: Option<String>,
    uri: String,
    tags: HashMap<String, serde_json::Value>,
}

impl JRequestMap {
    fn into_request_info(self) -> (RequestInfo, Tags) {
        let host: String = self
            .headers
            .get("host")
            .cloned()
            .or_else(|| self.attrs.authority.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let parsed_ip = self.attrs.ip.parse().ok();
        let geoip = GeoIp {
            ipstr: self.attrs.ip,
            ip: parsed_ip,
            country: None,
            city: None,
            asn: None,
            country_name: None,
        };
        let meta = EnvoyMeta {
            authority: self.attrs.authority,
            method: self.attrs.method,
            path: self.attrs.uri.clone(), // this is wrong, uri should be url-encoded back
            extra: HashMap::new(),
        };
        let qinfo = QueryInfo {
            qpath: self.attrs.path,
            query: self.attrs.query,
            uri: Some(self.attrs.uri),
            args: self.args,
        };
        let vtags: Vec<String> = self.attrs.tags.into_iter().map(|(k, _)| k).collect();
        (
            RequestInfo {
                cookies: self.cookies,
                headers: self.headers,
                rinfo: RInfo {
                    geoip,
                    meta,
                    qinfo,
                    host,
                },
            },
            Tags::from_vec(&vtags),
        )
    }
}

pub fn init_config() -> anyhow::Result<bool> {
    match get_config_default_path() {
        Ok(_) => Ok(true),
        Err(rr) => Err(anyhow::anyhow!("Could not load configuration: {}", rr)),
    }
}

pub fn clean_session(session_id: &str) -> anyhow::Result<()> {
    let uuid: Uuid = session_id.parse()?;
    if let Ok(mut w) = RINFOS.write() {
        w.remove(&uuid);
    }
    if let Ok(mut w) = TAGS.write() {
        w.remove(&uuid);
    }
    if let Ok(mut w) = URLMAP.write() {
        w.remove(&uuid);
    }
    Ok(())
}

pub fn session_serialize_request_map(session_id: &str) -> anyhow::Result<serde_json::Value> {
    let uuid: Uuid = session_id.parse()?;
    // get raw request first
    let mut raw: serde_json::Value = match RAW.read() {
        Ok(raws) => match raws.get(&uuid) {
            Some(v) => v.clone(),
            None => return Err(anyhow::anyhow!("Could not get RAW {}", uuid)),
        },
        Err(rr) => return Err(anyhow::anyhow!("Could not get read lock on RAW {}", rr)),
    };

    // get the tags
    let tags = with_tags(uuid, |tgs| Ok(tgs.clone()))?;

    // update the tags
    let attrs = raw
        .get_mut("attrs")
        .ok_or_else(|| anyhow::anyhow!("No attrs field"))?;
    let attrs_o = attrs
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Attrs was not an object"))?;
    attrs_o.insert("tags".to_string(), serde_json::to_value(tags)?);

    Ok(raw)
}

/// initializes a session from a json-encoded request map
pub fn session_init(encoded_request_map: &str) -> anyhow::Result<String> {
    let jvalue: serde_json::Value =
        serde_json::from_str(encoded_request_map)?;
    let jmap: JRequestMap =
        serde_json::from_value(jvalue.clone())?;
    let (rinfo, tags) = jmap.into_request_info();

    let uuid = Uuid::new_v4();

    let mut raw = RAW
        .write()
        .map_err(|rr| anyhow::anyhow!("Could not get RAW write lock {}", rr))?;
    raw.insert(uuid, jvalue);
    let mut rinfos = RINFOS
        .write()
        .map_err(|rr| anyhow::anyhow!("Could not get RINFOS write lock {}", rr))?;
    rinfos.insert(uuid, rinfo);
    let mut wtags = TAGS
        .write()
        .map_err(|rr| anyhow::anyhow!("Could not get TAGS write lock {}", rr))?;
    wtags.insert(uuid, tags);

    Ok(format!("{}", uuid))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SessionUrlMap {
    pub name: String,
    pub acl_profile: String,
    pub waf_profile: String,
    pub acl_active: bool,
    pub waf_active: bool,
    pub limit_ids: Vec<String>,
    pub urlmap: String
}

/// returns a RawUrlMap object (minus the match field), and updates the internal structure for the url map
pub fn session_match_urlmap(session_id: &str) -> anyhow::Result<SessionUrlMap> {
    let uuid: Uuid = session_id.parse()?;
    // this is done this way in order to release the config lock before writing the tags
    let (hostmap_name, urlmap) = with_config(|cfg| {
        with_request_info(uuid, |rinfo| match match_urlmap(&rinfo, &cfg) {
            Some((hn, urlmap)) => {
                let mut wurlmap = URLMAP
                    .write()
                    .map_err(|rr| anyhow::anyhow!("Could not get TAGS write lock {}", rr))?;
                wurlmap.insert(uuid, urlmap.clone());
                Ok((hn, urlmap.clone()))
            }
            None => Err(anyhow::anyhow!("No matching URL map")),
        })
    })?;
    with_tags_mut(uuid, |tags| {
        tags.insert(&format!("urlmap:{}", hostmap_name.clone()));
        tags.insert(&format!("urlmap-entry:{}", urlmap.name));
        tags.insert(&format!("aclid:{}", urlmap.acl_profile.id));
        tags.insert(&format!("aclname:{}", urlmap.acl_profile.name));
        tags.insert(&format!("wafid:{}", urlmap.waf_profile.name));
        Ok(())
    })?;
    let raw_urlmap = SessionUrlMap {
        name: urlmap.name,
        acl_profile: urlmap.acl_profile.id,
        waf_profile: urlmap.waf_profile.id,
        acl_active: urlmap.acl_active,
        waf_active: urlmap.waf_active,
        limit_ids: urlmap.limits.into_iter().map(|l| l.id).collect(),
        urlmap: hostmap_name
    };
    Ok(raw_urlmap)
}

// HELPERS

fn with_config<F, A>(f: F) -> anyhow::Result<A>
where
    F: FnOnce(&Config) -> anyhow::Result<A>,
{
    match CONFIG.read() {
        Ok(cfg) => f(&cfg),
        Err(rr) => Err(anyhow::anyhow!(
            "Could not get configuration read lock {}",
            rr
        )),
    }
}

fn with_request_info<F, A>(uuid: Uuid, f: F) -> anyhow::Result<A>
where
    F: FnOnce(&RequestInfo) -> anyhow::Result<A>,
{
    let infos = RINFOS
        .read()
        .map_err(|rr| anyhow::anyhow!("Could not get RINFOS read lock {}", rr))?;
    let rinfo = infos
        .get(&uuid)
        .ok_or_else(|| anyhow::anyhow!("Unknown session id"))?;
    f(rinfo)
}

fn with_urlmap<F, A>(uuid: Uuid, f: F) -> anyhow::Result<A>
where
    F: FnOnce(&UrlMap) -> anyhow::Result<A>,
{
    let maps = URLMAP
        .read()
        .map_err(|rr| anyhow::anyhow!("Could not get URLMAP read lock {}", rr))?;
    let umap = maps
        .get(&uuid)
        .ok_or_else(|| anyhow::anyhow!("Unknown session id"))?;
    f(umap)
}

fn with_tags<F, A>(uuid: Uuid, f: F) -> anyhow::Result<A>
where
    F: FnOnce(&Tags) -> anyhow::Result<A>,
{
    let tags = TAGS
        .read()
        .map_err(|rr| anyhow::anyhow!("Could not get TAGS read lock {}", rr))?;
    let tag = tags
        .get(&uuid)
        .ok_or_else(|| anyhow::anyhow!("Unknown session id"))?;
    f(tag)
}

fn with_tags_mut<F, A>(uuid: Uuid, f: F) -> anyhow::Result<A>
where
    F: FnOnce(&mut Tags) -> anyhow::Result<A>,
{
    let mut tags = TAGS
        .write()
        .map_err(|rr| anyhow::anyhow!("Could not get TAGS read lock {}", rr))?;
    let tag = tags
        .get_mut(&uuid)
        .ok_or_else(|| anyhow::anyhow!("Unknown session id"))?;
    f(tag)
}
