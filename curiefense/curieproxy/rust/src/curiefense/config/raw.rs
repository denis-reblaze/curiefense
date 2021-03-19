/// this module contains types that map to the the JSON configuration format of curiefense configuration files
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// a mapping of the configuration file for url map entries
/// it is called "urlmap" in the lua code
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawHostMap {
    #[serde(rename = "match")]
    pub match_: String,
    pub id: String,
    pub name: String,
    pub map: Vec<RawUrlMap>,
}

/// a mapping of the configuration file for url maps
/// it is called "urlmap-entry" in the lua code
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawUrlMap {
    #[serde(rename = "match")]
    pub match_: String,
    pub name: String,
    pub acl_profile: String,
    pub waf_profile: String,
    pub acl_active: bool,
    pub waf_active: bool,
    pub limit_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    AND,
    OR,
}

/// this is partial, as a ton of data is not needed
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawProfilingSection {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub tags: Vec<String>,
    pub rule: RawProfilingRule,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawProfilingRule {
    pub relation: Relation,
    pub sections: Vec<RawProfilingSSection>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ProfilingEntryType {
    Args,
    Cookies,
    Headers,
    Path,
    Query,
    Uri,
    Asn,
    Country,
    Method,
    Ip,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawProfilingSSection {
    pub relation: Relation,
    pub entries: Vec<(ProfilingEntryType, serde_json::Value, String)>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawLimit {
    pub id: String,
    pub name: String,
    pub limit: String,
    pub ttl: String,
    #[serde(default)]
    pub key: Vec<HashMap<String, String>>,
    #[serde(default)]
    pub include: RawLimitSelector,
    #[serde(default)]
    pub exclude: RawLimitSelector,
    pub pairwith: HashMap<String, String>,
    pub action: RawAction,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawLimitSelector {
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub cookies: HashMap<String, String>,
    #[serde(default)]
    pub args: HashMap<String, String>,
    #[serde(default)]
    pub attrs: HashMap<String, String>,
}

impl std::default::Default for RawLimitSelector {
    fn default() -> Self {
        RawLimitSelector {
            headers: HashMap::new(),
            cookies: HashMap::new(),
            args: HashMap::new(),
            attrs: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawAction {
    #[serde(rename = "type", default)]
    pub type_: RawActionType,
    #[serde(default)]
    pub params: RawActionParams,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum RawActionType {
    Default,
    Ban,
    Response,
    Challenge,
    Redirect,
    Monitor,
    RequestHeader,
}

impl std::default::Default for RawActionType {
    fn default() -> Self {
        RawActionType::Default
    }
}

fn get_false() -> bool {
    false
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawActionParams {
    pub status: Option<String>,
    #[serde(default = "get_false")]
    pub block_mode: bool,
    pub action: Option<Box<RawAction>>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub reason: Option<String>,
    pub content: Option<String>,
}

impl std::default::Default for RawActionParams {
    fn default() -> Self {
        RawActionParams {
            status: None,
            block_mode: true,
            action: None,
            headers: HashMap::new(),
            reason: None,
            content: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ACLProfile {
    pub id: String,
    pub name: String,
    pub allow: HashSet<String>,
    pub allow_bot: HashSet<String>,
    pub deny: HashSet<String>,
    pub deny_bot: HashSet<String>,
    pub bypass: HashSet<String>,
    pub force_deny: HashSet<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawWAFProfile {
    pub id: String,
    pub name: String,
    pub ignore_alphanum: bool,
    pub max_header_length: usize,
    pub max_cookie_length: usize,
    pub max_arg_length: usize,
    pub max_headers_count: usize,
    pub max_cookies_count: usize,
    pub max_args_count: usize,
    pub args: RawWAFProperties,
    pub headers: RawWAFProperties,
    pub cookies: RawWAFProperties,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawWAFProperties {
    pub names: Vec<RawWAFEntryMatch>,
    pub regex: Vec<RawWAFEntryMatch>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawWAFEntryMatch {
    pub key: String,
    pub reg: Option<String>,
    pub restrict: bool,
    pub mask: bool,
    pub exclusions: Option<HashMap<String, u64>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WAFSignature {
    pub id: String,
    pub name: String,
    pub msg: String,
    pub operand: String,
    pub severity: u8,
    pub certainity: u8,
    pub category: String,
    pub subcategory: String,
}
