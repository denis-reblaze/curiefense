use crate::curiefense::config::raw::{RawAction, RawActionType};
use serde_json::json;
/// this file contains all the data type that are used when interfacing with a proxy
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub enum Decision {
    Pass,
    /// pass because the Hostmap/Urlmap lacked a default entry
    Action(Action),
}

/// a newtype representing tags, to make sure they are tagified when inserted
#[derive(Debug, Clone)]
pub struct Tags(HashSet<String>);

fn tagify(tag: &str) -> String {
    fn filter_char(c: char) -> char {
        if c.is_ascii_alphanumeric() {
            c
        } else {
            '-'
        }
    }
    tag.chars().map(filter_char).collect()
}

impl Tags {
    pub fn new() -> Self {
        Tags(HashSet::new())
    }

    pub fn insert(&mut self, value: &str) -> bool {
        self.0.insert(tagify(value))
    }

    pub fn extend(&mut self, other: Self) {
        self.0.extend(other.0)
    }

    pub fn from_vec(vec: &[String]) -> Self {
        Tags(vec.iter().map(|s| tagify(&s)).collect())
    }

    pub fn contains(&self, s: &str) -> bool {
        self.0.contains(s)
    }

    pub fn as_hash_ref(&self) -> &HashSet<String> {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub atype: ActionType,
    pub ban: bool,
    pub status: u32,
    pub headers: Option<HashMap<String, String>>,
    pub reason: serde_json::value::Value,
    pub content: String,
    pub extra_tags: Option<HashSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ActionType {
    Monitor,
    Block,
    AlterHeaders,
}

impl std::default::Default for Action {
    fn default() -> Self {
        Action {
            atype: ActionType::Block,
            ban: false,
            status: 403,
            headers: None,
            reason: serde_json::value::Value::Null,
            content: "curiefense - request denied".to_string(),
            extra_tags: None,
        }
    }
}

impl Action {
    pub fn resolve(rawaction: &RawAction) -> anyhow::Result<Action> {
        let mut action = Action::default();
        match rawaction.type_ {
            RawActionType::Default => return Ok(action),
            RawActionType::Monitor => action.atype = ActionType::Monitor,
            RawActionType::Ban => {
                action = rawaction
                    .params
                    .action
                    .as_ref()
                    .map(|x| Action::resolve(x).ok())
                    .flatten()
                    .unwrap_or_default();
                action.ban = true;
            }
            RawActionType::RequestHeader => action.atype = ActionType::AlterHeaders,
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported action type {:?}",
                    rawaction.type_
                ))
            }
        };
        Ok(action)
    }
}

pub trait Grasshopper {
    fn js_app(&self) -> Option<String>;
    fn js_bio(&self) -> Option<String>;
    fn parse_rbzid(&self, rbzid: &str, seed: &str) -> Option<bool>;
    fn gen_new_seed(&self, seed: &str) -> Option<String>;
    fn verify_workproof(&self, workproof: &str, seed: &str) -> Option<String>;
}

pub fn gh_fail_decision(reason: &str) -> Decision {
    Decision::Action(Action {
        atype: ActionType::Block,
        ban: false,
        reason: json!({"initiator": "phase01", "reason": reason}),
        headers: None,
        status: 500,
        content: "internal_error".to_string(),
        extra_tags: None,
    })
}

pub fn challenge_phase01<GH: Grasshopper>(gh: &GH, ua: &str, tags: Vec<String>) -> Decision {
    let seed = match gh.gen_new_seed(ua) {
        None => return gh_fail_decision("could not call gen_new_seed"),
        Some(s) => s,
    };
    let chall_lib = match gh.js_app() {
        None => return gh_fail_decision("could not call chall_lib"),
        Some(s) => s,
    };
    let hdrs: HashMap<String, String> = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Expires", "Thu, 01 Aug 1978 00:01:48 GMT"),
        ("Cache-Control", "no-cache, private, no-transform, no-store"),
        ("Pragma", "no-cache"),
        (
            "P3P",
            "CP=\"IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT\"",
        ),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let mut content = "<html><head><meta charset=\"utf-8\"><script>".to_string();
    content += &chall_lib;
    content += ";;window.rbzns={bereshit: \"1\", seed: \"";
    content += &seed;
    content += "\", storage:\"3\"};winsocks();";
    content += "</script></head><body></body></html>";

    // here humans are accepted, as they were not denied
    // (this would have been caught by the previous guard)
    Decision::Action(Action {
        atype: ActionType::Block,
        ban: false,
        reason: json!({"initiator": "phase01", "reason": "challenge", "tags": tags}),
        headers: Some(hdrs),
        status: 247,
        content,
        extra_tags: Some(
            ["challenge_phase01"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
    })
}

fn extract_zebra(headers: &HashMap<String, String>) -> Option<String> {
    for (k, v) in headers {
        if k.starts_with("x-zebra-") {
            return Some(v.replace('-', "="));
        }
    }
    None
}

pub fn challenge_phase02<GH: Grasshopper>(
    gh: &GH,
    uri: &str,
    headers: &HashMap<String, String>,
) -> Option<Decision> {
    if !uri.starts_with("/7060ac19f50208cbb6b45328ef94140a612ee92387e015594234077b4d1e64f1/") {
        return None;
    }
    let ua = headers.get("user-agent")?;
    let workproof = extract_zebra(headers)?;
    let verified = gh.verify_workproof(&workproof, ua)?;
    let mut nheaders = HashMap::<String, String>::new();
    let mut cookie = "rbzid=".to_string();
    cookie += &verified.replace('=', "-");
    cookie += "; Path=/; HttpOnly";

    nheaders.insert("Set-Cookie".to_string(), cookie);

    Some(Decision::Action(Action {
        atype: ActionType::Block,
        ban: false,
        reason: json!({"initiator": "phase02", "reason": "challenge"}),
        headers: Some(nheaders),
        status: 248,
        content: "{}".to_string(),
        extra_tags: Some(
            ["challenge_phase02"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
    }))
}
