use crate::curiefense::config::raw::{RawAction, RawActionType};
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
    pub headers: HashMap<String, String>,
    pub initiator: String,
    pub reason: String,
    pub content: String,
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
            status: 503,
            headers: [("x-curiefense".to_string(), "response".to_string())]
                .iter()
                .cloned()
                .collect(),
            initiator: "undefined".to_string(),
            reason: "undefined".to_string(),
            content: "curiefense - request denied".to_string(),
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
