use anyhow::Context;
use std::cmp::Ordering;
use std::collections::HashMap;

use crate::curiefense::config::raw::{RawLimit, RawLimitSelector};
use crate::curiefense::config::utils::{
    decode_request_selector_condition, resolve_selector_raw, RequestSelector,
    RequestSelectorCondition, SelectorType,
};
use crate::curiefense::interface::Action;

#[derive(Debug, Clone)]
pub struct Limit {
    pub id: String,
    pub name: String,
    pub limit: u64,
    pub ttl: u64,
    pub action: Action,
    pub exclude: Vec<RequestSelectorCondition>,
    pub include: Vec<RequestSelectorCondition>,
    pub pairwith: Option<RequestSelector>,
    pub key: Vec<RequestSelector>,
}

fn resolve_selector_map(sel: HashMap<String, String>) -> anyhow::Result<RequestSelector> {
    if sel.len() != 1 {
        return Err(anyhow::anyhow!("invalid selector {:?}", sel));
    }
    let (key, val) = sel.into_iter().next().unwrap();
    resolve_selector_raw(&key, &val)
}

fn resolve_selectors(rawsel: RawLimitSelector) -> anyhow::Result<Vec<RequestSelectorCondition>> {
    let mk_selectors = |tp: SelectorType, mp: HashMap<String, String>| {
        mp.into_iter()
            .map(move |(v, cond)| decode_request_selector_condition(tp, &v, &cond))
    };
    mk_selectors(SelectorType::Args, rawsel.args)
        .chain(mk_selectors(SelectorType::Cookies, rawsel.cookies))
        .chain(mk_selectors(SelectorType::Headers, rawsel.headers))
        .chain(mk_selectors(SelectorType::Attrs, rawsel.attrs))
        .collect()
}

impl Limit {
    fn convert(rawlimit: RawLimit) -> anyhow::Result<(String, Limit)> {
        let mkey: anyhow::Result<Vec<RequestSelector>> =
            rawlimit.key.into_iter().map(resolve_selector_map).collect();
        Ok((
            rawlimit.id.clone(),
            Limit {
                id: rawlimit.id,
                name: rawlimit.name,
                limit: rawlimit
                    .limit
                    .parse()
                    .with_context(|| "when converting the limit")?,
                ttl: rawlimit
                    .limit
                    .parse()
                    .with_context(|| "when converting the ttl")?,
                action: Action::resolve(&rawlimit.action)
                    .with_context(|| "when resolving the action entry")?,
                exclude: resolve_selectors(rawlimit.exclude)
                    .with_context(|| "when resolving the exclude entry")?,
                include: resolve_selectors(rawlimit.include)
                    .with_context(|| "when resolving the include entry")?,
                pairwith: resolve_selector_map(rawlimit.pairwith).ok(),
                key: mkey.with_context(|| "when converting the key entry")?,
            },
        ))
    }
    pub fn resolve(rawlimits: Vec<RawLimit>) -> anyhow::Result<HashMap<String, Limit>> {
        rawlimits
            .into_iter()
            .map(|rl| {
                let curid = rl.id.clone();
                Limit::convert(rl).with_context(|| format!("limit id {}", curid))
            })
            .collect()
    }
}

/// order limits, so that 0's come first, and then ordering in descending order
pub fn limit_order(a: &Limit, b: &Limit) -> Ordering {
    match (a.limit, b.limit) {
        (0, 0) => Ordering::Equal,
        (0, _) => Ordering::Less,
        (_, 0) => Ordering::Greater,
        (x, y) => y.cmp(&x), // inverted order
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limit_ordering() {
        fn mklimit(name: &str, v: u64) -> Limit {
            Limit {
                name: name.to_string(),
                limit: v,
                ttl: 0,
                id: String::new(),
                action: Default::default(),
                include: Vec::new(),
                exclude: Vec::new(),
                key: Vec::new(),
                pairwith: None,
            }
        }
        let l1 = mklimit("l1", 0);
        let l2 = mklimit("l2", 8);
        let l3 = mklimit("l3", 4);
        let l4 = mklimit("l4", 1);
        let mut lvec = vec![l3, l2, l1, l4];
        lvec.sort_unstable_by(limit_order);
        let names: Vec<String> = lvec.into_iter().map(|l| l.name).collect();
        let expected: Vec<String> = ["l1", "l2", "l3", "l4"]
            .iter()
            .map(|x| x.to_string())
            .collect();
        assert_eq!(names, expected);
    }
}
