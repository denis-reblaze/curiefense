use regex::Regex;

#[derive(Debug, Clone)]
pub enum RequestSelector {
    Ip,
    Path,
    Query,
    Uri,
    Country,
    Method,
    Asn,
    Args(String),
    Cookie(String),
    Header(String),
}

#[derive(Debug, Clone)]
pub enum RequestSelectorCondition {
    N(RequestSelector, Regex),
    Tag(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SelectorType {
    Headers,
    Cookies,
    Args,
    Attrs,
}

// all kind of selector related functions
pub fn decode_attribute(s: &str) -> Option<RequestSelector> {
    match s {
        "ip" => Some(RequestSelector::Ip),
        "path" => Some(RequestSelector::Path),
        "query" => Some(RequestSelector::Query),
        "uri" => Some(RequestSelector::Uri),
        "country" => Some(RequestSelector::Country),
        "method" => Some(RequestSelector::Method),
        "asn" => Some(RequestSelector::Asn),
        _ => None,
    }
}

fn resolve_selector_type(k: &str) -> anyhow::Result<SelectorType> {
    match k {
        "headers" => Ok(SelectorType::Headers),
        "cookies" => Ok(SelectorType::Cookies),
        "args" => Ok(SelectorType::Args),
        "attrs" => Ok(SelectorType::Attrs),
        _ => Err(anyhow::anyhow!("Unknown selector type {}", k)),
    }
}

pub fn resolve_selector_raw(k: &str, v: &str) -> anyhow::Result<RequestSelector> {
    let st = resolve_selector_type(k)?;
    resolve_selector(st, v)
}

pub fn resolve_selector(tp: SelectorType, v: &str) -> anyhow::Result<RequestSelector> {
    match tp {
        SelectorType::Headers => Ok(RequestSelector::Header(v.to_string())),
        SelectorType::Cookies => Ok(RequestSelector::Cookie(v.to_string())),
        SelectorType::Args => Ok(RequestSelector::Args(v.to_string())),
        SelectorType::Attrs => {
            decode_attribute(v).ok_or_else(|| anyhow::anyhow!("Unknown attribute {}", v))
        }
    }
}

pub fn decode_request_selector_condition(
    tp: SelectorType,
    v: &str,
    cond: &str,
) -> anyhow::Result<RequestSelectorCondition> {
    if tp == SelectorType::Attrs && v == "tags" {
        Ok(RequestSelectorCondition::Tag(cond.to_string()))
    } else {
        let sel = resolve_selector(tp, v)?;
        let re = anchored_re(cond)?;
        Ok(RequestSelectorCondition::N(sel, re))
    }
}

#[derive(Debug, Clone)]
pub struct Matching<A> {
    pub matcher: Regex,
    pub inner: A,
}

// make sure regexes are anchored
pub fn anchored_re(i: &str) -> Result<Regex, regex::Error> {
    let mut s: String = i.to_string();
    if !s.starts_with('^') {
        s = "^".to_string() + &s;
    }
    if !s.ends_with('$') {
        s += "$";
    }
    Regex::new(&s)
}
