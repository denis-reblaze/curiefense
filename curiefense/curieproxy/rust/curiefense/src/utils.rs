use itertools::Itertools;
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;

pub mod url;

use crate::body::parse_body;
use crate::config::utils::{RequestSelector, RequestSelectorCondition};
use crate::interface::{Decision, Tags};
use crate::logs::Logs;
use crate::maxmind::{get_asn, get_city, get_country};
use crate::requestfields::RequestField;
use crate::utils::url::parse_urlencoded_params;

pub fn cookie_map(cookies: &mut RequestField, cookie: &str) {
    // tries to split the cookie around "="
    fn to_kv(cook: &str) -> (String, String) {
        match cook.splitn(2, '=').collect_tuple() {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (cook.to_string(), String::new()),
        }
    }
    for (k, v) in cookie.split("; ").map(to_kv) {
        cookies.add(k, v);
    }
}

/// Parse raw headers and:
/// * lowercase the header name
/// * extract cookies
///
/// Returns (headers, cookies)
pub fn map_headers(rawheaders: HashMap<String, String>) -> (RequestField, RequestField) {
    let mut cookies = RequestField::default();
    let mut headers = RequestField::default();
    for (k, v) in rawheaders {
        let lk = k.to_lowercase();
        if k == "cookie" {
            cookie_map(&mut cookies, &v);
        } else {
            headers.add(lk, v);
        }
    }

    (headers, cookies)
}

/// parses query parameters, such as
fn parse_query_params(query: &str) -> RequestField {
    let mut rf = RequestField::default();
    parse_urlencoded_params(&mut rf, query);
    rf
}

/// parses the request uri, storing the path and query parts (if possible)
/// returns the hashmap of arguments
fn map_args(logs: &mut Logs, path: &str, mcontent_type: Option<&str>, mbody: Option<&[u8]>) -> QueryInfo {
    // this is necessary to do this in this convoluted way so at not to borrow attrs
    let uri = urlencoding::decode(&path).ok();
    let (qpath, query, mut args) = match path.splitn(2, '?').collect_tuple() {
        Some((qpath, query)) => (qpath.to_string(), query.to_string(), parse_query_params(query)),
        None => (path.to_string(), String::new(), RequestField::default()),
    };

    if let Some(body) = mbody {
        if let Err(rr) = parse_body(logs, &mut args, mcontent_type, body) {
            // if the body could not be parsed, store it in an argument, as if it was text
            logs.error(rr);
            args.add("RAW_BODY".to_string(), String::from_utf8_lossy(body).to_string());
        } else {
            logs.debug("body parsed");
        }
    }

    QueryInfo {
        qpath,
        query,
        uri,
        args,
    }
}

#[derive(Debug, Clone)]
/// data extracted from the query string
pub struct QueryInfo {
    /// the "path" portion of the raw query path
    pub qpath: String,
    /// the "query" portion of the raw query path
    pub query: String,
    /// URL decoded path, if decoding worked
    pub uri: Option<String>,
    pub args: RequestField,
}

#[derive(Debug, Clone)]
pub struct GeoIp {
    pub ipstr: String,
    pub ip: Option<IpAddr>,
    pub country: Option<maxminddb::geoip2::Country>,
    pub city: Option<maxminddb::geoip2::City>,
    pub asn: Option<maxminddb::geoip2::Asn>,
    pub country_name: Option<String>,
}

impl GeoIp {
    fn to_json(&self) -> HashMap<&'static str, serde_json::Value> {
        let mut out = HashMap::new();
        for k in &["location", "country", "continent", "city"] {
            out.insert(*k, json!({}));
        }

        if let Some(city) = &self.city {
            if let Some(location) = &city.location {
                out.insert(
                    "location",
                    json!({
                        "lat": location.latitude,
                        "lon": location.longitude
                    }),
                );
            }
            if let Some(lcity) = &city.city {
                match lcity.names.as_ref().and_then(|names| names.get("en")) {
                    Some(name) => {
                        out.insert("city", json!({ "name": name }));
                    }
                    None => {
                        out.insert("city", json!({ "name": "-" }));
                    }
                }
            }
        }

        if let Some(country) = self.country.as_ref() {
            if let Some(lcountry) = &country.country {
                out.insert(
                    "country",
                    json!({
                        "eu": lcountry.is_in_european_union,
                        "name": lcountry.names.as_ref().and_then(|names| names.get("en")),
                        "iso": lcountry.iso_code
                    }),
                );
            }
            if let Some(continent) = &country.continent {
                out.insert(
                    "continent",
                    json!({
                        "name": continent.names.as_ref().and_then(|names| names.get("en")),
                        "code": continent.code
                    }),
                );
            }
        }

        if let Some(asn) = &self.asn {
            out.insert("asn", json!(asn.autonomous_system_number));
            out.insert("company", json!(asn.autonomous_system_organization));
        }

        out
    }
}

#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub authority: Option<String>,
    pub method: String,
    pub path: String,
    /// this field only exists for gradual Lua interop
    /// TODO: remove when complete
    pub extra: HashMap<String, String>,
}

impl RequestMeta {
    pub fn from_map(attrs: HashMap<String, String>) -> Result<Self, &'static str> {
        let mut mattrs = attrs;
        let authority = mattrs.remove("authority");
        let method = mattrs.remove("method").ok_or("missing method field")?;
        let path = mattrs.remove("path").ok_or("missing path field")?;
        Ok(RequestMeta {
            authority,
            method,
            path,
            extra: mattrs,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RInfo {
    pub meta: RequestMeta,
    pub geoip: GeoIp,
    pub qinfo: QueryInfo,
    pub host: String,
}

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub cookies: RequestField,
    pub headers: RequestField,
    pub rinfo: RInfo,
}

impl RequestInfo {
    pub fn into_json(self, tags: Tags) -> serde_json::Value {
        // TODO: geo
        let ipnum: Option<String> = self.rinfo.geoip.ip.as_ref().map(|i| match i {
            IpAddr::V4(a) => u32::from_be_bytes(a.octets()).to_string(),
            IpAddr::V6(a) => u128::from_be_bytes(a.octets()).to_string(),
        });
        serde_json::json!({
            "headers": self.headers,
            "cookies": self.cookies,
            "args": self.rinfo.qinfo.args,
            "attrs": {
                "uri": self.rinfo.qinfo.uri,
                "path": self.rinfo.qinfo.qpath,
                "query": self.rinfo.qinfo.query,
                "ip": self.rinfo.geoip.ipstr,
                "remote_addr": self.rinfo.geoip.ipstr,
                "ipnum": ipnum
            },
            "tags": tags,
            "geo": self.rinfo.geoip.to_json()
        })
    }
}

#[derive(Debug)]
pub struct InspectionResult {
    pub decision: Decision,
    pub rinfo: Option<RequestInfo>,
    pub tags: Option<Tags>,
    pub err: Option<String>,
    pub logs: Logs,
}

impl InspectionResult {
    pub fn into_json(self) -> (String, Option<String>) {
        // return the request map, but only if we have it !
        let resp = match self.rinfo {
            None => self.decision.to_json_raw(serde_json::Value::Null, self.logs),
            Some(rinfo) => self.decision.to_json(rinfo, self.tags.unwrap_or_default(), self.logs),
        };
        (resp, self.err)
    }
}

pub fn find_geoip(ipstr: String) -> GeoIp {
    let ip = ipstr.parse().ok();
    let country = ip.and_then(get_country);
    fn get_country_x(c: &maxminddb::geoip2::Country) -> Option<String> {
        Some(c.country.as_ref()?.names.as_ref()?.get("en")?.to_lowercase())
    }
    let country_name = country.as_ref().and_then(get_country_x);
    GeoIp {
        ipstr,
        ip,
        city: ip.and_then(get_city),
        asn: ip.and_then(get_asn),
        country,
        country_name,
    }
}

pub fn map_request(
    logs: &mut Logs,
    ipstr: String,
    headers: HashMap<String, String>,
    meta: RequestMeta,
    mbody: Option<&[u8]>,
) -> Result<RequestInfo, String> {
    logs.debug("map_request starts");
    let (headers, cookies) = map_headers(headers);
    logs.debug("headers mapped");
    let geoip = find_geoip(ipstr);
    logs.debug("geoip computed");
    let qinfo = map_args(logs, &meta.path, headers.get_str("content-type"), mbody);
    logs.debug("args mapped");

    let host = match meta.authority.as_ref().or_else(|| headers.get("host")) {
        Some(a) => a.clone(),
        None => "unknown".to_string(),
    };

    // TODO : parse body

    let rinfo = RInfo {
        meta,
        geoip,
        qinfo,
        host,
    };

    Ok(RequestInfo {
        cookies,
        headers,
        rinfo,
    })
}

enum Selected<'a> {
    Str(&'a String),
    U32(u32),
}

/// selects data from a request
///
/// the reason we return this selected type instead of something directly string-like is
/// to avoid copies, because in the Asn case there is no way to return a reference
fn selector<'a>(reqinfo: &'a RequestInfo, sel: &RequestSelector) -> Option<Selected<'a>> {
    match sel {
        RequestSelector::Args(k) => reqinfo.rinfo.qinfo.args.get(k).map(Selected::Str),
        RequestSelector::Header(k) => reqinfo.headers.get(k).map(Selected::Str),
        RequestSelector::Cookie(k) => reqinfo.cookies.get(k).map(Selected::Str),
        RequestSelector::Ip => Some(&reqinfo.rinfo.geoip.ipstr).map(Selected::Str),
        RequestSelector::Uri => reqinfo.rinfo.qinfo.uri.as_ref().map(Selected::Str),
        RequestSelector::Path => Some(&reqinfo.rinfo.qinfo.qpath).map(Selected::Str),
        RequestSelector::Query => Some(&reqinfo.rinfo.qinfo.query).map(Selected::Str),
        RequestSelector::Method => Some(&reqinfo.rinfo.meta.method).map(Selected::Str),
        RequestSelector::Country => reqinfo.rinfo.geoip.country_name.as_ref().map(Selected::Str),
        RequestSelector::Asn => reqinfo
            .rinfo
            .geoip
            .asn
            .as_ref()
            .and_then(|a| a.autonomous_system_number)
            .map(Selected::U32),
    }
}

pub fn select_string(reqinfo: &RequestInfo, sel: &RequestSelector) -> Option<String> {
    selector(reqinfo, sel).map(|r| match r {
        Selected::Str(s) => (*s).clone(),
        Selected::U32(n) => format!("{}", n),
    })
}

pub fn check_selector_cond(reqinfo: &RequestInfo, tags: &Tags, sel: &RequestSelectorCondition) -> bool {
    match sel {
        RequestSelectorCondition::Tag(t) => tags.contains(t),
        RequestSelectorCondition::N(sel, re) => match selector(reqinfo, sel) {
            None => false,
            Some(Selected::Str(s)) => re.is_match(s),
            Some(Selected::U32(s)) => re.is_match(&format!("{}", s)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_args_full() {
        let mut logs = Logs::default();
        let qinfo = map_args(&mut logs, "/a/b/%20c?xa%20=12&bbbb=12%28&cccc", None, None);

        assert_eq!(qinfo.qpath, "/a/b/%20c");
        assert_eq!(qinfo.uri, Some("/a/b/ c?xa =12&bbbb=12(&cccc".to_string()));
        assert_eq!(qinfo.query, "xa%20=12&bbbb=12%28&cccc");

        let expected_args: RequestField = [("xa ", "12"), ("bbbb", "12("), ("cccc", "")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(qinfo.args, expected_args);
    }

    #[test]
    fn test_map_args_simple() {
        let mut logs = Logs::default();
        let qinfo = map_args(&mut logs, "/a/b", None, None);

        assert_eq!(qinfo.qpath, "/a/b");
        assert_eq!(qinfo.uri, Some("/a/b".to_string()));
        assert_eq!(qinfo.query, "");

        assert_eq!(qinfo.args, RequestField::default());
    }
}
