use itertools::Itertools;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::curiefense::config::utils::{RequestSelector, RequestSelectorCondition};
use crate::curiefense::interface::Tags;
use crate::curiefense::maxmind::{get_asn, get_city, get_country};

/// extract client IP from request headers, and amount of "trusted hops"
pub fn ip_from_headers(headers: &HashMap<String, String>, hops: usize) -> String {
    let ips: Vec<&str> = headers
        .get("x-forwarded-for")
        .map(|h| h.split(',').map(|s| s.trim()).collect())
        .unwrap_or_default();

    if ips.len() <= hops {
        ips.first().unwrap_or(&"1.1.1.1")
    } else {
        ips[ips.len() - hops - 1]
    }
    .to_string()
}

/// Parse raw headers and:
/// * remove leading ':' for meta headers
/// * lowercase the header name
/// * extract cookies
///
/// THIS WILL PANIC IF authority, method and path are not set in the raw headers!
///
/// Returns (cookies, headers, envoymeta, attrs)
pub fn map_headers(
    rawheaders: HashMap<String, String>,
) -> (HashMap<String, String>, HashMap<String, String>, EnvoyMeta) {
    fn cookie_map(cookie: &str) -> HashMap<String, String> {
        // tries to split the cookie around "="
        fn to_kv(cook: &str) -> (String, String) {
            match cook.splitn(2, '=').collect_tuple() {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (cook.to_string(), String::new()),
            }
        }
        cookie.split("; ").map(to_kv).collect()
    }
    let mut cookies = HashMap::<String, String>::new();
    let mut headers = HashMap::<String, String>::new();
    let mut attrs = HashMap::<String, String>::new();
    for (k, v) in rawheaders {
        let lk = k.to_lowercase();
        if k == "cookie" {
            cookies = cookie_map(&v);
        } else {
            match &lk.strip_prefix(':') {
                None => { headers.insert(lk, v) ; },
                Some(ak) => { attrs.insert(ak.to_string(), v) ; },
            }
        }
    }

    let meta = EnvoyMeta {
        authority: attrs.get("authority").unwrap().clone(),
        method: attrs.get("method").unwrap().clone(),
        path: attrs.get("path").unwrap().clone(),
    };
    (cookies, headers, meta)
}

/// parses query parameters
fn map_query(query: &str) -> HashMap<String, String> {
    fn dec(s: &str) -> String {
        urlencoding::decode(s).unwrap_or_else(|_| s.to_string())
    };
    fn parse_kv(kv: &str) -> (String, String) {
        match kv.splitn(2, '=').collect_tuple() {
            Some((k, v)) => (dec(k), dec(v)),
            None => (dec(kv), String::new()),
        }
    }
    query.split('&').map(parse_kv).collect()
}

/// parses the request uri, storing the path and query parts (if possible)
/// returns the hashmap of arguments
fn map_args(path: &str) -> QueryInfo {
    // this is necessary to do this in this convoluted way so at not to borrow attrs
    let uri = urlencoding::decode(&path).ok();
    match path.splitn(2, '?').collect_tuple() {
        Some((qpath, query)) => QueryInfo {
            qpath: qpath.to_string(),
            query: query.to_string(),
            uri,
            args: map_query(query),
        },
        None => QueryInfo {
            qpath: path.to_string(),
            query: String::new(),
            uri,
            args: HashMap::new(),
        },
    }
}

#[derive(Debug)]
/// data extracted from the query string
pub struct QueryInfo {
    /// the "path" portion of the raw query path
    pub qpath: String,
    /// the "query" portion of the raw query path
    pub query: String,
    /// URL decoded path, if decoding worked
    pub uri: Option<String>,
    pub args: HashMap<String, String>,
}

#[derive(Debug)]
pub struct GeoIp {
    pub ipstr: String,
    pub ip: Option<IpAddr>,
    pub country: Option<maxminddb::geoip2::Country>,
    pub city: Option<maxminddb::geoip2::City>,
    pub asn: Option<maxminddb::geoip2::Asn>,
    pub country_name: Option<String>,
}

#[derive(Debug)]
pub struct EnvoyMeta {
    pub authority: String,
    pub method: String,
    pub path: String,
}

#[derive(Debug)]
pub struct RInfo {
    pub meta: EnvoyMeta,
    pub geoip: GeoIp,
    pub qinfo: QueryInfo,
}

#[derive(Debug)]
pub struct RequestInfo {
    pub cookies: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub rinfo: RInfo,
}

pub fn map_request(ipstr: String, rawheaders: HashMap<String, String>) -> RequestInfo {
    let (cookies, headers, meta) = map_headers(rawheaders);

    // this will panic if path is not set
    // however, it must be set by envoy
    let ip = ipstr.parse().ok();
    let country = ip.and_then(get_country);
    fn get_country_x(c: &maxminddb::geoip2::Country) -> Option<String> {
        Some(
            c.country
                .as_ref()?
                .names
                .as_ref()?
                .get("en")?
                .to_lowercase(),
        )
    }
    let country_name = country.as_ref().and_then(get_country_x);
    let geoip = GeoIp {
        ipstr,
        ip,
        city: ip.and_then(get_city),
        asn: ip.and_then(get_asn),
        country,
        country_name,
    };

    let qinfo = map_args(&meta.path);

    // TODO : parse body

    let rinfo = RInfo { meta, geoip, qinfo };

    RequestInfo {
        cookies,
        headers,
        rinfo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop_test(hop: usize, expected: &str) {
        let hdrs1: HashMap<String, String> = [(
            "x-forwarded-for".to_string(),
            "1.2.3.4,5.6.7.8,9.10.11.12".to_string(),
        )]
        .iter()
        .cloned()
        .collect();
        assert_eq!(ip_from_headers(&hdrs1, hop), expected);
    }

    #[test]
    fn test_ip_from_headers_0() {
        hop_test(0, "9.10.11.12");
    }

    #[test]
    fn test_ip_from_headers_1() {
        hop_test(1, "5.6.7.8");
    }

    #[test]
    fn test_ip_from_headers_2() {
        hop_test(2, "1.2.3.4");
    }

    #[test]
    fn test_ip_from_headers_3() {
        hop_test(3, "1.2.3.4");
    }

    #[test]
    fn test_ip_from_headers_4() {
        hop_test(4, "1.2.3.4");
    }

    #[test]
    fn test_ip_empty_headers_0() {
        assert_eq!(ip_from_headers(&HashMap::new(), 0), "1.1.1.1");
    }

    #[test]
    fn test_ip_empty_headers_1() {
        assert_eq!(ip_from_headers(&HashMap::new(), 1), "1.1.1.1");
    }

    #[test]
    fn test_map_args_full() {
        let qinfo = map_args("/a/b/%20c?xa%20=12&bbbb=12%28&cccc");

        assert_eq!(qinfo.qpath, "/a/b/%20c");
        assert_eq!(qinfo.uri, Some("/a/b/ c?xa =12&bbbb=12(&cccc".to_string()));
        assert_eq!(qinfo.query, "xa%20=12&bbbb=12%28&cccc");

        let expected_args: HashMap<String, String> = [("xa ", "12"), ("bbbb", "12("), ("cccc", "")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(qinfo.args, expected_args);
    }

    #[test]
    fn test_map_args_simple() {
        let qinfo = map_args("/a/b");

        assert_eq!(qinfo.qpath, "/a/b");
        assert_eq!(qinfo.uri, Some("/a/b".to_string()));
        assert_eq!(qinfo.query, "");

        assert_eq!(qinfo.args, HashMap::new());
    }
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

pub fn check_selector_cond(
    reqinfo: &RequestInfo,
    tags: &Tags,
    sel: &RequestSelectorCondition,
) -> bool {
    match sel {
        RequestSelectorCondition::Tag(t) => tags.contains(t),
        RequestSelectorCondition::N(sel, re) => match selector(reqinfo, sel) {
            None => false,
            Some(Selected::Str(s)) => re.is_match(s),
            Some(Selected::U32(s)) => re.is_match(&format!("{}", s)),
        },
    }
}
