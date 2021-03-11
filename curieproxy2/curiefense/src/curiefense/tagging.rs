use crate::curiefense::config::profiling::{
    PairEntry, ProfilingEntry, ProfilingEntryE, ProfilingSSection, SingleEntry,
};
use crate::curiefense::config::raw::Relation;
use crate::curiefense::config::Config;
use crate::curiefense::interface::Tags;
use crate::curiefense::utils::RequestInfo;
use std::collections::HashMap;
use std::net::IpAddr;

fn check_relation<A, F>(rinfo: &RequestInfo, rel: Relation, elems: &[A], checker: F) -> bool
where
    F: Fn(&RequestInfo, &A) -> bool,
{
    match rel {
        Relation::AND => elems.iter().all(|sub| checker(rinfo, sub)),
        Relation::OR => elems.iter().any(|sub| checker(rinfo, sub)),
    }
}

fn check_pair(pr: &PairEntry, s: &HashMap<String, String>) -> bool {
    s.get(&pr.key)
        .map(|v| &pr.exact == v || pr.re.as_ref().map(|re| re.is_match(v)).unwrap_or(false))
        .unwrap_or(false)
}

fn check_single(pr: &SingleEntry, s: &str) -> bool {
    pr.exact == s || pr.re.as_ref().map(|re| re.is_match(s)).unwrap_or(false)
}

fn check_entry(rinfo: &RequestInfo, sub: &ProfilingEntry) -> bool {
    let c = match &sub.entry {
        ProfilingEntryE::Ip(addr) => rinfo.rinfo.geoip.ip.map(|i| &i == addr).unwrap_or(false),
        ProfilingEntryE::Network(net) => rinfo
            .rinfo
            .geoip
            .ip
            .map(|i| net.contains(&i))
            .unwrap_or(false),
        ProfilingEntryE::Range4(net4) => match rinfo.rinfo.geoip.ip {
            Some(IpAddr::V4(ip4)) => net4.contains(&ip4),
            _ => false,
        },
        ProfilingEntryE::Range6(net6) => match rinfo.rinfo.geoip.ip {
            Some(IpAddr::V6(ip6)) => net6.contains(&ip6),
            _ => false,
        },
        ProfilingEntryE::Path(pth) => check_single(pth, &rinfo.rinfo.qinfo.qpath),
        ProfilingEntryE::Query(qry) => check_single(qry, &rinfo.rinfo.qinfo.query),
        ProfilingEntryE::Uri(uri) => rinfo
            .rinfo
            .qinfo
            .uri
            .as_ref()
            .map(|curi| check_single(uri, curi))
            .unwrap_or(false),
        ProfilingEntryE::Country(cty) => rinfo
            .rinfo
            .geoip
            .country_name
            .as_ref()
            .map(|ccty| check_single(cty, ccty.as_ref()))
            .unwrap_or(false),
        ProfilingEntryE::Method(mtd) => check_single(mtd, &rinfo.rinfo.meta.method),
        ProfilingEntryE::Header(hdr) => check_pair(hdr, &rinfo.headers),
        ProfilingEntryE::Args(arg) => check_pair(arg, &rinfo.rinfo.qinfo.args),
        ProfilingEntryE::Cookies(arg) => check_pair(arg, &rinfo.cookies),
        ProfilingEntryE::Asn(asn) => rinfo
            .rinfo
            .geoip
            .asn
            .as_ref()
            .map(|casn| casn.autonomous_system_number == Some(*asn))
            .unwrap_or(false),
    };
    c ^ sub.negated
}

fn check_subsection(rinfo: &RequestInfo, sub: &ProfilingSSection) -> bool {
    check_relation(rinfo, sub.relation, &sub.entries, check_entry)
}

pub fn tag_request(cfg: &Config, rinfo: &RequestInfo) -> Tags {
    let mut tags = Tags::new();
    tags.insert("all");
    tags.insert("curieaccesslog");
    for psection in &cfg.profiling {
        if check_relation(
            rinfo,
            psection.relation,
            &psection.sections,
            check_subsection,
        ) {
            tags.extend(psection.tags.clone());
        }
    }
    tags.insert_qualified("ip", &rinfo.rinfo.geoip.ipstr);
    tags.insert_qualified(
        "geo",
        rinfo.rinfo.geoip.country_name.as_deref().unwrap_or("nil"),
    );
    match rinfo
        .rinfo
        .geoip
        .asn
        .as_ref()
        .and_then(|g| g.autonomous_system_number)
    {
        None => {
            tags.insert_qualified("asn", "nil");
        }
        Some(asn) => {
            let sasn = format!("{}", asn);
            tags.insert_qualified("asn", &sasn);
        }
    }

    if let Some(container_name) = &cfg.container_name {
        tags.insert_qualified("container", container_name);
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curiefense::config::profiling::optimize_ipranges;
    use crate::curiefense::config::utils::anchored_re;
    use crate::curiefense::utils::map_request;

    fn mk_rinfo() -> RequestInfo {
        let raw_headers = [
            ("content-type", "/sson"),
            ("x-forwarded-for", "52.78.12.56"),
            (":method", "GET"),
            (":authority", "localhost:30081"),
            (":path", "/adminl%20e?lol=boo&bar=bze&%20encoded=%20%20%20"),
            ("x-forwarded-proto", "http"),
            ("x-request-id", "af36dcec-524d-4d21-b90e-22d5798a6300"),
            ("accept", "*/*"),
            ("user-agent", "curl/7.58.0"),
            ("x-envoy-internal", "true"),
        ];
        let headers: HashMap<String, String> = raw_headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        map_request("52.78.12.56".to_string(), headers)
    }

    fn t_check_entry(negated: bool, entry: ProfilingEntryE) -> bool {
        check_entry(&mk_rinfo(), &ProfilingEntry { negated, entry })
    }

    fn single_re(input: &str) -> SingleEntry {
        SingleEntry {
            exact: input.to_string(),
            re: anchored_re(input).ok(),
        }
    }

    fn double_re(key: &str, input: &str) -> PairEntry {
        PairEntry {
            key: key.to_string(),
            exact: input.to_string(),
            re: anchored_re(input).ok(),
        }
    }

    #[test]
    fn check_entry_ip_in() {
        let r = t_check_entry(false, ProfilingEntryE::Ip("52.78.12.56".parse().unwrap()));
        assert!(r);
    }
    #[test]
    fn check_entry_ip_in_neg() {
        let r = t_check_entry(true, ProfilingEntryE::Ip("52.78.12.56".parse().unwrap()));
        assert!(!r);
    }
    #[test]
    fn check_entry_ip_out() {
        let r = t_check_entry(false, ProfilingEntryE::Ip("52.78.12.57".parse().unwrap()));
        assert!(!r);
    }

    #[test]
    fn check_path_in() {
        let r = t_check_entry(false, ProfilingEntryE::Path(single_re(".*adminl%20e.*")));
        assert!(r);
    }

    #[test]
    fn check_path_in_not_partial_match() {
        let r = t_check_entry(false, ProfilingEntryE::Path(single_re("adminl%20e")));
        assert!(!r);
    }

    #[test]
    fn check_path_out() {
        let r = t_check_entry(false, ProfilingEntryE::Path(single_re(".*adminl e.*")));
        assert!(!r);
    }

    #[test]
    fn check_headers_exact() {
        let r = t_check_entry(false, ProfilingEntryE::Header(double_re("accept", "*/*")));
        assert!(r);
    }

    #[test]
    fn check_headers_match() {
        let r = t_check_entry(
            false,
            ProfilingEntryE::Header(double_re("user-agent", "^curl.*")),
        );
        assert!(r);
    }

    fn mk_profilingentries(lst: &[&str]) -> Vec<ProfilingEntry> {
        lst.iter()
            .map(|e| match e.strip_prefix('!') {
                None => ProfilingEntry {
                    negated: false,
                    entry: ProfilingEntryE::Network(e.parse().unwrap()),
                },
                Some(sub) => ProfilingEntry {
                    negated: true,
                    entry: ProfilingEntryE::Network(sub.parse().unwrap()),
                },
            })
            .collect()
    }

    fn optimize(ss: &ProfilingSSection) -> ProfilingSSection {
        ProfilingSSection {
            relation: ss.relation,
            entries: optimize_ipranges(ss.relation, ss.entries.clone()),
        }
    }

    fn check_iprange(rel: Relation, input: &[&str], samples: &[(&str, bool)]) {
        let entries = mk_profilingentries(input);
        let ssection = ProfilingSSection {
            entries,
            relation: rel,
        };
        let optimized = optimize(&ssection);

        let mut ri = mk_rinfo();
        for (ip, expected) in samples {
            ri.rinfo.geoip.ip = Some(ip.parse().unwrap());
            println!("UN {} {:?}", ip, ssection);
            assert_eq!(check_subsection(&ri, &ssection), *expected);
            println!("OP {} {:?}", ip, optimized);
            assert_eq!(check_subsection(&ri, &optimized), *expected);
        }
    }

    #[test]
    fn ipranges_simple() {
        let entries = ["192.168.1.0/24"];
        let samples = [
            ("10.0.4.1", false),
            ("192.168.0.23", false),
            ("192.168.1.23", true),
            ("192.170.2.45", false),
        ];
        check_iprange(Relation::AND, &entries, &samples);
    }

    #[test]
    fn ipranges_intersected() {
        let entries = ["192.168.0.0/23", "192.168.1.0/24"];
        let samples = [
            ("10.0.4.1", false),
            ("192.168.0.23", false),
            ("192.168.1.23", true),
            ("192.170.2.45", false),
        ];
        check_iprange(Relation::AND, &entries, &samples);
    }

    #[test]
    fn ipranges_simple_substraction() {
        let entries = ["192.168.0.0/23", "!192.168.1.0/24"];
        let samples = [
            ("10.0.4.1", false),
            ("192.168.0.23", true),
            ("192.168.1.23", false),
            ("192.170.2.45", false),
        ];
        check_iprange(Relation::AND, &entries, &samples);
    }

    #[test]
    fn ipranges_simple_union() {
        let entries = ["192.168.0.0/24", "192.168.1.0/24"];
        let samples = [
            ("10.0.4.1", false),
            ("192.168.0.23", true),
            ("192.168.1.23", true),
            ("192.170.2.45", false),
        ];
        check_iprange(Relation::OR, &entries, &samples);
    }

    #[test]
    fn ipranges_larger_union() {
        let entries = [
            "192.168.0.0/24",
            "192.168.2.0/24",
            "10.1.0.0/16",
            "10.4.0.0/16",
        ];
        let samples = [
            ("10.4.4.1", true),
            ("10.2.2.1", false),
            ("192.168.0.23", true),
            ("192.168.1.23", false),
            ("192.170.2.45", false),
        ];
        check_iprange(Relation::OR, &entries, &samples);
    }
}
