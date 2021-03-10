extern crate mlua;

use mlua::prelude::*;
use serde_json::json;
use std::collections::HashMap;

mod curiefense;

use curiefense::acl::{check_acl, ACLDecision, ACLResult};
use curiefense::config::hostmap::{HostMap, UrlMap};
use curiefense::config::{get_config, Config, HSDB};
use curiefense::interface::{
    challenge_phase01, challenge_phase02, Action, ActionType, Decision, Grasshopper,
};
use curiefense::limit::limit_check;
use curiefense::lua::{InspectionResult, LuaRequestInfo, Luagrasshopper};
use curiefense::tagging::tag_request;
use curiefense::utils::{ip_from_headers, map_request, RequestInfo};
use curiefense::waf::waf_check;

/// finds the urlmap matching a given request, based on the configuration
/// there are cases where default values do not exist (even though the UI should prevent that)
///
/// note that the url is matched using the url-decoded path!
///
/// returns the matching url map, along with the id of the selected host map
fn match_urlmap<'a>(ri: &RequestInfo, cfg: &'a Config) -> Option<(String, &'a UrlMap)> {
    // find the first matching hostmap, or use the default, if it exists
    let hostmap: &HostMap = cfg
        .urlmaps
        .iter()
        .find(|e| e.matcher.is_match(&ri.rinfo.host))
        .map(|m| &m.inner)
        .or_else(|| cfg.default.as_ref())?;
    // find the first matching urlmap, or use the default, if it exists
    let urlmap: &UrlMap = hostmap
        .entries
        .iter()
        .find(|e| e.matcher.is_match(&ri.rinfo.qinfo.qpath))
        .map(|m| &m.inner)
        .or_else(|| hostmap.default.as_ref())?;
    Some((hostmap.name.clone(), urlmap))
}

/// Lua/envoy entry point
fn inspect(
    lua: &Lua,
    args: (
        HashMap<String, String>,
        HashMap<String, LuaValue>,
        Option<LuaTable>,
    ),
) -> LuaResult<Option<InspectionResult>> {
    println!("ARGS: {:?}", args);

    let (metaheaders, metadata, lua_grasshopper) = args;
    let grasshopper = lua_grasshopper.map(Luagrasshopper);

    let hops: usize = metadata
        .get("xff_trusted_hops")
        .and_then(|v| FromLua::from_lua(v.clone(), lua).ok())
        .unwrap_or(1);
    let str_ip = ip_from_headers(&metaheaders, hops);

    let res = inspect_generic(grasshopper, "/config/current/config", str_ip, metaheaders);
    println!("Inspection result: {:?}", res);
    Ok(res.ok().map(InspectionResult))
}

fn lua_map_request(
    lua: &Lua,
    args: (HashMap<String, String>, HashMap<String, LuaValue>),
) -> LuaResult<LuaRequestInfo> {
    let (metaheaders, metadata) = args;

    let hops: usize = metadata
        .get("xff_trusted_hops")
        .and_then(|v| FromLua::from_lua(v.clone(), lua).ok())
        .unwrap_or(1);
    let str_ip = ip_from_headers(&metaheaders, hops);

    let rinfo = map_request(str_ip, metaheaders);

    Ok(LuaRequestInfo(rinfo))
}

fn acl_block(blocking: bool, code: i32, tags: &[String]) -> Decision {
    Decision::Action(Action {
        atype: if blocking {
            ActionType::Block
        } else {
            ActionType::Monitor
        },
        ban: false,
        status: 403,
        headers: None,
        reason: json!({"action": code, "initiator": "acl", "reason": tags }),
        content: "access denied".to_string(),
        extra_tags: None,
    })
}

fn challenge_verified<GH: Grasshopper>(gh: &GH, reqinfo: &RequestInfo) -> bool {
    if let Some(rbzid) = reqinfo.cookies.get("rbzid") {
        if let Some(ua) = reqinfo.headers.get("user-agent") {
            return gh
                .parse_rbzid(&rbzid.replace('-', "="), ua)
                .unwrap_or(false);
        }
    }
    false
}

/// generic entry point
/// this is not that generic, as we expect :path and :authority to be in metaheaders
fn inspect_generic<GH: Grasshopper>(
    mgh: Option<GH>,
    configpath: &str,
    ip_str: String,
    metaheaders: HashMap<String, String>,
) -> Result<Decision, Box<dyn std::error::Error>> {
    let cfg = get_config(configpath)?;
    let reqinfo = map_request(ip_str, metaheaders);
    let (nm, urlmap) = match match_urlmap(&reqinfo, &cfg) {
        None => return Ok(Decision::Pass),
        Some(x) => x,
    };

    if let Some(dec) = mgh.as_ref().and_then(|gh| {
        reqinfo
            .rinfo
            .qinfo
            .uri
            .as_ref()
            .and_then(|uri| challenge_phase02(gh, uri, &reqinfo.headers))
    }) {
        return Ok(dec);
    }

    let mut tags = tag_request(&cfg, &reqinfo);
    tags.insert(&format!("urlmap:{}", nm));
    tags.insert(&format!("urlmap-entry:{}", urlmap.name));
    tags.insert(&format!("aclid:{}", urlmap.acl_profile.id));
    tags.insert(&format!("aclname:{}", urlmap.acl_profile.name));
    tags.insert(&format!("wafid:{}", urlmap.waf_profile.name));

    // TODO challenge

    println!("REQINFO: {:?}", reqinfo);
    println!("urlmap: {:?}", urlmap);

    // limit checks, this is
    let limit_check = limit_check(&reqinfo, &urlmap.limits, &mut tags);
    println!("LIMIT_CHECKS: {:?}", limit_check);
    if let Decision::Action(_) = limit_check {
        // limit hit!
        return Ok(limit_check);
    }

    let acl_result = check_acl(&tags, &urlmap.acl_profile);
    println!("ACLRESULTS: {:?}", acl_result);
    match acl_result {
        ACLResult::Bypass(dec) => {
            if dec.allowed {
                return Ok(Decision::Pass);
            } else {
                return Ok(acl_block(urlmap.acl_active, 0, &dec.tags));
            }
        }
        // human blocked, always block, even if it is a bot
        ACLResult::Match(
            _,
            Some(ACLDecision {
                allowed: false,
                tags,
            }),
        ) => return Ok(acl_block(urlmap.acl_active, 5, &tags)),
        // robot blocked, should be challenged, just block for now
        ACLResult::Match(
            Some(ACLDecision {
                allowed: false,
                tags,
            }),
            _,
        ) => {
            // if grasshopper is available, run these tests
            if let Some(gh) = mgh {
                if !challenge_verified(&gh, &reqinfo) {
                    return Ok(match reqinfo.headers.get("user-agent") {
                        None => acl_block(urlmap.acl_active, 3, &tags),
                        Some(ua) => challenge_phase01(&gh, ua, tags),
                    });
                }
            }
        }
        _ => (),
    }
    let waf_result = waf_check(&reqinfo, &urlmap.waf_profile, HSDB.read()?);
    println!("WAFRESULTS: {:?}", waf_result);

    Ok(match waf_result {
        Ok(()) => Decision::Pass,
        Err(wb) => Decision::Action(wb.to_action()),
    })
}

#[mlua::lua_module]
fn curiedefense(lua: &Lua) -> LuaResult<LuaTable> {
    let exports = lua.create_table()?;
    exports.set("inspect", lua.create_function(inspect)?)?;
    exports.set("map_request", lua.create_function(lua_map_request)?)?;
    Ok(exports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_load() {
        let r = get_config("../mounts/config/current/config");
        assert!(r.is_ok(), format!("{:?}", r));
    }
}
