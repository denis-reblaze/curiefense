extern crate mlua;

use crate::curiefense::interface::Tags;
use crate::session::update_tags;
use crate::session::JRequestMap;
use anyhow::anyhow;
use mlua::prelude::*;
use serde_json::json;
use std::collections::HashMap;

mod curiefense;

use curiefense::acl::{check_acl, ACLDecision, ACLResult, BotHuman};
use curiefense::config::hostmap::{HostMap, UrlMap};
use curiefense::config::{with_config, Config, HSDB};
use curiefense::flow::flow_check;
use curiefense::interface::{
    challenge_phase01, challenge_phase02, Action, ActionType, Decision, Grasshopper,
};
use curiefense::limit::limit_check;
use curiefense::lua::{InspectionResult, LuaRequestInfo, Luagrasshopper};
use curiefense::session;
use curiefense::tagging::tag_request;
use curiefense::urlmap::match_urlmap;
use curiefense::utils::{ip_from_headers, map_request, RequestInfo};
use curiefense::waf::waf_check;

/// Lua entry point, does not work properly as it does not yet handle body parsing
#[allow(clippy::unnecessary_wraps)]
fn inspect(
    lua: &Lua,
    args: (
        HashMap<String, String>,
        HashMap<String, LuaValue>,
        Option<LuaTable>,
    ),
) -> LuaResult<(InspectionResult, Vec<String>)> {
    let (metaheaders, metadata, lua_grasshopper) = args;
    let grasshopper = lua_grasshopper.map(Luagrasshopper);

    let hops: usize = metadata
        .get("xff_trusted_hops")
        .and_then(|v| FromLua::from_lua(v.clone(), lua).ok())
        .unwrap_or(1);
    let str_ip = ip_from_headers(&metaheaders, hops);

    let (res, errs) = inspect_generic(grasshopper, "/config/current/config", str_ip, metaheaders);
    Ok((
        InspectionResult(res),
        errs.into_iter().map(|x| format!("{}", x)).collect(),
    ))
}

/// Lua entry point, parameters are
///  * a JSON-encoded request_map
///  * the grasshopper lua module
pub fn inspect_request_map(
    _lua: &Lua,
    args: (String, Option<LuaTable>),
) -> LuaResult<(String, Vec<String>)> {
    let (encoded_request_map, lua_grasshopper) = args;
    let grasshopper = lua_grasshopper.map(Luagrasshopper);

    let jvalue: serde_json::Value = match serde_json::from_str(&encoded_request_map) {
        Ok(v) => v,
        Err(rr) => {
            return Ok((
                Decision::Pass.to_json(serde_json::Value::Null),
                vec![format!("{}", rr)],
            ))
        }
    };
    let jmap: JRequestMap = match serde_json::from_value(jvalue.clone()) {
        Ok(v) => v,
        Err(rr) => return Ok((Decision::Pass.to_json(jvalue), vec![format!("{}", rr)])),
    };
    let (rinfo, itags) = jmap.into_request_info();

    let (res, tags, mut errs) = inspect_generic_request_map("/config/current/config", grasshopper, rinfo, itags);
    let updated_request_map = match update_tags(jvalue, tags) {
        Ok(v) => v,
        Err(rr) => {
            errs.push(rr);
            serde_json::Value::Null
        }
    };
    Ok((
        res.to_json(updated_request_map),
        errs.into_iter().map(|x| format!("{}", x)).collect(),
    ))
}

#[allow(clippy::unnecessary_wraps)]
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
        block_mode: blocking,
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
) -> (Decision, Vec<anyhow::Error>) {
    // make sure config is loaded before calling map_request
    // TODO: make it a load only event, not a config cloning event
    let _ = with_config(configpath, |_| {});
    let reqinfo = map_request(ip_str, metaheaders);
    let (dec, _tags, errs) = inspect_generic_request_map(configpath, mgh, reqinfo, Tags::new());
    (dec, errs)
}

// generic entry point when the request map has already been parsed
fn inspect_generic_request_map<GH: Grasshopper>(
    configpath: &str,
    mgh: Option<GH>,
    reqinfo: RequestInfo,
    itags: Tags,
) -> (Decision, Tags, Vec<anyhow::Error>) {
    let mut tags = itags;

    // do all config queries in the lambda once
    // there is a lot of copying taking place, to minimize the lock time
    // this decision should be backed with benchmarks
    let ((nm, urlmap), ntags, flows, mut errs) = match with_config(configpath, |cfg| {
        let murlmap = match_urlmap(&reqinfo, cfg).map(|(nm, um)| (nm, um.clone()));
        let nflows = cfg.flows.clone();
        let ntags = tag_request(&cfg, &reqinfo);
        (murlmap, ntags, nflows)
    }) {
        (Some((Some(stuff), itags, iflows)), ierrs) => (stuff, itags, iflows, ierrs),
        (_, ierrs) => return (Decision::Pass, Tags::new(), ierrs),
    };
    tags.extend(ntags);
    tags.insert_qualified("urlmap", &nm);
    tags.insert_qualified("urlmap-entry", &urlmap.name);
    tags.insert_qualified("aclid", &urlmap.acl_profile.id);
    tags.insert_qualified("aclname", &urlmap.acl_profile.name);
    tags.insert_qualified("wafid", &urlmap.waf_profile.name);

    match flow_check(&flows, &reqinfo, &tags) {
        Err(rr) => errs.push(rr),
        Ok(Decision::Pass) => {}
        // TODO, check for monitor
        Ok(a) => return (a, tags, errs),
    }

    if let Some(dec) = mgh.as_ref().and_then(|gh| {
        reqinfo
            .rinfo
            .qinfo
            .uri
            .as_ref()
            .and_then(|uri| challenge_phase02(gh, uri, &reqinfo.headers))
    }) {
        // TODO, check for monitor
        return (dec, tags, errs);
    }

    // limit checks
    let limit_check = limit_check(&urlmap.name, &reqinfo, &urlmap.limits, &mut tags);
    if let Decision::Action(_) = limit_check {
        // limit hit!
        return (limit_check, tags, errs);
    }

    let acl_result = check_acl(&tags, &urlmap.acl_profile);
    match acl_result {
        ACLResult::Bypass(dec) => {
            if dec.allowed {
                return (Decision::Pass, tags, errs);
            } else {
                return (acl_block(urlmap.acl_active, 0, &dec.tags), tags, errs);
            }
        }
        // human blocked, always block, even if it is a bot
        ACLResult::Match(BotHuman {
            bot: _,
            human:
                Some(ACLDecision {
                    allowed: false,
                    tags: dtags,
                }),
        }) => return (acl_block(urlmap.acl_active, 5, &dtags), tags, errs),
        // robot blocked, should be challenged
        ACLResult::Match(BotHuman {
            bot:
                Some(ACLDecision {
                    allowed: false,
                    tags: dtags,
                }),
            human: _,
        }) => {
            // if grasshopper is available, run these tests
            if let Some(gh) = mgh {
                if !challenge_verified(&gh, &reqinfo) {
                    return (
                        match reqinfo.headers.get("user-agent") {
                            None => acl_block(urlmap.acl_active, 3, &dtags),
                            Some(ua) => challenge_phase01(&gh, ua, dtags),
                        },
                        tags,
                        errs,
                    );
                }
            }
        }
        _ => (),
    }
    let waf_result = match HSDB.read() {
        Ok(rd) => waf_check(&reqinfo, &urlmap.waf_profile, rd),
        Err(rr) => {
            errs.push(anyhow!("Could not get lock on HSDB: {}", rr));
            Ok(())
        }
    };

    (
        match waf_result {
            Ok(()) => Decision::Pass,
            Err(wb) => Decision::Action(wb.to_action()),
        },
        tags,
        errs,
    )
}

/// wraps a result into a go-like pair
#[allow(clippy::unnecessary_wraps)]
fn lua_result<R>(v: anyhow::Result<R>) -> LuaResult<(Option<R>, Option<String>)> {
    Ok(match v {
        Ok(x) => (Some(x), None),
        Err(rr) => (None, Some(format!("{}", rr))),
    })
}

/// runs the passed function, assuming the argument is a string
fn with_str<F, R>(lua: &Lua, session_id: LuaValue, f: F) -> anyhow::Result<R>
where
    F: FnOnce(&str) -> anyhow::Result<R>,
{
    let decoded: String = FromLua::from_lua(session_id, lua).map_err(|rr| anyhow!("{}", rr))?;
    f(&decoded)
}

/// runs the underlying string using function, catching mlua errors
fn wrap_session<F, R>(
    lua: &Lua,
    session_id: LuaValue,
    f: F,
) -> LuaResult<(Option<R>, Option<String>)>
where
    F: FnOnce(&str) -> anyhow::Result<R>,
{
    lua_result(with_str(lua, session_id, f))
}

/// runs the underlying string using, json returning, function, catching mlua errors
fn wrap_session_json<F, R: serde::Serialize>(
    lua: &Lua,
    session_id: LuaValue,
    f: F,
) -> LuaResult<(Option<String>, Option<String>)>
where
    F: FnOnce(&str) -> anyhow::Result<R>,
{
    lua_result(with_str(lua, session_id, |s| {
        f(s).and_then(|r| serde_json::to_string(&r).map_err(|rr| anyhow!("{}", rr)))
    }))
}

/// runs the underlying string using, Decision returning, function, catching mlua errors
fn wrap_session_decision<F>(
    lua: &Lua,
    session_id: LuaValue,
    f: F,
) -> LuaResult<(Option<String>, Option<String>)>
where
    F: FnOnce(&str) -> anyhow::Result<Decision>,
{
    lua_result(with_str(lua, session_id, |s| {
        f(s).and_then(|r| session::session_serialize_request_map(s).map(|v| r.to_json(v)))
    }))
}

#[mlua::lua_module]
fn curiefense(lua: &Lua) -> LuaResult<LuaTable> {
    let exports = lua.create_table()?;
    exports.set("inspect", lua.create_function(inspect)?)?;
    exports.set(
        "inspect_request_map",
        lua.create_function(inspect_request_map)?,
    )?;
    exports.set("map_request", lua.create_function(lua_map_request)?)?;

    // session functions
    exports.set(
        "init_config",
        lua.create_function(|_: &Lua, _: ()| Ok(session::init_config()))?,
    )?;
    exports.set(
        "session_init",
        lua.create_function(|lua: &Lua, encoded_request_map: LuaValue| {
            wrap_session(lua, encoded_request_map, session::session_init)
        })?,
    )?;
    exports.set(
        "session_clean",
        lua.create_function(|lua: &Lua, session_id: LuaValue| {
            wrap_session(lua, session_id, |s| {
                session::clean_session(s).map(|()| true)
            })
        })?,
    )?;
    exports.set(
        "session_serialize_request_map",
        lua.create_function(|lua: &Lua, session_id: LuaValue| {
            wrap_session_json(lua, session_id, session::session_serialize_request_map)
        })?,
    )?;
    exports.set(
        "session_match_urlmap",
        lua.create_function(|lua: &Lua, session_id: LuaValue| {
            wrap_session_json(lua, session_id, session::session_match_urlmap)
        })?,
    )?;
    exports.set(
        "session_tag_request",
        lua.create_function(|lua: &Lua, session_id: LuaValue| {
            wrap_session_json(lua, session_id, session::session_tag_request)
        })?,
    )?;
    exports.set(
        "session_limit_check",
        lua.create_function(|lua: &Lua, session_id: LuaValue| {
            wrap_session_decision(lua, session_id, session::session_limit_check)
        })?,
    )?;
    exports.set(
        "session_acl_check",
        lua.create_function(|lua: &Lua, session_id: LuaValue| {
            wrap_session_json(lua, session_id, session::session_acl_check)
        })?,
    )?;
    exports.set(
        "session_waf_check",
        lua.create_function(|lua: &Lua, session_id: LuaValue| {
            wrap_session_decision(lua, session_id, session::session_waf_check)
        })?,
    )?;
    exports.set(
        "session_flow_check",
        lua.create_function(|lua: &Lua, session_id: LuaValue| {
            wrap_session_decision(lua, session_id, session::session_flow_check)
        })?,
    )?;

    exports.set(
        "new_ip_set",
        lua.create_function(curiefense::iptools::new_ip_set)?,
    )?;
    exports.set(
        "new_sig_set",
        lua.create_function(curiefense::iptools::new_sig_set)?,
    )?;
    exports.set(
        "new_geoipdb",
        lua.create_function(curiefense::iptools::new_geoipdb)?,
    )?;
    exports.set(
        "modhash",
        lua.create_function(curiefense::iptools::modhash)?,
    )?;
    exports.set(
        "iptonum",
        lua.create_function(curiefense::iptools::iptonum)?,
    )?;
    exports.set(
        "decodeurl",
        lua.create_function(curiefense::iptools::decodeurl)?,
    )?;
    exports.set(
        "encodeurl",
        lua.create_function(curiefense::iptools::encodeurl)?,
    )?;
    exports.set(
        "test_regex",
        lua.create_function(curiefense::iptools::test_regex)?,
    )?;

    Ok(exports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_load() {
        let (_, errs) = with_config("../config", |_| {});
        for r in &errs {
            println!("{}", r);
        }
        assert!(errs.len() == 1);
        assert!(format!("{}", errs[0]).contains("profiling-lists.json"))
    }
}
