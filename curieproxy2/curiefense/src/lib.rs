extern crate mlua;

use lazy_static::lazy_static;
use mlua::prelude::*;
use serde::Serialize;
use serde_json::{to_value, Value};
use std::collections::HashMap;
use std::sync::RwLock;

mod curiefense;

use curiefense::acl::{check_acl, ACLResult};
use curiefense::config::hostmap::{HostMap, UrlMap};
use curiefense::config::waf::WAFSignatures;
use curiefense::config::Config;
use curiefense::interface::{Action, ActionType, Decision};
use curiefense::limit::limit_check;
use curiefense::tagging::tag_request;
use curiefense::utils::{ip_from_headers, map_request, RequestInfo};
use curiefense::waf::waf_check;

lazy_static! {
    static ref CONFIG: RwLock<Config> = RwLock::new(Config::empty());
    static ref HSDB: RwLock<Option<WAFSignatures>> = RwLock::new(None);
}

fn get_config(basepath: &str) -> Result<Config, Box<dyn std::error::Error>> {
    // cloned to release the lock - this might be horribly expensive though
    // TODO: somehow work with a reference to that data
    let mconfig = { CONFIG.read()?.clone() };
    let config = match mconfig.reload(basepath)? {
        None => mconfig,
        Some((newconfig, hsdb)) => {
            let mut w = CONFIG.write()?;
            println!("Updating configuration!");
            *w = newconfig.clone();
            let mut dbw = HSDB.write()?;
            *dbw = Some(hsdb);
            newconfig
        }
    };
    Result::Ok(config)
}

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
        .find(|e| e.matcher.is_match(&ri.rinfo.meta.authority))
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

struct InspectionResult(Decision);

impl InspectionResult {
    fn in_action<F, A>(&self, f: F) -> LuaResult<Option<A>>
    where
        F: Fn(&Action) -> A,
    {
        Ok(match &self.0 {
            Decision::Pass => None,
            Decision::Action(a) => Some(f(a)),
        })
    }
}

impl mlua::UserData for InspectionResult {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("pass", |_, this: &InspectionResult, _: ()| {
            Ok(match this.0 {
                Decision::Pass => true,
                _ => false,
            })
        });
        methods.add_method("atype", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| format!("{:?}", a.atype))
        });
        methods.add_method("ban", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| a.ban)
        });
        methods.add_method("status", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| a.status)
        });
        methods.add_method("headers", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| a.headers.clone())
        });
        methods.add_method("initiator", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| a.initiator.clone())
        });
        methods.add_method("reason", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| a.reason.to_string())
        });
        methods.add_method("content", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| a.content.clone())
        });
    }
}

/// Lua/envoy entry point
fn inspect(
    lua: &Lua,
    args: (HashMap<String, String>, HashMap<String, LuaValue>),
) -> LuaResult<Option<InspectionResult>> {
    println!("ARGS: {:?}", args);

    let (metaheaders, metadata) = args;

    let hops: usize = metadata
        .get("xff_trusted_hops")
        .and_then(|v| FromLua::from_lua(v.clone(), lua).ok())
        .unwrap_or(1);
    let str_ip = ip_from_headers(&metaheaders, hops);

    let res = inspect_generic("/config/current/config", str_ip, metaheaders);
    println!("Inspection result: {:?}", res);
    match res {
        Ok(a) => Ok(Some(InspectionResult(a))),
        Err(_) => Ok(None),
    }
}

fn acl_block<T: Serialize>(reason: T) -> Decision {
    return Decision::Action(Action {
        atype: ActionType::Block,
        ban: false,
        status: 403,
        headers: HashMap::new(),
        initiator: "ACL".to_string(),
        reason: to_value(reason).unwrap_or(Value::Null),
        content: "access denied".to_string(),
    });
}

/// generic entry point
/// this is not that generic, as we expect :path and :authority to be in metaheaders
fn inspect_generic(
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
                return Ok(acl_block("TODO"));
            }
        }
        ACLResult::Match(mbot, mhuman) => {
            // todo, handle turing test, bot/human priority
            let result = mbot.or(mhuman);
            if let Some(r) = result {
                if !r.allowed && urlmap.acl_active {
                    return Ok(acl_block("TODO"));
                }
            }
        }
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
