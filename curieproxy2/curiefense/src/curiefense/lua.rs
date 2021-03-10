/// lua interfaces
use std::collections::HashMap;
use std::net::IpAddr;

use crate::curiefense::interface::{Action, Decision};
use crate::curiefense::utils::RequestInfo;
use crate::Grasshopper;
use mlua::prelude::{LuaFunction, LuaResult, LuaTable, LuaValue, ToLua};

pub struct InspectionResult(pub Decision);

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
            Ok(matches!(this.0, Decision::Pass))
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
        methods.add_method("reason", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| a.reason.to_string())
        });
        methods.add_method("content", |_, this: &InspectionResult, _: ()| {
            this.in_action(|a| a.content.clone())
        });
    }
}

pub struct Luagrasshopper<'t>(pub LuaTable<'t>);

impl Grasshopper for Luagrasshopper<'_> {
    fn js_app(&self) -> Option<String> {
        self.0
            .get("js_app")
            .and_then(|f: LuaFunction| f.call(()))
            .ok()
    }
    fn js_bio(&self) -> Option<String> {
        self.0
            .get("js_bio")
            .and_then(|f: LuaFunction| f.call(()))
            .ok()
    }
    fn parse_rbzid(&self, rbzid: &str, seed: &str) -> Option<bool> {
        self.0
            .get("parse_rbzid")
            .and_then(|f: LuaFunction| f.call((rbzid, seed)))
            .ok()
    }
    fn gen_new_seed(&self, seed: &str) -> Option<String> {
        self.0
            .get("gen_new_seed")
            .and_then(|f: LuaFunction| f.call(seed))
            .ok()
    }
    fn verify_workproof(&self, workproof: &str, seed: &str) -> Option<String> {
        self.0
            .get("verify_workproof")
            .and_then(|f: LuaFunction| f.call((workproof, seed)))
            .ok()
    }
}

/// a newtype that allows converting into the Lua "map" type
pub struct LuaRequestInfo(pub RequestInfo);

impl mlua::UserData for LuaRequestInfo {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("headers", |_, this: &LuaRequestInfo, _: ()| {
            Ok(this.0.headers.clone())
        });
        methods.add_method("cookies", |_, this: &LuaRequestInfo, _: ()| {
            Ok(this.0.cookies.clone())
        });
        methods.add_method("args", |_, this: &LuaRequestInfo, _: ()| {
            Ok(this.0.rinfo.qinfo.args.clone())
        });
        methods.add_method("attrs", |lua, this: &LuaRequestInfo, _: ()| {
            let mo: LuaResult<HashMap<String, LuaValue>> = this
                .0
                .rinfo
                .meta
                .extra
                .iter()
                .map(|(k, v)| v.clone().to_lua(lua).map(|lv| (k.clone(), lv)))
                .collect();
            let mut o = mo?;
            if let Some(uri) = this.0.rinfo.qinfo.uri.as_ref() {
                o.insert("uri".to_string(), uri.clone().to_lua(lua)?);
            }
            o.insert(
                "path".to_string(),
                this.0.rinfo.qinfo.qpath.clone().to_lua(lua)?,
            );
            o.insert(
                "query".to_string(),
                this.0.rinfo.qinfo.query.clone().to_lua(lua)?,
            );

            if let Some(ip) = this.0.rinfo.geoip.ip.as_ref() {
                o.insert("ip".to_string(), format!("{}", ip).to_lua(lua)?);
                o.insert("remote_addr".to_string(), format!("{}", ip).to_lua(lua)?);
                if let IpAddr::V4(ipv4) = ip {
                    o.insert(
                        "ipnum".to_string(),
                        ipv4.octets()
                            .iter()
                            .fold(0, |acc, x| acc * 256 + *x as u32)
                            .to_lua(lua)?,
                    );
                }
            }

            Ok(o)
        });
    }
}
