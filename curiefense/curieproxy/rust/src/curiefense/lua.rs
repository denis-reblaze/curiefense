/// lua interfaces
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::curiefense::interface::{Action, Decision};
use crate::curiefense::utils::RequestInfo;
use crate::Grasshopper;
use mlua::prelude::{Lua, LuaFunction, LuaResult, LuaTable, LuaValue, ToLua};

pub struct InspectionResult(pub Decision);

impl InspectionResult {
    #[allow(clippy::unnecessary_wraps)]
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
        methods.add_method("encoded", |_, this: &InspectionResult, _:()| {
            Ok(this.0.to_json(serde_json::Value::Null).ok())
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

fn geo_names<'t>(
    lua: &'t Lua,
    mnames: &Option<BTreeMap<String, String>>,
) -> LuaResult<Option<LuaValue<'t>>> {
    if let Some(name) = mnames.as_ref().and_then(|nm| nm.get("en")) {
        name.clone().to_lua(lua).map(Some)
    } else {
        Ok(None)
    }
}

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

            o.insert(
                "ip".to_string(),
                this.0.rinfo.geoip.ipstr.clone().to_lua(lua)?,
            );
            o.insert(
                "remote_addr".to_string(),
                this.0.rinfo.geoip.ipstr.clone().to_lua(lua)?,
            );

            if let Some(IpAddr::V4(ipv4)) = &this.0.rinfo.geoip.ip {
                o.insert(
                    "ipnum".to_string(),
                    ipv4.octets()
                        .iter()
                        .fold(0, |acc, x| acc * 256 + *x as u32)
                        .to_lua(lua)?,
                );
            }

            Ok(o)
        });

        methods.add_method("geo", |lua, this: &LuaRequestInfo, _: ()| {
            let mut m_country: HashMap<&'static str, LuaValue> = HashMap::new();
            let mut m_continent: HashMap<&'static str, LuaValue> = HashMap::new();
            let mut m_city: HashMap<&'static str, LuaValue> = HashMap::new();
            let mut m_location: HashMap<&'static str, LuaValue> = HashMap::new();

            if let Some(a_country) = &this.0.rinfo.geoip.country {
                if let Some(country) = &a_country.country {
                    m_country.insert(
                        "eu",
                        country.is_in_european_union.unwrap_or(false).to_lua(lua)?,
                    );
                    if let Some(iso) = &country.iso_code {
                        m_country.insert("iso", iso.clone().to_lua(lua)?);
                    }
                    if let Some(cname) = geo_names(lua, &country.names)? {
                        m_country.insert("name", cname);
                    }
                }
                if let Some(continent) = &a_country.continent {
                    if let Some(cname) = geo_names(lua, &continent.names)? {
                        m_continent.insert("name", cname);
                    }
                    if let Some(code) = &continent.code {
                        m_continent.insert("code", code.clone().to_lua(lua)?);
                    }
                }
            }

            if let Some(a_city) = &this.0.rinfo.geoip.city {
                if let Some(city) = &a_city.city {
                    if let Some(cityname) = geo_names(lua, &city.names)? {
                        m_city.insert("name", cityname);
                    }
                }
                if let Some(loc) = &a_city.location {
                    m_location.insert("lat", loc.latitude.to_lua(lua)?);
                    m_location.insert("lon", loc.longitude.to_lua(lua)?);
                }
            }

            let mut o: HashMap<&'static str, LuaValue> = [
                ("country", m_country.to_lua(lua)?),
                ("continent", m_continent.to_lua(lua)?),
                ("city", m_city.to_lua(lua)?),
                ("location", m_location.to_lua(lua)?),
            ]
            .iter()
            .cloned()
            .collect();

            if let Some(asn) = &this.0.rinfo.geoip.asn {
                if let Some(org) = &asn.autonomous_system_organization {
                    o.insert("company", org.clone().to_lua(lua)?);
                }
                if let Some(num) = &asn.autonomous_system_number {
                    o.insert("asn", num.to_lua(lua)?);
                }
            }

            Ok(o)
        });
    }
}
