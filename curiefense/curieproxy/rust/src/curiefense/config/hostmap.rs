use crate::curiefense::config::limit::Limit;
use crate::curiefense::config::raw::ACLProfile;
use crate::curiefense::config::utils::Matching;
use crate::curiefense::config::waf::WAFProfile;

/// the default entry is statically encoded so that it is certain it exists
#[derive(Debug, Clone)]
pub struct HostMap {
    pub id: String,
    pub name: String,
    pub entries: Vec<Matching<UrlMap>>,
    pub default: Option<UrlMap>,
}

/// a map entry, with links to the acl and waf profiles
#[derive(Debug, Clone)]
pub struct UrlMap {
    pub name: String,
    pub acl_active: bool,
    pub acl_profile: ACLProfile,
    pub waf_active: bool,
    pub waf_profile: WAFProfile,
    pub limits: Vec<Limit>,
}
