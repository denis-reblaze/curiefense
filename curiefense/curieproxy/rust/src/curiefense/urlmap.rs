use crate::{Config, HostMap, Logs, RequestInfo, UrlMap};

/// finds the urlmap matching a given request, based on the configuration
/// there are cases where default values do not exist (even though the UI should prevent that)
///
/// note that the url is matched using the url-decoded path!
///
/// returns the matching url map, along with the id of the selected host map
pub fn match_urlmap<'a>(
    ri: &RequestInfo,
    cfg: &'a Config,
    logs: &mut Logs,
) -> Option<(String, &'a UrlMap)> {
    // find the first matching hostmap, or use the default, if it exists
    let hostmap: &HostMap = cfg
        .urlmaps
        .iter()
        .find(|e| e.matcher.is_match(&ri.rinfo.host))
        .map(|m| &m.inner)
        .or_else(|| {
            logs.warning("could not find default urlmap".to_string());
            cfg.default.as_ref()
        })?;
    // find the first matching urlmap, or use the default, if it exists
    let urlmap: &UrlMap = hostmap
        .entries
        .iter()
        .find(|e| e.matcher.is_match(&ri.rinfo.qinfo.qpath))
        .map(|m| &m.inner)
        .or_else(|| {
            logs.warning("could not find default urlmap entry".to_string());
            hostmap.default.as_ref()
        })?;
    Some((hostmap.name.clone(), urlmap))
}
