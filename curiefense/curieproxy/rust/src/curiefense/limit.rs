use redis::RedisResult;

use crate::curiefense::config::limit::Limit;
use crate::curiefense::interface::{Decision, Tags};
use crate::curiefense::redis::redis_conn;
use crate::curiefense::utils::{check_selector_cond, select_string, RequestInfo};

fn build_key(url_map_name: &str, reqinfo: &RequestInfo, limit: &Limit) -> Option<String> {
    let mut key = url_map_name.to_string() + &limit.id;
    for kpart in limit.key.iter().map(|r| select_string(reqinfo, r)) {
        key += &kpart?;
    }
    Some(format!("{:X}", md5::compute(key)))
}

fn get_ban_key(key: &str) -> String {
    format!("{:X}", md5::compute(format!("limit-ban-hash{}", key)))
}

fn is_banned(cnx: &mut redis::Connection, key: &str) -> bool {
    let ban_key = get_ban_key(&key);
    let q: redis::RedisResult<Option<u32>> = redis::cmd("GET").arg(&ban_key).query(cnx);
    q.unwrap_or(None).is_some()
}

fn limit_react(cnx: &mut redis::Connection, limit: &Limit, key: String) -> Decision {
    if limit.action.ban {
        let ban_key = get_ban_key(&key);
        if let Err(rr) = redis::cmd("SET").arg(ban_key).arg(1).query::<()>(cnx) {
            println!("*** Redis error {}", rr);
        }
    }
    Decision::Action(limit.action.clone())
}

fn redis_check_limit(
    cnx: &mut redis::Connection,
    key: &str,
    limit: u64,
    ttl: u64,
    pairvalue: Option<String>,
) -> RedisResult<bool> {
    let (mcurrent, mexpire): (Option<i64>, Option<i64>) = match &pairvalue {
        None => redis::pipe()
            .cmd("INCR")
            .arg(key)
            .cmd("TTL")
            .arg(key)
            .query(cnx)?,
        Some(pv) => redis::pipe()
            .cmd("SADD")
            .arg(key)
            .arg(pv)
            .ignore()
            .cmd("SCARD")
            .arg(key)
            .cmd("TTL")
            .arg(key)
            .query(cnx)?,
    };
    let current = mcurrent.unwrap_or(0);
    let expire = mexpire.unwrap_or(-1);

    if expire < 0 {
        let _: () = redis::cmd("EXPIRE").arg(key).arg(ttl).query(cnx)?;
    }
    Ok(current > limit as i64)
}

pub fn limit_check(
    url_map_name: &str,
    reqinfo: &RequestInfo,
    limits: &[Limit],
    tags: &mut Tags,
) -> Decision {
    // early return to avoid redis connection
    if limits.is_empty() {
        return Decision::Pass;
    }

    // we connect once for each request
    let mut redis = match redis_conn() {
        Ok(c) => c,
        Err(rr) => {
            println!("Could not connect to the redis server {}", rr);
            return Decision::Pass;
        }
    };

    for limit in limits {
        if limit
            .exclude
            .iter()
            .any(|selcond| check_selector_cond(reqinfo, tags, selcond))
        {
            continue;
        }
        if !limit
            .include
            .iter()
            .all(|selcond| check_selector_cond(reqinfo, tags, selcond))
        {
            continue;
        }

        // every matching ratelimit rule is tagged by name
        tags.insert(&limit.name);

        let key = match build_key(url_map_name, reqinfo, limit) {
            None => return Decision::Pass,
            Some(k) => k,
        };

        if limit.limit == 0 {
            return limit_react(&mut redis, limit, key);
        }

        if is_banned(&mut redis, &key) {
            return limit_react(&mut redis, limit, key);
        }

        let pairvalue = limit
            .pairwith
            .as_ref()
            .and_then(|sel| select_string(reqinfo, sel));

        match redis_check_limit(&mut redis, &key, limit.limit, limit.ttl, pairvalue) {
            Err(rr) => println!("*** Redis problem: {}", rr),
            Ok(true) => return limit_react(&mut redis, limit, key),
            Ok(false) => (),
        }
    }
    Decision::Pass
}
