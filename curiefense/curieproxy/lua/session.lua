module(..., package.seeall)

local acl           = require "lua.acl"
local waf           = require "lua.waf"
local globals       = require "lua.globals"
local utils         = require "lua.utils"
local tagprofiler   = require "lua.tagprofiler"
local restysha1     = require "lua.resty.sha1"
local limit         = require "lua.limit"
local accesslog     = require "lua.accesslog"
local challenge     = require "lua.challenge"
local utils         = require "lua.utils"

local cjson       = require "cjson"
local rust        = require "curiefense"

local init          = globals.init

local acl_check     = acl.check
local acl_check_bot = acl.check_bot
local waf_check     = waf.check

local ACLNoMatch    = globals.ACLNoMatch
local ACLForceDeny  = globals.ACLForceDeny
local ACLBypass     = globals.ACLBypass
local ACLAllowBot   = globals.ACLAllowBot
local ACLDenyBot    = globals.ACLDenyBot
local ACLAllow      = globals.ACLAllow
local ACLDeny       = globals.ACLDeny

local WAFPass       = globals.WAFPass
local WAFBlock      = globals.WAFBlock

local re_match      = utils.re_match
local map_request   = utils.map_request
local tag_request   = utils.tag_request
local deny_request  = utils.deny_request
local custom_response  = utils.custom_response

local tag_lists     = tagprofiler.tag_lists

local log_request   = accesslog.log_request
local limit_check   = limit.check

local challenge_verified = challenge.verified
local challenge_phase01 = challenge.phase01
local challenge_phase02 = challenge.phase02

local sfmt = string.format

function match_urlmap(request_map)
    local default_map = nil
    local selected_map = nil
    local matched_path = "/"
    local url = request_map.attrs.path
    local host = request_map.headers.host or request_map.attrs.authority
    local handle = request_map.handle

    for _, profile in pairs(globals.URLMap) do
        if profile.match == "__default__" then
            default_map = profile
        else
            -- handle:logDebug(sfmt("URLMap - try %s with %s", host, profile.match))
            if re_match(host, profile.match) then
                -- handle:logInfo(sfmt("URLMap matched with: %s", profile.match))
                selected_map = profile
                break
            end
        end
    end

    if not selected_map then
        selected_map = default_map
    end

    for _, map_entry in ipairs(selected_map.map) do
        local path = map_entry.match
        if re_match(url, path) then
            if path:len() > matched_path:len() then
                matched_path = path
            end
        end
    end

    for _, map_entry in ipairs(selected_map.map) do
        if matched_path == map_entry.match then
            return map_entry, selected_map
        end
    end

    return default_map.map[1], default_map

end


function internal_url(url)
    return false
end

function print_request_map(request_map)
    for _, entry in ipairs({"headers", "cookies", "args", "attrs"}) do
        for k,v in pairs(request_map[entry]) do
            -- request_map.handle:logDebug(sfmt("%s: %s\t%s", entry, k, v))
        end
    end
end

function map_tags(request_map, urlmap_name, urlmapentry_name, acl_id, acl_name, waf_id, waf_name)

    tag_request(request_map, {
        "all",
        "curieaccesslog",
        globals.ContainerID,
        acl_id,
        acl_name,
        waf_id,
        waf_name,
        urlmap_name,
        urlmapentry_name,
        sfmt("ip:%s", request_map.attrs.ip),
        sfmt("geo:%s", request_map.geo.country.name),
        sfmt("asn:%s", request_map.geo.asn)
    })

end

local gettime = socket.gettime

function addentry(t, msg)
    table.insert(t, {gettime()*1000, msg})
end

function rust_inspect(handle)

    local headerm = {}
    for k, v in pairs(handle:headers()) do
        headerm[k] = v
    end
    local metam = {}
    for k, v in pairs(handle:metadata()) do
        metam[k] = v
    end

    res = rust.inspect(headerm, metam, grasshopper)
    handle:logInfo(string.format("res:pass() %s", res:pass()))
    if res and res:pass() == false then
        handle:logInfo(string.format("res atype %s", cjson.encode(res:atype())))
        handle:logInfo(string.format("res ban %s", cjson.encode(res:ban())))
        handle:logInfo(string.format("res reason %s", res:reason()))
        local action_params = {
            ["reason"] = res:reason(),
            ["block_mode"] = true
        }
        local headers = res:headers()
        if headers == nil then
            headers = { ["x-curiefense"] = "response" }
        end
        headers[":status"] = res:status()
        handle:respond(headers, res:content())
    else
        return
    end
end

function encode_request_map(request_map)
    local s_request_map = {
        headers = request_map.headers,
        cookies = request_map.cookies,
        params = request_map.params,
        attrs = request_map.attrs,
        args = request_map.args,
    }

    return cjson.encode(s_request_map)

end

function compare_tags(stage, session_uuid, request_map)
    local jrust_request_map = rust.session_serialize_request_map(session_uuid)
    if jrust_request_map then
        local rust_request_map = cjson.decode(jrust_request_map)
        local e_tags = request_map.attrs.tags
        local a_tags = rust_request_map.attrs.tags

        if utils.table_length(e_tags) ~= utils.table_length(a_tags) then
            request_map.handle:logErr(sfmt("differing tags, expected=%s actual=%s", cjson.encode(e_tags), cjson.encode(a_tags)))
            return
        end

        for e_key, _ in pairs(e_tags) do
            if not a_tags[e_key] then
                request_map.handle:logErr(sfmt("differing tags, expected=%s actual=%s", cjson.encode(e_tags), cjson.encode(a_tags)))
                return
            end
        end
    else
        request_map.handle:logErr("rust.session_serialize_request_map failed")
    end
end

function inspect(handle)

    local timeline = {}

    addentry(timeline, "0 init")
    init(handle)

    handle:logInfo("******* START ********")
    rust_init = rust.init_config()

    -- handle:logDebug("inspection initiated")
    addentry(timeline, "1 map_request")
    local request_map = map_request(handle)

    addentry(timeline, "2 url/host assignment")
    local url = request_map.attrs.path
    local host = request_map.headers.host or request_map.attrs.authority

    -- rust alternative
    local session_uuid = nil
    if rust_init then
        session_uuid = rust.session_init(encode_request_map(request_map))
        handle:logInfo(sfmt("rust uuid: %s", session_uuid))
    end

    -- unified the following 3 into a single operaiton
    addentry(timeline, "3 match_urlmap")
    local urlmap_entry, url_map = match_urlmap(request_map)

    addentry(timeline, "4 profiles assignment")
    local acl_active        = urlmap_entry["acl_active"]
    local waf_active        = urlmap_entry["waf_active"]
    local acl_profile_id    = urlmap_entry["acl_profile"]
    local waf_profile_id    = urlmap_entry["waf_profile"]
    local acl_profile       = globals.ACLProfiles[acl_profile_id]
    local waf_profile       = globals.WAFProfiles[waf_profile_id]

    addentry(timeline, "5 map_tags")
    map_tags(request_map,
        sfmt('urlmap:%s', url_map.name),
        sfmt('urlmap-entry:%s', urlmap_entry.name),
        sfmt("aclid:%s", acl_profile_id),
        sfmt("aclname:%s", acl_profile.name),
        sfmt("wafid:%s", waf_profile_id),
        sfmt("wafname:%s", waf_profile.name)
    )

    -- rust alternative
    local rust_urlmap = nil
    if session_uuid then
        local jrust_urlmap = rust.session_match_urlmap(session_uuid)
        handle:logDebug(sfmt("rust urlmap: %s", jrust_urlmap))
        if jrust_urlmap then
            rust_urlmap = cjson.decode(jrust_urlmap)
        end
    end

    if rust_urlmap then
        handle:logInfo("******* XXXX ********")

        if rust_urlmap.urlmap ~= url_map.name then
            handle:logErr("failed check urlmap")
        end
        if rust_urlmap.acl_active ~= urlmap_entry.acl_active then
            handle:logErr("failed check acl_active")
        end
        if rust_urlmap.waf_active ~= urlmap_entry.waf_active then
            handle:logErr("failed check waf_active")
        end
        if rust_urlmap.acl_profile ~= urlmap_entry.acl_profile then
            handle:logErr("failed check acl_profile")
        end
        if rust_urlmap.waf_profile ~= urlmap_entry.waf_profile then
            handle:logErr("failed check waf_profile")
        end
        if rust_urlmap.name ~= urlmap_entry.name then
            handle:logErr("failed check name")
        end
        -- limit_ids are not checked
    end

    addentry(timeline, "6 session_profiling")
    -- session profiling
    tag_lists(request_map)

    local rust_request_map = nil
    if session_uuid then
        local tagresult = rust.session_tag_request(session_uuid)
        if not tagresult then
            handle:logErr("rust.session_tag_request failed")
        end
    end

    compare_tags("tag_request", session_uuid, request_map)

    if url:startswith("/7060ac19f50208cbb6b45328ef94140a612ee92387e015594234077b4d1e64f1/") then
        -- resources must be cleaned for every implicit "return"
        if session_uuid then
            rust.session_clean(session_uuid)
        end
        -- handle:logDebug("CHALLENGE PHASE02")
        challenge_phase02(handle, request_map)
    end

    local rust_limit_check = nil
    if session_uuid then
        local jlimit_dec = rust.session_limit_check(session_uuid)
        if jlimit_dec then
            rust_limit_check = cjson.decode(jlimit_dec)
        end
    end

    if rust_limit_check then
        handle:logInfo(sfmt("rust.session_limit_check %s", cjson.encode(rust_limit_check)))
    else
        handle:logErr("rust.session_limit_check failed")
    end

    addentry(timeline, "7 limit_check")
    -- rate limit
    -- currently, if limit_check triggers a response, the rust session will not be cleaned
    limit_check(request_map, urlmap_entry["limit_ids"], urlmap_entry["name"])

    compare_tags("limit_check", session_uuid, request_map)

    local rust_acl_check = nil
    if session_uuid then
        local jacl_check = rust.session_acl_check(session_uuid)
        if jacl_check then
            rust_acl_check = cjson.decode(jacl_check)
        end
    end

    if rust_acl_check then
        handle:logInfo(sfmt("rust.session_acl_check %s", cjson.encode(rust_acl_check)))
    else
        handle:logErr("rust.session_acl_check failed")
    end

    if session_uuid then
        handle:logInfo(rust.session_serialize_request_map(session_uuid))
    end

    compare_tags("acl_check", session_uuid, request_map)

    -- if not internal_url(url) then
    -- acl
    addentry(timeline, "8 acl_check")
    local acl_code, acl_result = acl_check(acl_profile, request_map, acl_active)
    local acl_bot_code, acl_bot_result = acl_check_bot(acl_profile, request_map, acl_active)

    -- TODO compare acl result with rust result

    if acl_result then
        handle:logDebug(sfmt("001 ACL REASON: %s", acl_result.reason))
        handle:logDebug(sfmt("001b request_map.attrs: %s", cjson.encode(request_map.attrs) ))
        addentry(timeline, "8b acl_check/tag_request")
        tag_request(request_map, sfmt("acltag:%s" , acl_result.reason))
    end

    if acl_code == ACLDeny or acl_code == ACLForceDeny then
        addentry(timeline, "8c acl_check/deny_request")
        if session_uuid then
            rust.session_clean(session_uuid)
            session_uuid = nil
        end
        custom_response(request_map, {[ "reason" ] = acl_result, ["block_mode"] = acl_active})
    end

    addentry(timeline, "9 challenge_verified")
    local is_human = challenge_verified(handle, request_map)

    addentry(timeline, "9b challenge_verified/tag_request")
    tag_request(request_map, is_human and "human" or "bot")

    if acl_code ~= ACLBypass then
        if acl_bot_code == ACLDenyBot and not is_human then
            handle:logDebug("002 ACL DENY BOT MATCHED!")
            addentry(timeline, "9c challenge_verified/challenge_phase01")
            handle:logDebug("003 ACL DENY BOT MATCHED! << let's do some challenge >>")
            challenge_phase01(handle, request_map, "1")

        else
            local rust_waf_check = nil
            if session_uuid then
                local jwaf_result = rust.session_waf_check(session_uuid)
                if jwaf_result then
                    rust_waf_check = cjson.decode(jwaf_result)
                end
            end

            if rust_waf_check then
                handle:logInfo(sfmt("rust.session_waf_check %s", cjson.encode(rust_waf_check)))
            else
                handle:logErr("rust.session_waf_check failed")
            end

            -- ACLAllow / ACLAllowBot/ ACLNoMatch
            -- move to WAF
            addentry(timeline, "10 waf_check")
            local waf_code, waf_result = waf_check(waf_profile, request_map)
            -- blocked results returns as table
            if type(waf_result) == "table" then
                addentry(timeline, "10b waf_check/tag_request")
                tag_request(request_map, sfmt("wafsig:%s", waf_result.sig_id))

                if waf_code == WAFBlock then
                    addentry(timeline, "10c waf_check/deny_request")
                    local action_params = {
                        ["reason"] = waf_result,
                        ["block_mode"] = waf_active
                    }
                    if session_uuid then
                        rust.session_clean(session_uuid)
                        session_uuid = nil
                    end
                    custom_response(request_map, action_params)
                end
            end
        end
    end
    -- end

    if session_uuid then
        rust.session_clean(session_uuid)
        session_uuid = nil
    end

    -- logging
    addentry(timeline, "11 log_request")
    log_request(request_map)
    addentry(timeline, "12 done")
    handle:logDebug(string.format("timeline %s",cjson.encode(timeline)))

end
