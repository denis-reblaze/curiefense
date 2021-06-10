module(..., package.seeall)

local acl           = require "lua.acl"
local waf           = require "lua.waf"
local globals       = require "lua.globals"
local utils         = require "lua.utils"
local tagprofiler   = require "lua.tagprofiler"
local flowcontrol   = require "lua.flowcontrol"
local restysha1     = require "lua.resty.sha1"
local limit         = require "lua.limit"
local accesslog     = require "lua.accesslog"
local challenge     = require "lua.challenge"
local utils         = require "lua.utils"

local cjson       = require "cjson"

local init          = globals.init

local waf_check         = waf.check
local acl_check         = acl.check
local acl_check_bot     = acl.check_bot
local limit_check       = limit.check
local flowcontrol_check = flowcontrol.check

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

local challenge_verified = challenge.verified
local challenge_phase01 = challenge.phase01
local challenge_phase02 = challenge.phase02

local sfmt = string.format

function match_urlmap(host, url, request_map)
    local default_map = nil
    local selected_map = nil
    local matched_path = "/"
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
        -- TODO: add city as tags
        sfmt("asn:%s", request_map.geo.asn)
    })

end

local gettime = socket.gettime

-- function addentry(t, msg)
--     table.insert(t, {gettime()*1000, msg})
-- end

function inspect(handle)

    local timeline = {}

    init(handle)

    -- handle:logDebug("inspection initiated")
    local request_map = map_request(handle)

    local url = request_map.attrs.path
    local host = request_map.headers.host or request_map.attrs.authority


    -- unified the following 3 into a single operaiton
    local urlmap_entry, url_map = match_urlmap(host, url, request_map)

    local acl_active        = urlmap_entry["acl_active"]
    local waf_active        = urlmap_entry["waf_active"]
    local acl_profile_id    = urlmap_entry["acl_profile"]
    local waf_profile_id    = urlmap_entry["waf_profile"]
    local acl_profile       = globals.ACLProfiles[acl_profile_id]
    local waf_profile       = globals.WAFProfiles[waf_profile_id]

    map_tags(request_map,
        sfmt('urlmap:%s', url_map.name),
        sfmt('urlmap-entry:%s', urlmap_entry.name),
        sfmt("aclid:%s", acl_profile_id),
        sfmt("aclname:%s", acl_profile.name),
        sfmt("wafid:%s", waf_profile_id),
        sfmt("wafname:%s", waf_profile.name)
    )


    -- session profiling
    tag_lists(request_map)

    local action = flowcontrol_check(request_map)

    if action then
        if action.type == "default" then
            action = {
                ["type"] = "default",
                ["params"] = {
                    ["status"] = "503",
                    ["block_mode"] = true
                }
            }
        end

        custom_response(request_map, action.params)
    end

    if url:startswith("/7060ac19f50208cbb6b45328ef94140a612ee92387e015594234077b4d1e64f1/") then
        -- handle:logDebug("CHALLENGE PHASE02")
        challenge_phase02(handle, request_map)
    end


    -- rate limit
    limit_check(request_map, urlmap_entry["limit_ids"], urlmap_entry["name"])

    -- if not internal_url(url) then
    -- acl
    local acl_code, acl_result = acl_check(acl_profile, request_map, acl_active)
    local acl_bot_code, acl_bot_result = acl_check_bot(acl_profile, request_map, acl_active)

    if acl_result then
        handle:logDebug(sfmt("001 ACL REASON: %s", acl_result.reason))
        handle:logDebug(sfmt("001b request_map.attrs: %s", cjson.encode(request_map.attrs) ))
        tag_request(request_map, sfmt("acltag:%s" , acl_result.reason))
    end

    if acl_code == ACLDeny or acl_code == ACLForceDeny then
        custom_response(request_map, {[ "reason" ] = acl_result, ["block_mode"] = acl_active})
    end

    local is_human = challenge_verified(handle, request_map)

    tag_request(request_map, is_human and "human" or "bot")

    if acl_code ~= ACLBypass then
        if acl_bot_code == ACLDenyBot and not is_human then
            challenge_phase01(handle, request_map, "1")
        else
            -- ACLAllow / ACLAllowBot/ ACLNoMatch
            -- move to WAF
            local waf_code, waf_result = waf_check(waf_profile, request_map)
            -- blocked results returns as table
            if type(waf_result) == "table" then
                tag_request(request_map, sfmt("wafsig:%s", waf_result.sig_id))

                if waf_code == WAFBlock then
                    local action_params = {
                        ["reason"] = waf_result,
                        ["block_mode"] = waf_active
                    }
                    custom_response(request_map, action_params)
                end
            end
        end
    end

    -- logging
    log_request(request_map)

end
