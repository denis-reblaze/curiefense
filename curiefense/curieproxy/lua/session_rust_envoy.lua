module(..., package.seeall)

local cjson       = require "cjson"

local curiefense  = require "curiefense"
local grasshopper = require "grasshopper"

local accesslog   = require "lua.accesslog"
local utils       = require "lua.utils"

local sfmt = string.format

local log_request = accesslog.envoy_log_request
local map_request = utils.map_request
local custom_response = utils.envoy_custom_response


function inspect(handle)


    local ip_str = utils.extract_ip(handle:headers(), handle:metadata())

    local headers = {}
    local meta = {}
    for k, v in pairs(handle:headers()) do
        if utils.startswith(k, ":") then
            meta[k:sub(2):lower()] = v
        else
            headers[k] = v
        end
    end

    local hbody = handle:body()
    local body_content = nil
    if hbody then
        body_content = hbody:getBytes(0, hbody:length())
    end

    -- the meta table contains the following elements:
    --   * path : the full request uri
    --   * method : the HTTP verb
    --   * authority : optionally, the HTTP2 authority field
    local response, err = curiefense.inspect_request(
        meta, headers, body_content, ip_str, grasshopper
    )

    if err then
        handle:logErr(sfmt("curiefense.inspect_request_map error %s", err))
    end

    if response then
        local response_table = cjson.decode(response)
        handle:logDebug("decision " .. response)
        utils.log_native_messages(handle, response_table["logs"])
        request_map = response_table["request_map"]
        request_map.handle = handle
        if response_table["action"] == "custom_response" then
            custom_response(request_map, response_table["response"])
        end
    end

    log_request(request_map)

end
