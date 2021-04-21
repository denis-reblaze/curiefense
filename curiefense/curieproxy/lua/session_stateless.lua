module(..., package.seeall)

local accesslog   = require "lua.accesslog"
local cjson       = require "cjson"
local curiefense  = require "curiefense"
local grasshopper = require "grasshopper"
local utils       = require "lua.utils"

local map_request   = utils.map_request
local log_request   = accesslog.log_request

local sfmt = string.format


function inspect(handle)

    local request_map = map_request(handle)

    local request_map_as_json = cjson.encode({
        headers = request_map.headers,
        cookies = request_map.cookies,
        attrs = request_map.attrs,
        args = request_map.args,
        geo = request_map.geo
    })

    local response, err = curiefense.inspect_request_map(request_map_as_json, grasshopper)

    if err then
        for _, r in ipairs(err) do
            handle:logErr(sfmt("curiefense.inspect_request_map error %s", r))
        end
    end

    if response then
        local response_table = cjson.decode(response)
        handle:logDebug("decision " .. response)
        request_map = response_table["request_map"]
        request_map.handle = handle
        if response_table["action"] == "custom_response" then
            custom_response(request_map, response_table["response"])
        end
    end

    log_request(request_map)

end
