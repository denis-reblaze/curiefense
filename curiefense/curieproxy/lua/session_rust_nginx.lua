module(..., package.seeall)

local cjson       = require "cjson"

local curiefense  = require "curiefense"
local grasshopper = require "grasshopper"

local accesslog   = require "lua.accesslog"
local utils       = require "lua.nativeutils"

local sfmt = string.format

local log_request = accesslog.nginx_log_request
local custom_response = utils.nginx_custom_response


function inspect(handle)
    local ip_str = handle.var.remote_addr

    local headers = {}

    local rheaders, err = ngx.req.get_headers()
    if err == "truncated" then
        handle.log(handle.ERR, "truncated headers: " .. err)
    end

    for k, v in pairs(rheaders) do
        headers[k] = v
    end

    handle.log(handle.INFO, cjson.encode(headers))

    handle.req.read_body()
    local body_content = handle.req.get_body_data()
    local meta = { path=handle.var.request_uri, method=handle.req.get_method(), authority=nil }

    -- the meta table contains the following elements:
    --   * path : the full request uri
    --   * method : the HTTP verb
    --   * authority : optionally, the HTTP2 authority field
    local response, err = curiefense.inspect_request(
        meta, headers, body_content, ip_str, grasshopper
    )

    if err then
        handle:log(handle.ERR, sfmt("curiefense.inspect_request_map error %s", err))
    end

    if response then
        local response_table = cjson.decode(response)
        handle.log(handle.INFO, "decision " .. response)
        utils.log_nginx_messages(handle, response_table["logs"])
        request_map = response_table["request_map"]
        request_map.handle = handle
        if response_table["action"] == "custom_response" then
            custom_response(request_map, response_table["response"])
        end
    end

    log_request(request_map)
end
