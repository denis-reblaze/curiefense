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
    if body_content ~= nil then
        handle.ctx.body_len = body_content:len()
    else
        handle.ctx.body_len = 0
    end
    local meta = { path=handle.var.request_uri, method=handle.req.get_method(), authority=nil }

    -- the meta table contains the following elements:
    --   * path : the full request uri
    --   * method : the HTTP verb
    --   * authority : optionally, the HTTP2 authority field
    local response, err = curiefense.inspect_request(
        meta, headers, body_content, ip_str, grasshopper
    )

    if err then
        handle.log(handle.ERR, sfmt("curiefense.inspect_request_map error %s", err))
    end

    if response then
        local response_table = cjson.decode(response)
        handle.ctx.response = response_table
        handle.log(handle.DEBUG, "decision: " .. response)
        utils.log_nginx_messages(handle, response_table["logs"])
        request_map = response_table["request_map"]
        request_map.handle = handle
        if response_table["action"] == "custom_response" then
            custom_response(request_map, response_table["response"])
        end
    end
end

-- log block stage processing
function log(handle)
    local response = handle.ctx.response
    handle.ctx.response = nil
    local request_map = response.request_map

    local body_len = handle.ctx.body_len
    local req_len = handle.var.request_length 

    local raw_status = handle.var.status
    local status = tonumber(raw_status) or raw_status
    local req = {
        tags=request_map["tags"],
        path=handle.var.uri,
        host=handle.var.host,
        -- TODO: authority
        -- authority= "34.66.199.37:30081",
        tls= tls,
        requestid=handle.var.request_id,
        method=handle.var.request_method,
        response={
          code=status,
          headers=handle.resp.get_headers(),
          trailers=nil,
          bodybytes=0,
          headersbytes=0,
          codedetails="unknown"
        },
        scheme=handle.var.scheme,
        metadata={},
        port=0,
        block_reason=response.response.reason,
        blocked=response.response.block_mode,
    }

    local raw_server_port = handle.var.server_port
    local raw_remote_port = handle.var.remote_port
    local server_port = tonumber(raw_server_port) or raw_server_port
    local remote_port = tonumber(raw_remote_port) or raw_remote_port

    req.downstream = {
      localaddressport=server_port,
      remoteaddress=handle.var.remote_addr,
      localaddress=handle.var.server_addr,
      remoteaddressport=remote_port,
      directlocaladdress=handle.var.server_addr,
      directremoteaddressport=remote_port,
    }

    req.upstream = {}
    req.upstream.cluster = handle.var.proxy_host
    req.upstream.remoteaddress = handle.var.upstream_addr
    req.upstream.remoteaddressport = handle.var.proxy_port
    if not req.upstream.cluster then
        req.upstream.cluster = "?"
    end
    if not req.upstream.remoteaddress then
        req.upstream.remoteaddress = "?"
    end
    if not req.upstream.remoteaddressport then
        req.upstream.remoteaddressport = "?"
    end

    -- TLS: TODO
    req.tls = {
          version= handle.var.ssl_protocol,
          snihostname= handle.var.ssl_preread_server_name,
          ciphersuite= handle.var.ssl_cipher,
          peercertificate= {
            dn=handle.var.ssl_client_s_dn,
            properties= "",
            propertiesaltnames= {}
          },
          localcertificate= {
            dn=handle.var.ssl_client_s_dn,
            properties= "",
            propertiesaltnames= {}
          },
          sessionid= handle.var.ssl_session_id
    }

    req.request = {
        originalpath="",
        geo=request_map["geo"],
        arguments=request_map["args"],
        headers=request_map["headers"],
        cookies=request_map["cookies"],
        -- TODO: we are currently including the length of the first line of the HTTP request
        headersbytes=req_len - body_len,
        bodybytes=body_len
    }

    req.request.attributes=request_map.attrs
    handle.var.request_map = cjson.encode(req)
end
