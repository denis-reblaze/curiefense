module(..., package.seeall)

local cjson = require "cjson"

local json_encode   = cjson.encode
local json_decode   = cjson.decode

-- dynamic metadata filter name
DMFN = "com.reblaze.curiefense"
LOG_KEY = "request.info"

function get_log_table(request_map)
  -- handle is userData which is not serilizable
  local entries = {
    ["geo"]     = "geo",
    ["headers"] = "headers",
    ["cookies"] = "cookies",
    ["args"]    = "arguments",
    ["attrs"]   = "attributes",
    ["tags"]    = "tags"
  }

  local log_table = {}

  for luaname, logname in pairs(entries) do
    log_table[logname] = request_map[luaname]
  end

  -- local tags = log_table.attributes.tags

  -- if tags then
  --   local tagnames = {}
  --   local n = 0

  --   for name,v in pairs(tags) do
  --     n = n + 1
  --     tagnames[n] = name
  --   end

  --   log_table.tags = tagnames
  --   log_table.attributes.tags = nil
  -- end

  log_table.blocked = log_table.attributes.blocked
  log_table.block_reason = log_table.attributes.block_reason

  log_table.attributes.blocked = nil
  log_table.attributes.block_reason = nil
  return log_table
end

function get_log_str_map(request_map)
  local log_table = get_log_table(request_map)
  local str_map = json_encode(log_table)
  return str_map
end

function envoy_log_request(request_map)
  local request_handle = request_map.handle
  local str_map = get_log_str_map(request_map)
  request_handle:logDebug(str_map)
  request_handle:streamInfo():dynamicMetadata():set(DMFN, LOG_KEY, str_map)
end
