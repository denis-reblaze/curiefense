# Current status

An initial implementation of all filtering components had been written.

## Missing features

 * logging
 * request body parsing

## Things to fix

 * pervasive testing, making sure the behaviour is in line with what is expected
 * implement asynchronous methods so as not to block envoy
 * more sharing, less copying of the configuration
 * code structure / refactorings / etc.

## Sample lua filter

```lua
module(..., package.seeall)

local native      = require "curiedefense"
local cjson       = require "cjson"
local grasshopper = require "grasshopper"

function native_map_request(handle)
    local map = utils.new_request_map()

    local headerm = {}
    for k, v in pairs(handle:headers()) do
        headerm[k] = v
    end
    local metam = {}
    for k, v in pairs(handle:metadata()) do
        metam[k] = v
    end
    local n_map = native.map_request(headerm, metam)

    map.handle = handle
    map.headers = n_map:headers()
    map.cookies = n_map:cookies()
    map.args = n_map:args()
    map.attrs = n_map:attrs()
    map.attrs.tags = {}

    return map
end

function native_inspect(handle)

    local headerm = {}
    for k, v in pairs(handle:headers()) do
        headerm[k] = v
    end
    local metam = {}
    for k, v in pairs(handle:metadata()) do
        metam[k] = v
    end

    res = native.inspect(headerm, metam, grasshopper)
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
```
