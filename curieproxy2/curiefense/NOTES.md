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

# Session API

The session API can be used for fine grained control over the matching process.

## Functions

All functions return an empty result on failure (`nil` with Lua).

Most functions need other functions to be called before being available:

 * the `rust_init_config` **MUST** be called before any other function is called
 * the `rust_session_init` must be called before any function taking a `session_id` as an argument
 * once the `rust_session_clean` function is called, the corresponding `session_id` is invalidated and will not work anymore
 * the `rust_session_match_urlmap` must be called before most matching functions, as described in the following documentation

### `rust_init_config`

Called without arguments.

Returns `true` on success.

### `rust_session_init`

Takes a single argument : JSON-encoded string representing the *request_map*.

Returns a string, representing a *session id*.

### `rust_session_match_urlmap`

Takes a single argument: the *session id*.

Returns a JSON-encoded object, that looks like:

```json
{
   "acl_profile" : "34511ea458ac",
   "acl_active" : true,
   "urlmap" : "default entry",
   "name" : "admin path",
   "waf_profile" : "__default__",
   "limit_ids" : [],
   "waf_active" : true
}
```

It has the same format as a configuration *urlmap entry*, except:

 * there is no `match` field
 * the `urlmap` field contains the name of the matched *urlmap*

## Sample code, parallel Rust/Lua execution

### Initialization

```lua
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

function inspect(handle)
    init(handle)
    native.rust_init_config()

    local request_map = map_request(handle)
    local url = request_map.attrs.path
    local host = request_map.headers.host or request_map.attrs.authority

    local encoded = encode_request_map(request_map)

    -- initialize rust session
    local session_uuid = native.rust_session_init(encode_request_map(request_map))
```

### `match_urlmap`

```lua
    -- ****** lua *******
    local urlmap_entry, url_map = match_urlmap(request_map)
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

    -- ****** rust *******
    local urlmap_entry = native.rust_session_match_urlmap(session_uuid)
    local acl_active        = urlmap_entry["acl_active"]
    local waf_active        = urlmap_entry["waf_active"]
    local acl_profile_id    = urlmap_entry["acl_profile"]
    local waf_profile_id    = urlmap_entry["waf_profile"]
    local acl_profile       = globals.ACLProfiles[acl_profile_id]
    local waf_profile       = globals.WAFProfiles[waf_profile_id]
    -- no need to add tags here, it is done in rust_session_match_urlmap

```

### Tagging

```lua
    -- ****** lua *******
    tag_lists(request_map)

    -- ****** rust *******
    native.rust_session_tag_request(session_uuid)
```
### Cleanup

```lua
    -- retrieve the rust request map
    local rust_request_map = native.rust_session_serialize_request_map(session_uuid)
    handle:logInfo(string.format("rust: %s", rust_request_map))

    -- clean session
    native.rust_session_clean(session_uuid)
end
```