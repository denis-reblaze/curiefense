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

# JSON API

If not specified here, the referenced data structures are to be looked up in the JSON schema repositories.
If the input is malformed, the functions return an object with the following property:

 * `error`: `string`, representing the error

When called from LUA, all arguments must be passed as JSON-encoded strings, and all output is returned as a JSON-encoded string.

## `match_urlmap`

### Arguments

 * `config_path`: `string`, path to the configuration directory
 * `request_map`: `RequestMap`

### Output

On success, returns an object with the following properties:

 * `hostmapid`: `string`, representing the id of the matched "host map"
 * `urlmap`: `object`, with the following properties:

   * `name`: `string`
   * `acl_active`: `bool`
   * `waf_active`: `bool`
   * `acl_profile`: `string`, id of the selected acl profile
   * `waf_profile`: `string`, id of the selected waf profile
   * `limits`: `list` of `string`, ids of the rate limiting to enforce

On failure, returns `null`.

### Notes

This function can fail when:

 * The configuration is malformed. Note that the whole configuration is parsed, which means that, for example, a problem in the WAF profiles will cause this function to fail.
 * No host map matched, and no default was provided.
 * No url map matched, and no default was provided.


## `tag_request`

### Arguments

 * `request_map`: `RequestMap`

### Output

A list of `string`, representing the tags.

### Notes

This function can't fail.

Note that the urlmap-related tags are not added by this function.

## `limit_checks`

### Arguments

 * `request_map`: `RequestMap`
 * `limits`: list of `Limit`
 * `tags`: list of `string`

### Output

An object with the following entries:

 * `decision`: `Decision`
 * `tags`: list of `string`, the updated list of tags

### Note

While this function cannot fail, it might fail to mark requests as having exceeded limits (for example, when the Redis server is down).

## `check_acl`

### Arguments

 * `tags`: list of `string`
 * `profile`: `ACLProfile`

### Output

Returns either a "bypass" or "matches" object, with the following configuration:

#### Bypass

An object, with the following entry:

 * `bypass`: `ACLDecision`

#### Matches

An object with the following entries:

 * `human`, `ACLDecision` or `null`
 * `bot`, `ACLDecision` or `null`

#### ACLDecision

An object with the following entries:

 * `allowed`: `bool`, as its name implies, the request is allowed when set to `true`, and denied when set to `false`
 * `tags`: list of `string`, the tags that were matched when reaching this decision

### Note

This function can't fail.

The output represents the result of an ACL check.
It either returns a "bypass" result (force deny, or bypass), or a pair of results, depending on whether the matched client is a "human" or a "bot".

## `waf_check`

### Arguments

 * `request_map`: `RequestMap`
 * `profile`: `ACLProfile`

### Output

Returns a `Decision`

### Note

This function can't fail.

# Schemas

## `RequestMap`

Note that this specification is only a subset of what the Lua `request_map` structure contains.

```json
{
  "$schema": "http://json-schema.org/draft-06/schema#",
  "$ref": "#/definitions/RequestMap",
  "definitions": {
    "RequestMap": {
      "type": "object",
      "additionalProperties": true,
      "properties": {
        "headers": {
          "$ref": "#/definitions/StrMap",
          "$comment": "Request headers, except the Cookies header"
        },
        "cookies": {
          "$ref": "#/definitions/StrMap",
          "$comment": "Request cookies"
        },
        "params": {
          "$ref": "#/definitions/StrMap",
          "$comment": "URL parameters"
        },
        "attrs": {
          "$ref": "#/definitions/Attrs",
          "$comment": "Various request attributes"
        }
      },
      "required": [
        "headers",
        "params",
        "cookies",
        "attrs"
      ],
      "title": "RequestMap"
    },
    "StrMap": {
      "type": "object",
      "additionalProperties": {
        "type": "string"
      }
    },
    "Attrs": {
      "type": "object",
      "additionalProperties": true,
      "properties": {
        "path": {
          "type": "string",
          "$comment": "the path part of the URL"
        },
        "method": {
          "type": "string",
          "$comment": "the HTTP method"
        },
        "ip": {
          "type": "string",
          "$comment": "source IP address, canonical string representation"
        },
        "query": {
          "type": "string",
          "$comment": "the query part of the URL"
        },
        "authority": {
          "type": "string",
          "$comment": "optional field (HTTP >=2)"
        },
        "uri": {
          "type": "string",
          "$comment": "the url decoded URI (might contain arbitrary binary data)"
        },
        "asn": {
          "type": "integer",
          "$comment": "ASN number"
        }
      },
      "required": [
        "ip",
        "method",
        "path",
        "query",
        "remote_addr",
        "uri"
      ],
      "title": "Attrs"
    }
  }
}
```