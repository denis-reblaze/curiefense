

# questions for later

## matching on the uri

The lua code does this (summarized):

```lua
local _uri = urldecode(map.attrs.path)
if _uri:find("?") then
    local path, query = unpack(_uri:split("?", 1))
    map.attrs.path = path
```

This is the path that is used to match urlmaps. Is that not surprising to match on `url_decoded` strings?

## exact matches in tag profiler

Is it expected that exact match works?

```lua
function match_singles(request_map, list_entry)
  for entry_key, list_entries in pairs(list_entry) do
    -- exact request map
    local entry_match = list_entries[request_map[entry_key]]
    request_map.handle:logInfo(string.format("match_singles:: Exact Match? %s %s %s %s", entry_match, entry_key, request_map[entry_key], cjson.encode(list_entries)))
    if entry_match then
      -- request_map.handle:logDebug(string.format("match_singles:: Exact Match! %s %s %s", entry_match, entry_key, request_map[entry_key]))
      return entry_match
    end
    -- exact request map's attr
    entry_match = list_entries[request_map.attrs[entry_key]]
    if entry_match then
      -- request_map.handle:logDebug(string.format("match_singles:: ATTR Match! %s %s %s", entry_match, entry_key, request_map.attrs[entry_key]))
      return entry_match
    end

    -- pattern matching for all but ip or ASN.
    if entry_key ~= 'ip' and entry_key ~= 'asn' then
      for pattern, annotation in pairs(list_entries) do
        local value = request_map.attrs[entry_key]
        if value then
          local val_patt_match = re_match(value, pattern)
          -- request_map.handle:logDebug(string.format("match_singles:: %s matched? %s >>  - regex %s %s", entry_key, val_patt_match, value, pattern))
          if val_patt_match then
            return annotation
          end
        end
      end
    end
  end
  -- no match
  return false
end
```

# differences in behaviour

## content of attrs

 * envoy metadata is currently not mapped into attrs

## Resolving the host
The Lua code retrieves the queried host this way:

```lua
local host = request_map.headers.host or request_map.attrs.authority
```

The Rust code only trusts the `:authority` metadata provided by Envoy.

## tagging regexps

Tagging support regexp and exact match for single and pair entries.
The Lua version will fail on invalid regexps, but the Rust version does not and still allows for exact matching with things that are invalid regexes.