# Current status

An initial implementation of all filtering components had been written. The following is currently handled in Lua:

 * request mapping
 * request replies
 * logging

## Things to fix

 * pervasive testing, making sure the behaviour is in line with what is expected
 * implement asynchronous methods so as not to block envoy -> unfortunately hard than expected
 * performance profiling
 * code structure / refactorings / etc.

# Stateless API

The stateless API can be used to perform filtering operations.

## Functions

### `inspect_request_map`

Takes two arguments:

 * a JSON-encoded string representing the *request_map*
 * a Lua table containing the *grasshopper* functions (such as the imported grasshopper module), or `nil`

It will perform all the curieproxy checks, and return a pair, with:

 * a Decision (see below),
 * a list of strings, containing all encountered errors

# Session API

The session API can be used for fine grained control over the matching process.

## Functions

All functions return pairs, where the first value is the function result (possibly `nil` for functions that don't return anything),
and the second value is a string encoded error (`nil` when there were no errors).

Most functions need other functions to be called before being available:

 * the `rust_init_config` **MUST** be called before any other function is called
 * the `rust_session_init` must be called before any function taking a `session_id` as an argument
 * once the `rust_session_clean` function is called, the corresponding `session_id` is invalidated and will not work anymore
 * the `rust_session_match_urlmap` must be called before most matching functions, as described in the following documentation

### `init_config`

Called without arguments.

Returns a boolean value, `true` meaning the config was loaded without errors.

The "error" part of the returned pair is a list of strings, and not a single string, when errors happen.
It will list all problems encountered when loading the configuration files.

### `session_init`

Takes a single argument : JSON-encoded string representing the *request_map*.

Returns a string, representing a *session id*.

### `session_clean`

Takes a single argument: the *session id*.

Returns a value that can be discarded.

There must be a single call to `session_clean` for each call to `session_init` in order to prevent memory leaks.

### `session_serialize_request_map`

Takes a single argument: the *session id*.

Returns a JSON-encoded object, which is identical to the object sent to `session_init`, except for the list of tags which could have been updated as a result of calling any of the other functions.

### `session_match_urlmap`

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

This function updates the tags with the urlmap specific tags.

### `session_tag_request`

Takes a single argument: the *session id*.

Returns a value that can be discarded.

### `session_flow_check`

Takes a single argument: the *session id*.

Returns a decision (see below).

### `session_limit_check`

**`session_match_urlmap` must have been called before using this function!**

Takes a single argument: the *session id*.

Returns a decision (see below).

### `session_acl_check`

**`session_match_urlmap` must have been called before using this function!**

Takes a single argument: the *session id*.

On success, returns a JSON encoded object, having a single key:

 * if the key is `Bypass`, it represents a force deny/bypass decision
 * if the key is `Match`, it represents the decisions for humans and bots

In all cases, the matching tags are collected. Examples:

```json
{"Match":{"human":null,"bot":null}}
```

No match has been found (results in filtering proceeding to WAF checks).

```json
{"Match":{"human":{"tags":["foo"],"allowed":true},"bot":{"tags":["bar"],"allowed":false}}}
```
Humans are allowed, bots are denied (results in humans being accepted, and bots being challenged).

```json
{"Match":{"human":{"tags":["yyy"],"allowed":false},"bot":null}}
```

Humans are denied, bots are not matched (results in a deny).

```json
{"Bypass":{"tags":["xxx"],"allowed":true}}
```

Bypass (results in the request being allowed).

```json
{"Bypass":{"tags":["xxx"],"allowed":false}}
```

Force deny (results in the request being dropped).

### `session_waf_check`

**`session_match_urlmap` must have been called before using this function!**

Takes a single argument: the *session id*.

Returns a decision (see below).

### The decision data structure

The decision is a json encoded value, with can be of the following form:

 * The string `"Pass"`, meaning the request is allowed at this stage,
 * An object with a single key, `Action`, and a single value representing the action to be taken.

Example, when actions needs to be taken:

```json
{
   "Action" : {
      "atype" : "block",
      "ban" : false,
      "reason" : {
         "sig_subcategory" : "generic",
         "section" : "args",
         "initiator" : "waf",
         "sig_operand" : "/adxmlrpc.php",
         "sig_id" : "100062",
         "sig_msg" : "RFI/LFI/OSCI",
         "sig_category" : "generic",
         "name" : "lol",
         "sig_severity" : 5,
         "value" : "lalalala/adxmlrpc.phpB"
      },
      "status" : 403,
      "headers" : null,
      "content" : "Access denied",
      "extra_tags" : null
   }
}
```

The fields have the following meaning:

 * `atype`: type of the action, can be `block`, `monitor`, or `alter_headers` ;
 * `ban`, a boolean, indicating whether banning had been performed ;
 * `reason`, an arbitrary value, for logging purposes,
 * `status`, http status of the response ;
 * `headers`, an optional object with strings values, for headers to be appended to the request before passing it upstream ;
 * `content`, body content of the response,
 * `extra_tags`, undefined (might be removed in the future).

## Sample code, parallel Rust/Lua execution

Sample code is now [in the repo](https://github.com/curiefense/curiefense/blob/wasm_test/curiefense/curieproxy/lua/session.lua).