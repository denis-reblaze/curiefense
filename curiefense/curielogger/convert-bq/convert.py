import fileinput
import json
import sys
import datetime

def dictify_headers(request):
    block = request["request_headers"]
    ret = dict((i["h_name"], i["h_value"]) for i in block)
    ret["referer"] = request["referer"]
    ret["user-agent"] = request["user_agent"]
    ret["host"] = request["host"]
    return ret

def dictify_cookies(block):
    return dict((i["c_name"], i["c_value"]) for i in block)

def dictify_args(block):
    return dict((i["arg_name"], i["arg_value"]) for i in block)

def tagify (tags, record):
    tags = list(tags)

    if record["is_anonymizer"]:
        tags.append("anonymizer")

    if record["is_human"]:
        tags.append("human")
    else:
        tags.append("bot")

    if record["is_proxy"]:
        tags.append("proxy")

    if record["is_tor"]:
        tags.append("tor")

    if record["is_vpn"]:
        tags.append("vpn")

    return tags


def reblazer_to_elastic(json_line):
    ngxjson = json.loads(json_line)
    anything_else = json.loads(ngxjson.get('anything_else', "{}"))

    eljson = {}

    eljson["requestid"] = ngxjson["request_id"]
    eljson["@timestamp"] = datetime.datetime.fromtimestamp(float(ngxjson["timestamp"])).isoformat()

    tls_used = len(ngxjson["ssl_protocol"]) > 2
    eljson["scheme"] = (tls_used and "https") or "http"
    eljson["authority"] = ngxjson["host"]
    eljson["port"] = ngxjson["port"] = (tls_used and 443) or 80
    eljson["method"] = ngxjson["method"]
    eljson["path"] = ngxjson["uri"]
    eljson["blocked"] = ngxjson["blocked"]
    eljson["block_reason"] = {"reason": ngxjson["block_reason"]}

    eljson["downstream"] = {
        "remoteaddress": ngxjson["remote_addr"]
    }

    if len(ngxjson["upstream_addr"]) > 1:
        upstream = ngxjson["upstream_addr"].split(":")
        addr = upstream[0]
        # port = int(upstream[1].split(",")[0])
        eljson["upstream"] = {
            "remoteaddress": addr,
            "remoteaddressport": 0
        }

    eljson["tls"] = {
        "ciphersuite": ngxjson["ssl_cipher"],
        "version": ngxjson["ssl_protocol"]
    }

    eljson["request"] = {
        "bodybytes": int(ngxjson["request_length"]),
        "originalpath": ngxjson["request"],
        "headers": anything_else["headers"],
        "cookies": anything_else["cookies"],
        "arguments": anything_else["args"],
        # "attributes": dictify_attrs(ngxjson),
    }

    eljson["request"]["headers"]["referer"] = ngxjson["referer"]
    eljson["request"]["headers"]["user-agent"] = ngxjson["user_agent"]
    eljson["request"]["headers"]["host"] = ngxjson["host"]

    eljson["tags"] = tagify(anything_else.get("tags", {}).keys(), ngxjson)

    eljson["response"] = {
        "bodybytes": int(ngxjson["bytes_sent"]),
        "code": int(ngxjson["status"])
    }

    return eljson["requestid"], json.dumps(eljson)


def main():

    for line in fileinput.input():
        try:
            recid, eljson = reblazer_to_elastic(line)
            index_line = json.dumps({
                "index" : {
                    "_index" : "curieaccesslog",
                    "_id" : recid
                    }
                })
            print (index_line, file=sys.stdout)
            print (eljson, file=sys.stdout)

        except Exception as err:
            print(err, file=sys.stderr)
            print("Unexpected error:", sys.exc_info()[0], file=sys.stderr)


if __name__ == "__main__":
    main()