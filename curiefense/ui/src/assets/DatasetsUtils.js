import ip6addr from 'ip6addr'

const CIDRRanges={ "1":"32", "2":"31", "4":"30", "8":"29", "16":"28", "32":"27", "64":"26", "128":"25", "256":"24", "512":"23", "1024":"22", "2048":"21", "4096":"20", "8192":"19", "16384":"18", "32768":"17", "65536":"16", "131072":"15", "262144":"14", "524288":"13", "1048576":"12", "2097152":"11", "4194304":"10", "8388608":"9", "16777216":"8", "33554432":"7", "67108864":"6", "134217728":"5", "268435456":"4", "536870912":"3", "1073741824":"2", "2147483648":"1", "4294967296":"0"}
const CIDRPatterns={ "32": RegExp("(\\d{1,3}\\.){3}\\d{1,3}/32"), "31": RegExp("(\\d{1,3}\\.){3}\\d{1,3}/31"), "30": RegExp("(\\d{1,3}\\.){3}\\d{1,3}/30"), "29": RegExp("(\\d{1,3}\\.){3}\\d{1,3}/29"), "28": RegExp("(\\d{1,3}\\.){3}\\d{1,3}/28"), "27": RegExp("(\\d{1,3}\\.){3}\\d{1,3}/27"), "26": RegExp("(\\d{1,3}\\.){3}\\d{1,3}/26"), "25": RegExp("(\\d{1,3}\\.){3}\\d{1,3}/25"), "24": RegExp("(\\d{1,3}\\.){2}\\d{1,3}\\.0/24"), "23": RegExp("(\\d{1,3}\\.){2}\\d{1,3}\\.0/23"), "22": RegExp("(\\d{1,3}\\.){2}\\d{1,3}\\.0/22"), "21": RegExp("(\\d{1,3}\\.){2}\\d{1,3}\\.0/21"), "20": RegExp("(\\d{1,3}\\.){2}\\d{1,3}\\.0/20"), "19": RegExp("(\\d{1,3}\\.){2}\\d{1,3}\\.0/19"), "18": RegExp("(\\d{1,3}\\.){2}\\d{1,3}\\.0/18"), "17": RegExp("(\\d{1,3}\\.){2}\\d{1,3}\\.0/17"), "16": RegExp("(\\d{1,3}\\.){2}0\\.0/16"), "15": RegExp("(\\d{1,3}\\.){2}0\\.0/15"), "14": RegExp("(\\d{1,3}\\.){2}0\\.0/14"), "13": RegExp("(\\d{1,3}\\.){2}0\\.0/13"), "12": RegExp("(\\d{1,3}\\.){2}0\\.0/12"), "11": RegExp("(\\d{1,3}\\.){2}0\\.0/11"), "10": RegExp("(\\d{1,3}\\.){2}0\\.0/10"), "9": RegExp("(\\d{1,3}\\.){2}0\\.0/9"), "8": RegExp("\\d{1,3}\\.0\\.0\\.0/8"), "7": RegExp("\\d{1,3}\\.0\\.0\\.0/7"), "6": RegExp("\\d{1,3}\\.0\\.0\\.0/6"), "5": RegExp("\\d{1,3}\\.0\\.0\\.0/5"), "4": RegExp("\\d{1,3}\\.0\\.0\\.0/4"), "3": RegExp("\\d{1,3}\\.0\\.0\\.0/3"), "2": RegExp("\\d{1,3}\\.0\\.0\\.0/2"), "1": RegExp("\\d{1,3}\\.0\\.0\\.0/1"), "0": RegExp("0\\.0\\.0\\.0/0") }
const Countries = "Norway;Uruguay;Thailand;Serbia;Germany;Republic of Lithuania;Russia;Eritrea;Hungary;Martinique;Lesotho;Venezuela;Benin;Northern Mariana Islands;Jersey;Fiji;Monaco;Argentina;Cambodia;Slovakia;Democratic Republic of Timor-Leste;Tajikistan;Dominican Republic;Namibia;Laos;Saint Barth\\u00e9lemy;Malta;Angola;Netherlands;Niger;Ireland;Papua New Guinea;French Guiana;Mayotte;Bangladesh;Republic of the Congo;Oman;Brazil;Peru;Kuwait;San Marino;Western Sahara;Azerbaijan;Belize;Uganda;United Kingdom;Guinea-Bissau;Taiwan;Saint Lucia;Saint Helena;Macedonia;Yemen;Tunisia;Guatemala;Congo;China;Senegal;Georgia;Greenland;Kyrgyzstan;Nauru;Republic of Moldova;Sierra Leone;Tanzania;Somalia;Pakistan;Japan;Philippines;Colombia;Myanmar;Honduras;India;Montenegro;Bolivia;Cook Islands;Ukraine;Palau;Liberia;Grenada;Greece;Tuvalu;Mexico;U.S. Virgin Islands;Kenya;Togo;Vietnam;Vanuatu;North Korea;Gabon;St Kitts and Nevis;Suriname;Eswatini;Algeria;Bonaire, Sint Eustatius, and Saba;South Sudan;Poland;British Indian Ocean Territory;Heard Island and McDonald Islands;Bahrain;Gambia;Samoa;Lebanon;Croatia;Cameroon;Andorra;Burkina Faso;Morocco;Dominica;Equatorial Guinea;Singapore;Czechia;Luxembourg;Italy;Guyana;Slovenia;Antarctica;Portugal;El Salvador;Syria;\\u00c5land;Saint Vincent and the Grenadines;Jamaica;Anguilla;S\\u00e3o Tom\\u00e9 and Pr\\u00edncipe;Wallis and Futuna;Guinea;Kosovo;Nigeria;Mali;Burundi;Nicaragua;Bermuda;Trinidad and Tobago;Indonesia;Saudi Arabia;French Polynesia;Malawi;French Southern Territories;Cyprus;Haiti;Libya;Svalbard and Jan Mayen;Sri Lanka;Uzbekistan;Turkey;Federated States of Micronesia;Hashemite Kingdom of Jordan;Tokelau;Liechtenstein;Vatican City;Djibouti;Ghana;Belarus;Estonia;Zimbabwe;Iraq;Mauritania;Turkmenistan;Norfolk Island;Sint Maarten;Barbados;Bosnia and Herzegovina;Israel;Saint Pierre and Miquelon;Saint Martin;Ivory Coast;Solomon Islands;Afghanistan;Faroe Islands;Falkland Islands;Hong Kong;Mozambique;Costa Rica;Aruba;Seychelles;Antigua and Barbuda;Turks and Caicos Islands;Ethiopia;Guernsey;Panama;R\\u00e9union;Macao;Qatar;Sweden;U.S. Minor Outlying Islands;Marshall Islands;Nepal;Mongolia;Chad;Chile;Kiribati;Bhutan;South Africa;American Samoa;Maldives;Ecuador;Australia;United Arab Emirates;New Caledonia;New Zealand;Spain;Cabo Verde;Cura\\u00e7ao;Isle of Man;Rwanda;Finland;Pitcairn Islands;Bouvet Island;Puerto Rico;Egypt;Tonga;United States;Guadeloupe;Zambia;Denmark;Paraguay;South Georgia and the South Sandwich Islands;Comoros;Montserrat;Sudan;South Korea;Austria;Cuba;Kazakhstan;Iran;Bulgaria;Brunei;Gibraltar;Albania;Switzerland;Guam;Mauritius;Cayman Islands;Bahamas;Latvia;Romania;Central African Republic;Madagascar;Belgium;Cocos [Keeling] Islands;France;Palestine;Iceland;Botswana;Niue;Armenia;Christmas Island;Canada;British Virgin Islands;Malaysia".split(";");
const Classes = ["bot", "cloud", "tor", "vpn", "anon-proxy"];

function RangeToCIDR(start_addr, end_addr) {
  if (start_addr === end_addr){
    end_addr += 1
  } else {
    start_addr -= 1
    end_addr +=2
  }
  let range = end_addr - start_addr

  let bits = CIDRRanges[range.toString()];
  if (bits) {
    // convert start address from int to string
    let saddr = ip6addr.parse(start_addr).toString();
    // return the CIDR
    return saddr + "/" + bits;
  }
}

function CIDRToRange(cidr) {
  let sub = ip6addr.createCIDR(cidr)
  return [sub.first().toLong(), sub.last().toLong()]
}

const Titles = {
  "admin": "Admin",
  "allow": "Allow",
  "allow_bot": "Allow Bot",
  "args": "Arguments",
  "attrs": "Attributes",
  "audit-log": "Audit Log",
  "bypass": "Bypass",
  "cookies": "Cookies",
  "curiefense-lists": "Curiefense Lists",
  "customsigs": "Custom Signatures",
  "deny": "Deny",
  "deny_bot": "Deny Bot",
  "events-and-attacks": "Events & Attacks",
  "external-lists": "External Lists",
  "force_deny": "Enforce Deny",
  "headers": "Headers",
  "names": "Name",
  "reg": "Regex",
  "regex": "Regex",
  "saml2-sso": "SAML2 SSO",
  "top-activities": "Top Activities",
  "traffic-overview": "Traffic Overview",
  "update-log": "Update log",
  "version-control": "Version Control",

  "headers-entry": "Header",
  "cookies-entry": "Cookie",
  "args-entry": "Argument",
  "attrs-entry": "Attribute",


  "aclprofiles": "ACL Profiles",
  "limits": "Rate Limits",
  "urlmaps": "URL Maps",
  "wafprofiles": "WAF Profiles",
  "wafsigs": "WAF Signatures",
  "profilinglists": "Profiling Lists"
}

const LimitRulesTypes = {
  "headers": "Header",
  "cookies": "Cookie",
  "args": "Argument",
  "attrs": "Attribute"
}

const LimitAttributes = {
  "ip": "IP Address",
  "asn": "Provider",
  "uri": "URI",
  "path": "Path",
  "tags": "Tag",
  "query": "Query",
  "method": "Method",
  "company": "Company",
  "country": "Country",
  "authority": "Authority",
}

const LimitActions = {
  "default": {"title": "Default (503)"},
  "challenge": {"title": "Challenge"},
  "monitor": {"title": "Monitor"},
  "response": {"title": "Response", "params": {"status": "", "content": ""}},
  "redirect": {"title": "Redirect", "params": {"status": "30[12378]", "location": "https?://.+"}},
  "ban": {"title": "Ban", "params": {"ttl": "[0-9]+", "action": { "type": "default", "params": {} } }},
  "request_header": {"title": "Header", "params": {"headers": ""}}
}

function UUID() {
    var dt = new Date().getTime();
    var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = (dt + Math.random()*16)%16 | 0;
        dt = Math.floor(dt/16);
        return (c=='x' ? r :(r&0x3|0x8)).toString(16);
    });
    return uuid;
}

function UUID2() { return UUID().split("-")[4] }

const NewDocEntryFactory = {
    aclprofiles() {
        return  {
          "id": UUID2(),
          "name": "NEW ACL",

          "allow": [],
          "allow_bot": [],
          "deny_bot": [],
          "bypass": [],
          "force_deny":[],
          "deny": []
        }
    },

    wafprofiles() {
      return {
        "id": UUID2(),
        "name": "NEW WAF",
        "ignore_alphanum": true,

        "max_header_length": 1024,
        "max_cookie_length": 1024,
        "max_arg_length": 1024,

        "max_headers_count": 42,
        "max_cookies_count": 42,
        "max_args_count": 512,

        "args": {
          "names": [],
          "regex": []
        },
        "headers": {
          "names":[],
          "regex": []
        },
        "cookies": {
          "names": [],
          "regex": []
        }
      }
    },

    profilinglists() {
      return {
        "id": UUID2(),
        "name": "New Profiling List",
        "source": "self-managed",
        "mdate": (new Date()).toISOString(),
        "notes": "New List Notes and Remarks",
        "entries_relation": "OR",
        "active": true,
        "tags": [],
        "entries": []
      }
    },

    urlmaps () {
      return {
        "id": UUID2(),
        "name": "NEW URL MAP",
        "match": "__default__",
        "map": [
          {
            "match": "/",
            "name": "default",
            "acl_profile": "__default__",
            "waf_profile": "__default__",
            "acl_active": true,
            "waf_active": true,
            "limit_ids": []
          }
        ]
      }
    },
    limits() {
      return {
        "id": UUID2(),
        "description": "New Rate Limit Rule",
        "name": "New Rate Limit Rule",
        "limit": "3",
        "key": [
          {
            "attrs": "ip"
          }
        ],
        "ttl": "180",
        "action": {
          "type": "default"
        },
        "exclude": {
          "headers": {},
          "cookies": {},
          "args": {},
          "attrs": {"tags": "whitelist"}
        },
        "include": {
          "headers": {},
          "cookies": {},
          "args": {},
          "attrs": {"tags": "blacklist"}
        },
        "pairwith": {
          "self": "self"
        }
      }
    }

}

const ConfAPIRoot = "/conf/api"
const ConfAPIVersion = "v1"

const LogsAPIRoot = "/logs/api"
const LogsAPIVersion = "v1"

const ACCESSLOG_COLUMNS_NAMES="rowid,ProtocolVersion,SampleRate,DownstreamRemoteAddress,DownstreamRemoteAddressPort,DownstreamLocalAddress,DownstreamLocalAddressPort,StartTime,TimeToLastRxByte,TimeToFirstUpstreamTxByte,TimeToLastUpstreamTxByte,TimeToFirstUpstreamRxByte,TimeToLastUpstreamRxByte,TimeToFirstDownstreamTxByte,TimeToLastDownstreamTxByte,UpstreamRemoteAddress,UpstreamRemoteAddressPort,UpstreamLocalAddress,UpstreamLocalAddressPort,UpstreamCluster,FailedLocalHealthcheck,NoHealthyUpstream,UpstreamRequestTimeout,LocalReset,UpstreamRemoteReset,UpstreamConnectionFailure,UpstreamConnectionTermination,UpstreamOverflow,NoRouteFound,DelayInjected,FaultInjected,RateLimited,UnauthorizedDetails,RateLimitServiceError,DownstreamConnectionTermination,UpstreamRetryLimitExceeded,StreamIdleTimeout,InvalidEnvoyRequestHeaders,DownstreamProtocolError,Curiefense,UpstreamTransportFailureReason,RouteName,DownstreamDirectRemoteAddress,DownstreamDirectRemoteAddressPort,TlsVersion,TlsCipherSuite,TlsSniHostname,LocalCertificateProperties,LocalCertificatePropertiesAltNames,PeerCertificateProperties,PeerCertificatePropertiesAltNames,TlsSessionId,RequestMethod,Scheme,Authority,Port,Path,UserAgent,Referer,ForwardedFor,RequestId,OriginalPath,RequestHeadersBytes,RequestBodyBytes,RequestHeaders,ResponseCode,ResponseHeadersBytes,ResponseBodyBytes,ResponseHeaders,ResponseTrailers,ResponseCodeDetails"


const ACCESSLOG_SQL = `SELECT * FROM (SELECT *, CAST(row_to_json(row) as text) as json_row  FROM logs row) rows`;
const ACCESSLOG_SQL_SUFFIX = " ORDER BY StartTime DESC LIMIT 2048"
const ACCESSLOG_COLUMNS = ACCESSLOG_COLUMNS_NAMES.split(",")

export default {
  name: "DatasetsUtils",
  CIDRRanges,
  CIDRPatterns,
  Countries,
  ASNs,
  Classes,
  RangeToCIDR,
  CIDRToRange,
  Titles,
  LimitActions,
  LimitAttributes,
  LimitRulesTypes,
  UUID,
  UUID2,
  ConfAPIRoot,
  ConfAPIVersion,
  NewDocEntryFactory,
  LogsAPIRoot,
  LogsAPIVersion,
  ACCESSLOG_SQL,
  ACCESSLOG_SQL_SUFFIX,
  ACCESSLOG_COLUMNS
}