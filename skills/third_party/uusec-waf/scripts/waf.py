#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UUSEC WAF console REST API client -- standard library only, no third-party deps, multi-instance.

Usage
-----
  waf.py init                                     generate a config skeleton (you fill in url/token)
  waf.py hosts                                    list every instance in the config
  waf.py hosts --add <name> --url <URL> [--token <T>|--token -] [--update]
                                                  fill in an instance for you (`--token -` = read from stdin, no echo)
  waf.py -i <instance> ping                       connectivity + auth self-check
  waf.py -i <instance> list <resource>            quick list: sites|rules|ruleset|certs|plugins|users
  waf.py -i <instance> api <METHOD> <PATH> [BODY]   send an arbitrary request
  waf.py -i <instance> logs [-q <QUERY_JSON>] [--table] [--raw] [--page N] [--size N]
                                                   log query (the request field is hidden by default)
  waf.py -i <instance> top | total | live | report    dashboard quick data
  waf.py -i <instance> ruleset <ID>                print the rule list inside the given ruleset
  waf.py -i <instance> get rule <ID> [--field <field>] [--out <file>]
                                                   fetch a single rule field (default: content)
  waf.py -i <instance> push rule <ID|new> --file <file> [--name N] [--lf] [--dry-run]
                                                   write back the rule body (byte-exact; new = create)
  waf.py -i <instance> push ruleset <ID> [--set JSON | --add ID... | --remove ID...]
                                                   change the ruleset's enabled list
  waf.py -i <instance> ipblock [--check <IP> | --unlock <IP> | --check-all | --unlock-all]
                                                   ban list (--check-all is the same) / check status / unban
  waf.py -i <instance> backup [config|db] [--out <file>]
                                                   export config / database backup (mandatory before changes)
  waf.py -i <instance> delete rule|ruleset|cert|plugin <ID> [--dry-run]
                                                   delete (production write, get authorization first)
  waf.py -i <instanceA> diff rule|ruleset <ID> --with <instanceB>
                                                   compare the same rule/ruleset across instances (byte level)
  waf.py -h | --help                               help

Write Path Notes
----------------
  * `get`/`push` work around two hard problems: "there is no GET /rules/{id}" and
    "the body cannot be inlined into a shell". Write the body to a file first, edit it,
    then write it back -- **byte-exact** (newlines are not normalized unless --lf is given).
  * `push` GETs the current object first, replaces only the given fields, then writes back --
    it never guesses the field shape.
    Add `--dry-run` to print the body it would send without sending any request.
  * Write operations require a non-empty `waf_nodes`; they are production changes, so get
    authorization first (see the operating discipline in SKILL.md).

Instance Sources (priority)
---------------------------
  1. `-i <instance>`: pick an instance from the config file ~/.config/waf-hosts.json (recommended).
  2. Environment variables (fallback when -i is absent): WAF_API_URL + WAF_API_TOKEN.

Config File Format (~/.config/waf-hosts.json, permissions must be 600)
---------------------------------------------------------------------
  {
    "<instance>": {"url": "https://<server-IP>:4443", "token": "<Api-Token>"}
  }
  - New users: run `waf.py init` to generate the skeleton, fill it in, then `-i <instance> ping` to self-check.
  - Adding a new WAF: just add another block to that file, this script needs no changes; `hosts --add` can also fill it in.
  - The token lives in a 600-permission file, read by the script; it never passes through model context and never enters the conversation.
  - Set url to a reachable panel address (127.0.0.1 / LAN IP / domain all work), with the panel port 4443.
  - Copy the Api-Token from the panel's "System Settings -> API Access Token" (copying requires a panel login; afterwards the API only needs that token).

Security Notes
--------------
  * All requests skip self-signed certificate verification (panels are self-signed by default).
  * The `logs` subcommand strips the `request` field by default -- that field carries credentials
    such as Authorization / Cookie.
    When you really need the raw message, add `--raw` explicitly and make sure it is neither
    written to disk nor echoed.
  * A failed authentication returns `{"message":"missing or malformed jwt"}`, usually a
    verbatim token error.

Common Misuse (see references/management-api.md for details)
-----------------------------------------------------------
  * Log queries must use POST; `GET /logs` returns Not Found.
  * The log `time_range` must include hours/minutes/seconds; a bare date silently returns 0 rows.
    This script fills in the missing time automatically.
  * `level: 5` means "all".
  * Use `GET /rules` to fetch the rule body; the content returned by `GET /ruleset/rules` is always empty.
"""
import difflib
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

CONFIG_PATH = os.path.expanduser("~/.config/waf-hosts.json")
API_PREFIX = "/api/v1"

BASE = None
TOKEN = None
INSTANCE = None


# --------------------------------------------------------------------------- #
# Instance selection
# --------------------------------------------------------------------------- #
def _load_config(raw=False):
    """Read the config. With raw=False, skip documentation keys starting with `_` (they are not instances)."""
    if not os.path.exists(CONFIG_PATH):
        _die("config file not found: %s\n"
             "  run `waf.py init` to generate a skeleton first, or use the environment variables "
             "WAF_API_URL + WAF_API_TOKEN"
             % CONFIG_PATH)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:                                    # noqa: BLE001
        _die("failed to parse the config file: %s" % exc)
    if raw:
        return data
    return {k: v for k, v in data.items() if not str(k).startswith("_")}


def _is_placeholder(v):
    """Placeholder values in the skeleton (empty / `<...>`) do not count as "configured"."""
    s = str(v or "").strip()
    return (not s) or s.startswith("<")


def _save_config(cfg):
    """Atomically write the config back, permissions fixed at 600 (credential file, never in git, never in the conversation)."""
    os.makedirs(os.path.dirname(CONFIG_PATH) or ".", mode=0o700, exist_ok=True)
    tmp = "%s.tmp-%d" % (CONFIG_PATH, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)


SKELETON = {
    "_doc": ("each key is one WAF instance: url = a reachable panel address (e.g. https://<server-IP>:4443, "
             "that port is the panel port; 80/443 are the data plane and 4447 is the built-in management plane); "
             "token = the string copied from the panel's \"System Settings -> API Access Token\". "
             "This file must have 600 permissions; do not commit it to git and do not paste it into the conversation."),
    "mywaf": {"url": "https://<server-IP>:4443", "token": "<paste your Api-Token here>"},
}


def cmd_init(force=False):
    """Generate a config skeleton for you to fill in url / token yourself."""
    if os.path.exists(CONFIG_PATH):
        if not force:
            print("config file already exists: %s" % CONFIG_PATH)
            print("  (to merely add an instance use `hosts --add`; to really rebuild use `init --force`, the old file is backed up first)")
            return
        bak = "%s.bak-%s" % (CONFIG_PATH, time.strftime("%Y%m%d-%H%M%S"))
        os.replace(CONFIG_PATH, bak)
        os.chmod(bak, 0o600)
        print("old config backed up: %s" % bak)
    _save_config(SKELETON)
    print("config skeleton generated: %s (permissions 600)" % CONFIG_PATH)
    print("  1) rename `mywaf` to your instance name and fill in url and token (or let the agent fill it in with `hosts --add`)")
    print("  2) self-check: python3 %s -i <instance> ping" % sys.argv[0])


def _select(name):
    global BASE, TOKEN, INSTANCE
    cfg = _load_config()
    if name not in cfg:
        _die("no instance '%s' in the config file. Available: %s" % (name, ", ".join(cfg) or "(none)"))
    entry = cfg[name] or {}
    BASE = str(entry.get("url", "")).rstrip("/")
    TOKEN = str(entry.get("token", ""))
    INSTANCE = name
    if not BASE or not TOKEN:
        _die("instance '%s' is missing url or token" % name)


def _use_env():
    global BASE, TOKEN, INSTANCE
    BASE = os.environ.get("WAF_API_URL", "").rstrip("/")
    TOKEN = os.environ.get("WAF_API_TOKEN", "")
    INSTANCE = "(env)"
    if not BASE or not TOKEN:
        _die("no instance: use -i <instance> to pick a configured instance, "
             "or set the environment variables WAF_API_URL + WAF_API_TOKEN")


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def _req(method, path, body=None, timeout=30, raw_path=False):
    """Send a request. When path does not start with /, the /api/v1 prefix is added automatically."""
    url = path if raw_path else (BASE + API_PREFIX + path)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE              # panels are self-signed by default
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("Api-Token", TOKEN)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            # Some endpoints return JSON with a UTF-8 BOM (e.g. /setting/ipBlock/all);
            # decoding with utf-8-sig strips the BOM automatically, otherwise json.loads fails.
            return resp.status, resp.read().decode("utf-8-sig", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8-sig", "replace")
    except Exception as exc:                                    # noqa: BLE001
        _die("request failed: %s" % exc)


def _pretty(text):
    try:
        return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
    except Exception:                                           # noqa: BLE001
        return text


def _die(msg):
    sys.stderr.write("[error] %s\n" % msg)
    sys.exit(2)


# --------------------------------------------------------------------------- #
# Log query helpers
# --------------------------------------------------------------------------- #
def _norm_time_range(tr):
    """Pad a bare date into a time range with hours/minutes/seconds.

    For `["YYYY-MM-DD","YYYY-MM-DD"]` the panel silently returns 0 rows;
    hours/minutes/seconds are required for it to take effect. This fills them in
    automatically so you do not hit that trap.
    """
    if not tr:
        return []
    if not isinstance(tr, (list, tuple)) or len(tr) != 2:
        _die("time_range must be a two-element array [start, end]")
    out = []
    for idx, item in enumerate(tr):
        s = str(item).strip()
        if not s:
            return []
        if " " not in s:
            s = s + (" 00:00:00" if idx == 0 else " 23:59:59")
        out.append(s)
    return out


def _strip_request(record):
    """Remove the request field, which carries credentials."""
    if isinstance(record, dict) and "request" in record:
        rec = dict(record)
        raw = rec.pop("request", "")
        rec["request"] = "<omitted, %d bytes, contains credentials; use --raw if needed>" % len(str(raw))
        return rec
    return record


def cmd_logs(args):
    query, page, size, table, want_raw = {}, 1, 20, False, False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-q" and i + 1 < len(args):
            try:
                query = json.loads(args[i + 1])
            except Exception as exc:                             # noqa: BLE001
                _die("failed to parse -q: %s" % exc)
            i += 2
            continue
        if a == "--page" and i + 1 < len(args):
            page = int(args[i + 1]); i += 2; continue
        if a == "--size" and i + 1 < len(args):
            size = int(args[i + 1]); i += 2; continue
        if a == "--table":
            table = True; i += 1; continue
        if a == "--raw":
            want_raw = True; i += 1; continue
        _die("logs: unknown argument: %s" % a)

    query.setdefault("level", 5)                # 5 = all
    if "time_range" in query:
        query["time_range"] = _norm_time_range(query["time_range"])

    status, text = _req("POST", "/logs",
                        {"page": page, "page_size": size, "query": query})
    try:
        payload = json.loads(text)
    except Exception:                                            # noqa: BLE001
        _die("non-JSON response (HTTP %s): %s" % (status, text[:200]))
    if isinstance(payload, dict) and payload.get("err"):
        _die(payload["err"])

    rows = payload.get("data", [])
    total = payload.get("total", 0)
    if not want_raw:
        rows = [_strip_request(r) for r in rows]

    if table and rows:
        print("total=%s  page=%s  size=%s" % (total, page, size))
        print("%-20s %-8s %-18s %-16s %-26s %s" %
              ("updated_at", "level", "rule", "ip", "host", "url"))
        for r in rows:
            print("%-20s %-8s %-18s %-16s %-26s %s" % (
                str(r.get("updated_at", ""))[:19],
                r.get("level", ""),
                str(r.get("name", ""))[:18],
                str(r.get("ip", ""))[:16],
                str(r.get("host", ""))[:26],
                str(r.get("url", ""))[:60],
            ))
        print("(request field omitted; add --raw if you really need the raw message)")
    else:
        print(json.dumps({"total": total, "data": rows},
                         ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #
LIST = {
    "sites":   "GET /sites",
    "rules":   "GET /rules",
    "ruleset": "GET /ruleset",
    "certs":   "GET /certs",
    "plugins": "GET /plugins",
    "users":   "GET /users",
}


def cmd_list(resource):
    if resource not in LIST:
        _die("available resources: %s" % ", ".join(sorted(LIST)))
    method, path = LIST[resource].split(" ", 1)
    status, text = _req(method, path)
    if status >= 400:
        _die("HTTP %s: %s" % (status, text[:200]))
    try:
        data = json.loads(text)
    except Exception:                                            # noqa: BLE001
        print(text); return

    if resource == "sites":
        if isinstance(data, dict) and isinstance(data.get("sites"), list):
            print("ruleset options:")
            for opt in data.get("options", []) or []:
                print("  [%s] %s" % (opt.get("value"), opt.get("label")))
            print("sites:")
            for s in data["sites"]:
                hosts = s.get("hosts")
                hosts = ",".join(hosts) if isinstance(hosts, list) else str(hosts)
                print("  [%s] %-46s ruleset=%s  mode=%s  %s" % (
                    s.get("id"), hosts, s.get("ruleset_id"),
                    s.get("mode"), s.get("description", "")))
            print("(mode: true=block mode / false=observation mode; ruleset IDs are the options listed above)")
            return
    if resource == "ruleset":
        for rs in data if isinstance(data, list) else [data]:
            try:
                ids = json.loads(rs.get("content") or "[]")
            except Exception:                                    # noqa: BLE001
                ids = []
            print("  [%s] %-14s %d rules  %s" %
                  (rs.get("id"), rs.get("name"), len(ids), rs.get("updated_at", "")))
            print("       %s" % json.dumps(ids, separators=(",", ":")))
        return
    if resource in ("rules", "certs", "plugins", "users"):
        for item in data if isinstance(data, list) else [data]:
            if resource == "rules":
                t = item.get("type")
                tag = "Lua" if t == 1 else ("DSL" if t == 0 else "?")
                nm = item.get("name") or "(DSL rule, body is in content)"
                print("  [%s] %-26s type=%s(%s) level=%s phase=%s len=%s" % (
                    item.get("id"), str(nm)[:26], t, tag,
                    item.get("level"), item.get("phase"),
                    len(item.get("content") or "")))
            elif resource == "certs":
                print("  [%s] %-20s sni=%s" % (
                    item.get("id"), str(item.get("name"))[:20], item.get("sni", "")))
            elif resource == "plugins":
                print("  [%s] %-20s enabled=%s" % (
                    item.get("id"), str(item.get("name"))[:20], item.get("enabled")))
            else:
                print("  [%s] %s  otp=%s" % (
                    item.get("id"), item.get("usr"), item.get("enable_otp")))
        print("(note: the content of rules is omitted; to fetch a body use `api GET /rules` and filter "
              "locally -- there is no `GET /rules/{id}`, it returns Not Found in practice)")
        return
    print(_pretty(text))


def cmd_ruleset(rid):
    """Print the members of a ruleset.

    Note: the `id` parameter of `GET /ruleset/rules` **has no effect** (it always returns the
    summary of the whole rule library), so this reads `GET /ruleset` to get each ruleset's
    `content` array (the real member list) and then filters down to the requested ruleset.
    """
    status, text = _req("GET", "/ruleset")
    if status >= 400:
        _die("HTTP %s: %s" % (status, text[:200]))
    try:
        sets = json.loads(text)
    except Exception:                                            # noqa: BLE001
        print(text); return
    if not isinstance(sets, list):
        sets = [sets]

    wanted = str(rid) if rid else None
    if wanted and not any(str(s.get("id")) == wanted for s in sets):
        _die("ruleset %s does not exist. Available: %s" %
             (rid, ", ".join("%s(%s)" % (s.get("id"), s.get("name")) for s in sets)))

    for rs in sets:
        if wanted and str(rs.get("id")) != wanted:
            continue
        try:
            ids = json.loads(rs.get("content") or "[]")
        except Exception:                                        # noqa: BLE001
            ids = []
        print("ruleset [%s] %s -- %d enabled rules:" %
              (rs.get("id"), rs.get("name"), len(ids)))
        print("  %s" % json.dumps(ids, separators=(",", ":")))
        print("  (execution order is ascending by rule ID, regardless of array order)")


def _field_hint(path):
    """For known endpoints, return a one-line hint about the field meanings (so you need not open the docs every time)."""
    H = {
        "/sites": "hosts=domain array mode=bool(true block/false observe) type=LB algorithm(roundrobin|chash|swrr) "
                  "servers=[{ip,port,weight}] scheme=upstream protocol ip_source=0socket/1XFF/2custom header "
                  "ip_order=nth from the end ip_header=header name is_websocket/is_ml/is_cache/force_ssl=bool",
        "/rules": "type=0DSL/1Lua level=0notice..4severe phase=0request/1response header/2response body "
                  "content=body(CRLF or LF) name exists for Lua only(empty for DSL) uid is always 1(not a built-in discriminator)",
        "/ruleset": "content=JSON array string(which rule IDs are enabled; execution is ascending by ID, array order is meaningless)",
        "/certs": "type=0apply/1upload sni=JSON array string crt/key=PEM(sensitive) dns_credential(sensitive)",
        "/plugins": "name=identifier enabled=bool content=full Lua text(built-ins include example credentials, do not copy them)",
        "/users": "role=0admin/1operator/2auditor pwd_expiration=0unlimited/45/90/180 "
                  "otp_url contains the plaintext TOTP(sensitive) fail=login failure count",
        "/setting": "id/addr/dsn(sensitive)/jwt_key(sensitive)/jwt_expiration/waf_nodes=array[\"ip:port\"]/"
                    "ml_server/ml_token(sensitive)/api_token(sensitive)/log_db(bool)/log_level(error|info|debug)/language/version",
        "/setting/waf": "data plane parameters such as resolver/listen/http2/ssl/gzip/cache/proxy/error_page/log",
        "/cdn": "host=domain uri=regex path cache_time=unit s/m/h/d/M/y enabled=bool",
        "/ml": "host/uri/schema/enabled (commercial edition; the community edition returns an upgrade prompt)",
        "/logs/total": "[total requests,today,7 days,blocked]",
        "/logs/top": "{attackers,sites,types}",
        "/logs/live": "{usage:{cpu,mem,disk},req,atk,geo}(atk/geo are JSON strings and must be parsed again)",
        "/audits": "type=action type usr ip info updated_at",
    }
    key = path.split("?")[0]
    if key in H:
        return H[key]
    if key.startswith("/setting/ipBlock"):
        return "actions: check=query status / unlock=unban / checkAll / unlockAll (body is {ip} for all of them)"
    if key.startswith("/rules/"):
        return "single delete (no body); to fetch a body you must GET /rules and filter (there is no GET /rules/{id})"
    return None


def cmd_api(args):
    if len(args) < 2:
        _die("usage: waf.py -i <instance> api <METHOD> <PATH> [BODY_JSON]")
    method, path = args[0].upper(), args[1]
    body = None
    if len(args) > 2:
        try:
            body = json.loads(args[2])
        except Exception as exc:                                 # noqa: BLE001
            _die("failed to parse BODY: %s" % exc)
    status, text = _req(method, path, body)
    print(_pretty(text))
    hint = _field_hint(path)
    if hint:
        print("\n# field meanings (%s): %s" % (path, hint))
    sys.exit(0 if status < 400 else 1)


def cmd_hosts(rest=()):
    """No arguments = list instances; `--add <name> --url <URL> [--token <T>|--token -] [--update]` = fill in for you."""
    if "--add" in rest or "--url" in rest or "--token" in rest:
        return _hosts_add(rest)
    if not os.path.exists(CONFIG_PATH):
        print("config file not found: %s" % CONFIG_PATH)
        print("  run `waf.py init` to generate a skeleton first, or use the environment variables WAF_API_URL + WAF_API_TOKEN.")
        return
    cfg = _load_config()
    if not cfg:
        print("the config file is empty.")
        return
    print("configured WAF instances (%s):" % CONFIG_PATH)
    for name, entry in cfg.items():
        entry = entry or {}
        tok = str(entry.get("token", ""))
        # Only report "whether it is configured" and its length, never echo any fragment of the token --
        # this keeps credentials out of model context
        state = "(to fill in)" if _is_placeholder(tok) else ("configured(%d chars)" % len(tok))
        url = str(entry.get("url", ""))
        print("  - %-14s %-32s token=%s%s" %
              (name, url, state, "  <- url is also a placeholder" if _is_placeholder(url) else ""))


def _hosts_add(rest):
    """Write the url / token given by the user into the config file. The token can be read from
    stdin (`--token -`) so it does not show up in the command line history; the token is never
    echoed under any circumstances."""
    name = url = token = None
    update = "--update" in rest
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--update":
            i += 1
            continue
        if a in ("--add", "--url", "--token"):
            if i + 1 >= len(rest):
                _die("usage: waf.py hosts --add <name> --url <URL> [--token <T>|--token -] [--update]")
            val = rest[i + 1]
            if a == "--add":
                name = val
            elif a == "--url":
                url = val
            else:
                token = sys.stdin.read().strip() if val == "-" else val
            i += 2
            continue
        _die("usage: waf.py hosts --add <name> --url <URL> [--token <T>|--token -] [--update]")
    if not name or not url:
        _die("usage: waf.py hosts --add <name> --url <URL> [--token <T>|--token -] [--update]")
    cfg = _load_config(raw=True) if os.path.exists(CONFIG_PATH) else dict(SKELETON)
    if name in cfg and not update:
        _die("instance '%s' already exists (add --update to overwrite it)" % name)
    cfg[name] = {"url": url.rstrip("/"),
                 "token": token if token is not None else "<paste your Api-Token here>"}
    _save_config(cfg)
    n = len(str(cfg[name]["token"]))
    print("instance '%s' written: url=%s  token=%s" %
          (name, cfg[name]["url"], "(to fill in)" if _is_placeholder(cfg[name]["token"])
           else "configured(%d chars)" % n))
    print("  self-check: python3 %s -i %s ping" % (sys.argv[0], name))
    if token:
        print("  reminder: if the token was passed through the conversation or the command line, "
              "consider rotating it as needed (it has shown up in those records).")


# --------------------------------------------------------------------------- #
# Write path: get / push / ipblock
# --------------------------------------------------------------------------- #
def _http(method, path, body=None):
    """Send a request and parse the response as JSON; anything non-2xx or non-JSON errors out."""
    status, text = _req(method, path, body)
    if status >= 400:
        _die("HTTP %s: %s" % (status, text[:300]))
    try:
        return json.loads(text)
    except Exception:                                            # noqa: BLE001
        _die("non-JSON response (HTTP %s): %s" % (status, text[:200]))


def _find(lst, rid):
    for item in lst if isinstance(lst, list) else []:
        if str(item.get("id")) == str(rid):
            return item
    return None


def _to_id(v):
    """Coerce a rule ID to int as far as possible (the server stores ints in a ruleset's content)."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def cmd_get(args):
    """Fetch a single rule field (content by default) -- working around "there is no GET /rules/{id}".

    When the body contains CRLF it is written to the file byte for byte (newline=""
    performs no newline conversion), so that "fetch -> edit -> write back" does not
    produce a whole-file bogus diff.
    """
    if len(args) < 2 or args[0] != "rule":
        _die("usage: waf.py -i <instance> get rule <ID> [--field <field>] [--out <file>]\n"
             "  --field defaults to content; use --field __meta__ to see metadata only (without the body)")
    rid, field, out = args[1], "content", None
    i = 2
    while i < len(args):
        a = args[i]
        if a == "--field" and i + 1 < len(args):
            field = args[i + 1]; i += 2; continue
        if a == "--out" and i + 1 < len(args):
            out = args[i + 1]; i += 2; continue
        _die("get: unknown argument: %s" % a)

    rules = _http("GET", "/rules")
    rule = _find(rules, rid)
    if rule is None:
        ids = ", ".join(str(r.get("id")) for r in rules) if isinstance(rules, list) else "?"
        _die("rule %s does not exist. %s in total, available IDs: %s" %
             (rid, len(rules) if isinstance(rules, list) else "?", ids))

    if field == "__meta__":
        print(json.dumps({k: v for k, v in rule.items() if k != "content"},
                         ensure_ascii=False, indent=2))
        return
    if field not in rule:
        _die("rule %s has no field '%s'. Available: %s" % (rid, field, ", ".join(sorted(rule))))

    val = rule.get(field)
    text = val if isinstance(val, str) else json.dumps(val, ensure_ascii=False, indent=2)
    if out:
        # newline="" -> no newline conversion, CRLF / LF are written to disk as-is (byte-exact)
        with open(out, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print("written to %s (%d chars, %d CRLF lines, %d LF lines)" %
              (out, len(text), text.count("\r\n"),
               text.count("\n") - text.count("\r\n")))
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _read_payload(fpath, to_lf):
    if not fpath:
        _die("you must specify the body file with --file (this avoids escape/newline corruption "
             "from inlining the body into the shell)")
    if not os.path.exists(fpath):
        _die("file not found: %s" % fpath)
    with open(fpath, encoding="utf-8", newline="") as fh:
        content = fh.read()
    if to_lf:
        content = content.replace("\r\n", "\n")
    if content == "":
        _die("the file is empty, refusing to write (use the panel if you need to clear the body)")
    return content


def _push_rule(args):
    dry = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    if not args:
        _die("usage: waf.py -i <instance> push rule <ID|new> --file <file> "
             "[--name <name>] [--type 1] [--level 3] [--phase 0] [--lf] [--dry-run]\n"
             "  new = create (POST / id=0); a numeric ID = update (PUT, with id)")
    target = args[0]
    fpath, name, to_lf, opts = None, None, False, {}
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--file" and i + 1 < len(args):
            fpath = args[i + 1]; i += 2; continue
        if a == "--name" and i + 1 < len(args):
            name = args[i + 1]; i += 2; continue
        if a == "--lf":
            to_lf = True; i += 1; continue
        if a in ("--type", "--level", "--phase", "--description") and i + 1 < len(args):
            opts[a[2:]] = args[i + 1]; i += 2; continue
        _die("push rule: unknown argument: %s" % a)

    content = _read_payload(fpath, to_lf)

    if target in ("new", "0"):
        body = {"id": 0, "name": name or os.path.basename(fpath),
                "type": int(opts.get("type", 1)), "level": int(opts.get("level", 3)),
                "phase": int(opts.get("phase", 0)),
                "description": opts.get("description", ""), "content": content}
        method, action = "POST", "create"
    else:
        cur = _find(_http("GET", "/rules"), target)
        if cur is None:
            _die("rule %s does not exist. Check the ID for an update; use `push rule new` to create one." % target)
        body = dict(cur)                     # base it on the server's current object, touch only the needed fields
        body["content"] = content
        if name is not None:
            body["name"] = name
        for k in ("type", "level", "phase"):
            if k in opts:
                body[k] = int(opts[k])
        if "description" in opts:
            body["description"] = opts["description"]
        method, action = "PUT", "update"

    print("about to %s rule %s: %d chars (%d CRLF lines / %d LF lines), type=%s level=%s phase=%s" %
          (action, target, len(content), content.count("\r\n"),
           content.count("\n") - content.count("\r\n"),
           body.get("type"), body.get("level"), body.get("phase")))
    if dry:
        print("[dry-run] not sent. Fields of the body that would be submitted: %s" % ", ".join(sorted(body)))
        return
    res = _http(method, "/rules", body)
    print("submitted (%s /rules): %s" % (method, json.dumps(res, ensure_ascii=False)[:300]))
    print("note: a rule only takes effect once it is attached to the ruleset used by the site; "
          "verify against the actually effective state, not against HTTP 200.")


def _push_ruleset(args):
    dry = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    if not args:
        _die("usage: waf.py -i <instance> push ruleset <ID> "
             "[--set '[9,500]' | --add 500 | --remove 19] [--dry-run]")
    rid = args[0]
    sets = _http("GET", "/ruleset")
    if not isinstance(sets, list):
        sets = [sets]
    cur = _find(sets, rid)
    if cur is None:
        _die("ruleset %s does not exist. Available: %s" %
             (rid, ", ".join("%s(%s)" % (s.get("id"), s.get("name")) for s in sets)))

    try:
        ids = json.loads(cur.get("content") or "[]")
    except Exception:                                            # noqa: BLE001
        ids = []
    before = list(ids)
    i = 1
    while i < len(args):
        a = args[i]
        if a in ("--set", "--add", "--remove") and i + 1 < len(args):
            v = args[i + 1]
            if a == "--set":
                ids = json.loads(v)
            elif a == "--add":
                if _to_id(v) not in ids:
                    ids.append(_to_id(v))
            else:
                ids = [x for x in ids if str(x) != str(v)]
            i += 2; continue
        _die("push ruleset: unknown argument: %s" % a)

    added = [x for x in ids if x not in before]
    removed = [x for x in before if x not in ids]
    print("ruleset [%s] %s: %d -> %d rules (+%s / -%s)" %
          (cur.get("id"), cur.get("name"), len(before), len(ids),
           ",".join(map(str, added)) or "none", ",".join(map(str, removed)) or "none"))
    if ids == before:
        print("no change, nothing sent.")
        return
    body = dict(cur)
    body["content"] = json.dumps(ids)
    if dry:
        print("[dry-run] not sent. Would submit the content of ruleset %s." % cur.get("id"))
        return
    res = _http("PUT", "/ruleset", body)
    print("submitted (PUT /ruleset): %s" % json.dumps(res, ensure_ascii=False)[:200])
    print("note: array order is meaningless, execution is ascending by rule ID; before changing, "
          "back up first with GET /setting/backupConfig.")


def cmd_push(args):
    if not args:
        _die("usage: waf.py -i <instance> push rule|ruleset ... (see waf.py -h)")
    if args[0] == "rule":
        _push_rule(args[1:])
    elif args[0] == "ruleset":
        _push_ruleset(args[1:])
    else:
        _die("push only supports: rule | ruleset")


def cmd_ipblock(args):
    """IP ban list operations.

    In practice the frontend only has four actions (PUT /setting/ipBlock/<action>, body {"ip":...}):
      check / unlock / checkAll / unlockAll
    Note that `check` is a **query** for the ban status of that IP (returns {locked:bool}),
    **not** an unban.
    """
    ACTIONS = {"check": "query the ban status of a single IP", "unlock": "unban a single IP",
               "checkAll": "export the whole list (same as the default output)", "unlockAll": "unban everything"}
    if args:
        a = args[0]
        if a == "--check-all":
            # The panel's "check all" button actually downloads GET /setting/ipBlock/all (JSONL),
            # it does not call PUT .../checkAll (which needs a valid ip and the UI never uses it).
            # Stay consistent with that here: export the list directly.
            _print_ipblock()
            return
        if a == "--unlock-all":
            print(json.dumps(_http("PUT", "/setting/ipBlock/unlockAll", {}),
                             ensure_ascii=False))
            print("(unbanning everything is a production change; first confirm they really are not attack sources)")
            return
        if a in ("--check", "--unlock"):
            if len(args) < 2:
                _die("usage: waf.py -i <instance> ipblock %s <IP>" % a)
            act = "check" if a == "--check" else "unlock"
            res = _http("PUT", "/setting/ipBlock/" + act, {"ip": args[1]})
            print("%s %s: %s" % (ACTIONS[act], args[1],
                                 json.dumps(res, ensure_ascii=False)))
            if act == "unlock":
                print("(unbanning is a production change: first confirm that this IP really is not an attack source)")
            return
        _die("ipblock: unknown argument: %s\n"
             "  usage: ipblock [--check <IP> | --unlock <IP> | --check-all | --unlock-all]\n"
             "  %s" % (a, "; ".join("%s=%s" % (k, v) for k, v in ACTIONS.items())))
    _print_ipblock()


def _print_ipblock():
    status, text = _req("GET", "/setting/ipBlock/all")
    if status >= 400:
        _die("HTTP %s: %s" % (status, text[:300]))
    # The frontend downloads the checkAll result as ipblock.jsonl -- the body is JSONL (one object
    # per line), and an empty list is `{}`. So you cannot json.loads the whole thing, and you must
    # not treat a dict as "1 entry".
    recs = []                                    # [(ip, note)]
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(obj, dict):
            ipk = next((k for k in ("ip", "address", "addr", "key") if k in obj), None)
            if ipk:                              # single record: {"ip":...,"count":...}
                recs.append((str(obj[ipk]),
                             ",".join("%s=%s" % (k, v) for k, v in obj.items()
                                      if k != ipk)))
            else:                                # mapping form: {"1.2.3.4": count}
                for k, v in obj.items():
                    recs.append((str(k), "" if v is True else "count=%s" % v))
        elif isinstance(obj, list):
            recs.extend((str(x), "") for x in obj)
        else:
            recs.append((str(obj), ""))
    print("IP ban list (%d entries; stored in the Lua shared memory ipBlock, TTL 600s, self-clearing after triggering stops):" %
          len(recs))
    if not recs:
        print("  (empty)")
    for ip, note in recs:
        print("  %s%s" % (ip, ("  " + note) if note else ""))


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def _fetch_rule(rid):
    rules = _http("GET", "/rules")
    rule = _find(rules, rid)
    if rule is None:
        _die("rule %s does not exist" % rid)
    return rule


def cmd_delete(args):
    """Delete a single item: rule/ruleset go through path deletion, cert/plugin through batch deletion with a body."""
    if len(args) < 2:
        _die("usage: waf.py -i <instance> delete rule|ruleset|cert|plugin <ID> [--dry-run]\n"
             "  WARNING: deletion is a production write; get authorization first and run `backup` when needed.")
    kind, rid = args[0], _to_id(args[1])
    dry = "--dry-run" in args
    if kind in ("rule", "ruleset"):
        path, body = "/%ss/%s" % (kind, rid), None
    elif kind in ("cert", "plugin"):
        path, body = "/%ss" % kind, {"keys": [rid]}
    else:
        _die("delete only supports rule / ruleset / cert / plugin")
    if dry:
        print("[dry-run] DELETE %s  body=%s" % (path, json.dumps(body) if body else "none"))
        return
    status, text = _req("DELETE", path, body)
    print("[HTTP %s] %s" % (status, _pretty(text)))
    if status < 400:
        print("WARNING: deletion submitted. Verify: is the site still attached to the deleted ruleset; "
              "does any ruleset content still reference it.")


def cmd_backup(args):
    """Export a config / database backup to a local file (for backing up before changes)."""
    what = args[0] if args and not args[0].startswith("-") else "config"
    out = None
    i = 0
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            out = args[i + 1]; i += 2; continue
        i += 1
    if what not in ("config", "db"):
        _die("usage: waf.py -i <instance> backup [config|db] [--out <file>]")
    path = "/setting/backupConfig" if what == "config" else "/setting/backupDB"
    status, text = _req("GET", path)
    if status >= 400:
        _die("backup failed HTTP %s: %s" % (status, text[:200]))
    if not out:
        out = "/tmp/waf-%s-backup-%s.json" % (what, time.strftime("%Y%m%d-%H%M%S"))
    # The backup contains passwords/keys -> permissions 600, so it is not left in /tmp where others can read it
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    hint = "(permissions 600; back up before changes, delete once verified)"
    if what == "config":
        hint = "🔴 contains sensitive fields (dsn/jwt_key/api_token/ml_token): do not echo, do not commit " + hint
    print("saved %s: %d bytes %s" % (out, len(text.encode()), hint))


def cmd_diff(args):
    """Compare the same rule / ruleset across instances (byte level + first difference)."""
    if len(args) < 2 or args[0] not in ("rule", "ruleset"):
        _die("usage: waf.py -i <instanceA> diff rule|ruleset <ID> --with <instanceB> [--field content]")
    kind, rid, other, field = args[0], args[1], None, "content"
    i = 2
    while i < len(args):
        if args[i] == "--with" and i + 1 < len(args):
            other = args[i + 1]; i += 2; continue
        if args[i] == "--field" and i + 1 < len(args):
            field = args[i + 1]; i += 2; continue
        _die("diff: unknown argument: %s" % args[i])
    if not other:
        _die("--with <instanceB> is required")
    res = "/rules" if kind == "rule" else "/ruleset"
    one = _find(_http("GET", res), rid)
    if one is None:
        _die("%s %s does not exist on %s" % (kind, rid, INSTANCE))
    left, left_name = str(one.get(field) or ""), INSTANCE
    _select(other)
    two = _find(_http("GET", res), rid)
    if two is None:
        _die("%s %s does not exist on %s" % (kind, rid, INSTANCE))
    right, right_name = str(two.get(field) or ""), INSTANCE
    lb, rb = left.encode(), right.encode()
    print("%s %s . field=%s" % (kind, rid, field))
    print("  %-10s %7d bytes  CRLF %-4d md5 %s" %
          (left_name, len(lb), lb.count(b"\r\n"), hashlib.md5(lb).hexdigest()))
    print("  %-10s %7d bytes  CRLF %-4d md5 %s" %
          (right_name, len(rb), rb.count(b"\r\n"), hashlib.md5(rb).hexdigest()))
    if lb == rb:
        print("  ✅ byte-for-byte identical")
        return
    if lb.replace(b"\r\n", b"\n") == rb.replace(b"\r\n", b"\n"):
        print("  ⚠️ only the newline style differs (CRLF vs LF), contents are identical")
        return
    print("  ❌ contents differ (left %s / right %s), line-by-line diff:" % (left_name, right_name))
    for line in list(difflib.unified_diff(left.splitlines(), right.splitlines(),
                                          lineterm="", n=1))[:40]:
        print("    " + line)


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    name = None
    if argv[0] == "-i":
        if len(argv) < 2:
            _die("-i must be followed by an instance name")
        name, argv = argv[1], argv[2:]
    if not argv:
        print(__doc__)
        sys.exit(0)

    if argv[0] == "init":                        # no instance needed
        cmd_init(force="--force" in argv[1:])
        return
    if argv[0] == "hosts":                       # hosts does not need an instance
        cmd_hosts(argv[1:])
        return

    # Validate the subcommand before requiring an instance -- otherwise a typo reports
    # "missing instance" and misleads your troubleshooting
    KNOWN = ("api", "list", "logs", "ruleset", "ping", "top", "total", "live", "report",
             "get", "push", "ipblock", "backup", "delete", "diff")
    if argv[0] not in KNOWN:
        sys.stderr.write("[error] unknown subcommand: %s\n" % argv[0])
        sys.stderr.write("available: hosts, %s\n" % ", ".join(KNOWN))
        sys.exit(2)

    _select(name) if name else _use_env()

    cmd, rest = argv[0], argv[1:]
    if cmd == "api":
        cmd_api(rest)
    elif cmd == "list":
        cmd_list(rest[0] if rest else "")
    elif cmd == "logs":
        cmd_logs(rest)
    elif cmd == "get":
        cmd_get(rest)
    elif cmd == "push":
        cmd_push(rest)
    elif cmd == "ipblock":
        cmd_ipblock(rest)
    elif cmd == "backup":
        cmd_backup(rest)
    elif cmd == "delete":
        cmd_delete(rest)
    elif cmd == "diff":
        cmd_diff(rest)
    elif cmd == "ruleset":
        cmd_ruleset(rest[0] if rest else "")
    elif cmd == "ping":
        status, text = _req("GET", "/setting/license")
        print("[HTTP %s] %s" % (status, _pretty(text)))
        sys.exit(0 if status < 400 else 1)
    elif cmd == "top":
        print(_pretty(_req("GET", "/logs/top")[1]))
    elif cmd == "total":
        print(_pretty(_req("GET", "/logs/total")[1]))
    elif cmd == "live":
        print(_pretty(_req("GET", "/logs/live")[1]))
    elif cmd == "report":
        print(_pretty(_req("POST", "/logs/report", {})[1]))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
