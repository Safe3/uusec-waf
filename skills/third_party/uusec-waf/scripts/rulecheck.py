#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rulecheck.py -- UUSEC WAF (南墙) rule/plugin "semantic layer" validator (standard library only, runs on any machine)

Covers the blind spots of pcrecheck.py / wafcheck.sh: those two only check "syntax and regex",
while this script checks "names and phases" -- APIs that do not exist, misspelled constants,
variables used in a mismatched phase, plugin-only variables/ngx misused in a rule, misspelled
plugin hook names, require() of a module the target instance does not have, DSL structure errors.
Lua syntax compilation still has to go through `wafcheck.sh lua` (luajit in the container).

Usage:
  rulecheck.py api     <file>                  # waf.* / log.* symbol existence, constant spelling, ngx misuse
  rulecheck.py phase   <file> --phase 0|1|2    # phase × variable matrix
  rulecheck.py hooks   <plugin file>           # plugin phase function names and required fields
  rulecheck.py modules <file>                  # whether the modules require()d exist on the target instance
  rulecheck.py dsl     <file|JSON string>      # DSL (type=0) structure validation
  rulecheck.py symbols [--doc <official api doc>]   # whether the symbol table is in sync with the official docs (self-check after a version upgrade)
  rulecheck.py all     <file> [--phase N] [--plugin] [--no-regex] [--no-lua]
                                              # semantics + regex + Lua syntax (whichever is available; all three in one pass)

Exit codes: 0 = passed / 1 = problems found / 2 = usage or environment error
Symbol table source: the official API docs (offline-docs/api.zh-CN.md) + measurements against the built-in rules (v7.2.5);
the module list was measured on a v7.2.5 container (`find /uuwaf/luajit/share/lua/5.1 -name '*.lua'`).
"""
import difflib
import json
import os
import re
import shutil
import subprocess
import sys

# --------------------------------------------------------------------------- #
# Symbol tables (v7.2.5)
# --------------------------------------------------------------------------- #
WAF_FUNCS = {
    # -- listed in the official api.zh-CN.md --
    "startWith", "endWith", "toLower", "contains", "regex", "rgxMatch", "rgxGmatch",
    "rgxSub", "rgxGsub", "kvFilter", "knFilter", "jsonFilter", "base64Decode",
    "checkSQLI", "checkRCE", "checkPT", "checkXSS", "strCounter", "trim", "inArray",
    "pmMatch", "urlDecode", "htmlEntityDecode", "hexDecode", "block", "checkRobot",
    "checkTurnstile", "redirect", "ip2loc", "errLog", "searchEngineValid",
    # -- not in the official docs, but measured in use by the built-in rules / engine --
    "getRootDomain", "plugins",
}
WAF_VARS = {
    "ip", "scheme", "httpVersion", "host", "ipBlock", "ipCache", "requestLine", "uri",
    "method", "reqUri", "userAgent", "referer", "reqContentType", "XFF", "origin",
    "reqHeaders", "hErr", "isQueryString", "reqContentLength", "queryString", "qErr",
    "form", "fErr", "cookies", "cErr",
    "status", "respHeaders", "respContentLength", "respContentType", "respBody",
    "replaceFilter",
}
WAF_CONSTS = {"RULE_BLOCK", "RULE_ALLOW", "RULE_LOG_ONLY"}
PLUGIN_MODULES = {
    "scannerDetection", "fileLeakDetection", "weakPwdDetection", "sqlErrorDetection",
    "phpErrorDetection", "javaErrorDetection", "javaClassDetection",
}
PLUGIN_ONLY_VARS = {"msg", "rule_id", "deny", "ctx"}      # invalid inside a rule
# present in the engine, but not in the official docs and never used by the 50 built-in rules
# (measured from bytecode) -> warn only, not an error
WAF_UNDOC = {"jsonDecode", "checkJson", "split", "respContentEncoding"}
LOG_FUNCS = {"errLog", "utf8", "getReq", "encodeJson", "broker", "ip2loc"}
# the official docs list only the first 5; log.ip2loc and friends are "hidden features"
# (the official kafka-logger uses them), so an unknown log.* only gets a hint

# Phase read-only visibility: key = phase number, value = the variables **unavailable** in that phase
PHASE_FORBIDDEN = {
    0: {"status", "respHeaders", "respContentLength", "respContentType",
        "respBody", "replaceFilter"},
    1: {"respBody", "replaceFilter"},
    2: set(),
}
PHASE_NAME = {0: "请求阶段", 1: "返回 HTTP 头阶段", 2: "返回页面阶段"}

HOOKS = {
    "ssl_pre_filter", "ssl_post_filter", "req_pre_filter", "req_post_filter",
    "resp_header_pre_filter", "resp_header_post_filter", "resp_body_pre_filter",
    "resp_body_post_filter", "log_pre_filter", "log_post_filter",
}
OLD_HOOKS = {"req_filter", "resp_header_filter", "resp_body_filter", "log"}

# modules that can be require()d on the target image (v7.2.5); the ones with * are prefix matches (submodules)
MODULES_OK = {
    "cjson", "cjson.safe", "lua_pack", "ahocorasick", "jsonschema", "mmdb",
    "net.url", "tablepool",
    "resty.aes", "resty.chash", "resty.core", "resty.dns.resolver", "resty.expr.v1",
    "resty.htmlentities", "resty.http", "resty.http_connect", "resty.http_headers",
    "resty.ipmatcher", "resty.libinjection", "resty.lock", "resty.lrucache",
    "resty.md5", "resty.mysql", "resty.radixtree", "resty.random", "resty.roundrobin",
    "resty.rsa", "resty.sha1", "resty.sha256", "resty.string", "resty.swrr",
    "resty.zlib",
    "ngx.base64", "ngx.re", "ngx.req", "ngx.resp", "ngx.semaphore", "ngx.ssl",
    "ngx.process", "ngx.pipe", "ngx.balancer", "ngx.errlog",
}
MODULES_OK_PREFIX = ("resty.core.", "resty.kafka.", "resty.ldap.", "resty.sha",
                     "resty.lrucache.", "jsonschema.", "ngx.ssl.", "waf.")
MODULES_KNOWN_ABSENT = {"resty.redis", "resty.memcached", "resty.upload", "lfs",
                        "socket", "resty.template", "resty.http_ng", "resty.session",
                        "resty.websocket.server", "resty.websocket.client"}
MODULE_HINT = ("Check the available modules on the target instance:\n"
               "    docker exec <WAF container> sh -c 'ls /uuwaf/luajit/share/lua/5.1/resty/'\n"
               "    docker exec <WAF container> sh -c 'find /uuwaf/luajit/lib -name \"*.so\"'")

DSL_ACTIONS = {"1", "2", "3"}
DSL_LOGIC = {"&", "|", "~&", "~|"}
DSL_OPS = {"*", "~*", ".", "~.", "-", "~-", "^", "$", "=", "~=", ">", "<"}
DSL_KEYS = {"ip", "method", "reqUri", "uri", "queryString", "reqHeaders", "userAgent",
            "referer", "reqContentType", "XFF", "origin", "reqContentLength", "form",
            "status", "respHeaders", "respContentType", "respContentLength", "respBody"}


# --------------------------------------------------------------------------- #
# Lua scanning: strip comments / strip strings (line numbers preserved)
# --------------------------------------------------------------------------- #
def scan_lua(src):
    """Return (comment-stripped text, comment-and-string-stripped text); both keep the original line numbers."""
    n = len(src)
    nocmt = list(src)
    bare = list(src)
    i = 0
    while i < n:
        c = src[i]
        if c == "-" and src[i:i + 2] == "--":
            m = re.match(r"--\[(=*)\[", src[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = src.find(close, i + len(m.group(0)))
                j = n if j < 0 else j + len(close)
            else:
                j = src.find("\n", i)
                j = n if j < 0 else j
            for k in range(i, j):
                if src[k] != "\n":
                    nocmt[k] = " " if nocmt[k] != "\n" else "\n"
                    bare[k] = " "
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                if src[j] == "\n":
                    break
                j += 1
            for k in range(i, j):
                if src[k] != "\n":
                    bare[k] = " "
            i = j
            continue
        if c == "[":
            m = re.match(r"\[(=*)\[", src[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = src.find(close, i + len(m.group(0)))
                j = n if j < 0 else j + len(close)
                for k in range(i, j):
                    if src[k] != "\n":
                        bare[k] = " "
                i = j
                continue
        i += 1
    return "".join(nocmt), "".join(bare)


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def is_plugin(code):
    return bool(re.search(r"\bfunction\s+_M\.[A-Za-z_][A-Za-z0-9_]*", code) or
                re.search(r"\breturn\s+_M\b", code))


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def check_api(path, code_nocmt, code_bare, force_plugin=None):
    problems = []
    plugin = is_plugin(code_nocmt) if force_plugin is None else force_plugin

    # waf.<name>
    for m in re.finditer(r"\bwaf\.([A-Za-z_][A-Za-z0-9_]*)", code_bare):
        name, ln = m.group(1), line_of(code_bare, m.start())
        if name in PLUGIN_MODULES:
            continue                                   # validated separately by the plugins branch
        if name == "plugins":
            for pm in re.finditer(r"waf\.plugins\.([A-Za-z_][A-Za-z0-9_]*)", code_bare):
                mod = pm.group(1)
                if mod not in PLUGIN_MODULES:
                    problems.append(("unknown detection module", "waf.plugins.%s" % mod,
                                     line_of(code_bare, pm.start()),
                                     "available: " + " / ".join(sorted(PLUGIN_MODULES))))
            continue
        if (name in WAF_CONSTS or name in WAF_FUNCS or name in WAF_VARS
                or name in PLUGIN_ONLY_VARS):
            continue
        if name in WAF_UNDOC:
            problems.append(("undocumented symbol", "waf.%s" % name, ln,
                             "it exists in the engine, but is not in the official docs and was never "
                             "used by the built-in rules -- unstable across versions, so measure it on "
                             "the target instance before using it", "warn"))
            continue
        pool = sorted(WAF_FUNCS | WAF_VARS | WAF_CONSTS)
        near = difflib.get_close_matches(name, pool, n=2, cutoff=0.6)
        problems.append(("unknown API/variable", "waf.%s" % name, ln,
                         ("closest: " + " / ".join("waf." + x for x in near)) if near
                         else "no such name in the official API docs or the built-in rules"))
    # log.<name> (only meaningful in a plugin, but writing it in a rule is simply a no-op -- reported either way)
    for m in re.finditer(r"\blog\.([A-Za-z_][A-Za-z0-9_]*)", code_bare):
        name, ln = m.group(1), line_of(code_bare, m.start())
        if name not in LOG_FUNCS:
            near = difflib.get_close_matches(name, sorted(LOG_FUNCS), n=1, cutoff=0.6)
            problems.append(("log function not seen in the docs", "log.%s" % name, ln,
                             (("closest: log." + near[0] + "; ") if near else "") +
                             "the official docs only list errLog/utf8/getReq/encodeJson/broker, "
                             "and other unpublished functions exist (e.g. ip2loc) -- please verify "
                             "on the target instance", "warn"))
    # constant spelling (e.g. RULE_BLOK, or RULE_BLOCK written bare without the waf. prefix)
    for m in re.finditer(r"\bwaf\.(RULE_[A-Z_]+)", code_bare):
        if m.group(1) not in WAF_CONSTS:
            problems.append(("constant spelling error", "waf.%s" % m.group(1),
                             line_of(code_bare, m.start()),
                             "only waf.RULE_BLOCK / waf.RULE_ALLOW / waf.RULE_LOG_ONLY"))

    # plugin-only capabilities misused in a rule
    if not plugin:
        for m in re.finditer(r"\bwaf\.([A-Za-z_][A-Za-z0-9_]*)", code_bare):
            name, ln = m.group(1), line_of(code_bare, m.start())
            if name in PLUGIN_ONLY_VARS:
                problems.append(("plugin-only variable used in a rule", "waf.%s" % name, ln,
                                 "waf.msg / waf.rule_id / waf.deny / waf.ctx are only valid inside a "
                                 "plugin; to share state across events in a rule use waf.ipCache"))
        for m in re.finditer(r"\bngx\b", code_bare):
            problems.append(("raw ngx used in a rule", "ngx", line_of(code_bare, m.start()),
                             "the official interface only exposes waf.* to rules (0 of the built-in "
                             "rules use ngx); if you need ngx, write a plugin"))
        for m in re.finditer(r"\brequire\s*\(", code_bare):
            problems.append(("require used in a rule", "require", line_of(code_bare, m.start()),
                             "rules do not support require; if you need an external library, write a plugin"))
    return plugin, problems


def detect_phase(src):
    """Infer the phase number from the rule header comment "过滤阶段:"; return None if it cannot be recognized."""
    m = re.search(r"过滤阶段\s*[:：]\s*([^\n*]+)", src)
    if not m:
        return None
    txt = m.group(1)
    if "返回页面" in txt or "返回内容" in txt or "body" in txt.lower():
        return 2
    if "返回" in txt or "header" in txt.lower():
        return 1
    if "请求" in txt:
        return 0
    return None


def check_phase(code_bare, phase, plugin):
    problems = []
    if plugin:
        return problems
    forbidden = PHASE_FORBIDDEN.get(phase, set())
    for name in sorted(forbidden):
        for m in re.finditer(r"\bwaf\.%s\b" % re.escape(name), code_bare):
            problems.append(("phase mismatch", "waf.%s" % name, line_of(code_bare, m.start()),
                             "%s cannot read this variable (the panel disables it as well)" % PHASE_NAME[phase]))
    return problems


def check_hooks(code_nocmt, code_bare):
    problems = []
    found = set(re.findall(r"\bfunction\s+_M\.([A-Za-z_][A-Za-z0-9_]*)", code_nocmt))
    for h in sorted(found):
        if h in OLD_HOOKS:
            problems.append(("old hook name", "_M.%s" % h, 0,
                             "since v4.1.0 these became pre/post sub-phases (e.g. req_pre_filter / req_post_filter)"))
        elif not h.endswith("_filter"):
            problems.append(("not a phase function", "_M.%s" % h, 0,
                             "a phase hook should look like req_pre_filter; helper functions are better written as local", "warn"))
        elif h not in HOOKS:
            near = difflib.get_close_matches(h, sorted(HOOKS), n=1, cutoff=0.6)
            problems.append(("unknown phase hook", "_M.%s" % h, 0,
                             ("closest: _M." + near[0]) if near else
                             "available: " + " / ".join(sorted(HOOKS))))
    if not found:
        problems.append(("no phase function", "(whole file)", 0, "a plugin must implement at least one *_filter hook"))
    if not re.search(r"\breturn\s+_M\b", code_nocmt):
        problems.append(("missing return _M", "(end of file)", 0, "a plugin module must return _M"))
    if not re.search(r"\bversion\s*=", code_nocmt) or not re.search(r"\bname\s*=", code_nocmt):
        problems.append(("missing _M.version / _M.name", "_M table", 0, "the template always contains these two fields", "warn"))
    return problems


def check_modules(code_nocmt):
    problems, listed = [], []
    for m in re.finditer(r"""require\s*\(\s*["']([^"']+)["']""", code_nocmt):
        mod, ln = m.group(1), line_of(code_nocmt, m.start())
        listed.append(mod)
        if mod in MODULES_OK or mod.startswith(MODULES_OK_PREFIX):
            continue
        if mod in MODULES_KNOWN_ABSENT:
            problems.append(("module does not exist in measurements", mod, ln, "this image (v7.2.5) does not bundle this module -- switch implementation, or check the target instance first"))
        else:
            problems.append(("module not in the measured list", mod, ln,
                             "it is not in the v7.2.5 measured list -- it may be uninstalled or a different version, so be sure to check first"))
    return listed, problems


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DOC = os.path.join(SCRIPT_DIR, "..", "references", "offline-docs", "api.zh-CN.md")


def run_regex_check(path):
    """Delegate to pcrecheck.py for regex validation (standalone PCRE2 build). Returns (rc, list of output lines)."""
    tool = os.path.join(SCRIPT_DIR, "pcrecheck.py")
    if not os.path.exists(tool):
        return None, ["(pcrecheck.py not found, skipping regex validation)"]
    try:
        out = subprocess.run([sys.executable, tool, "extract", path],
                             capture_output=True, text=True, timeout=180)
    except Exception as exc:                                     # noqa: BLE001
        return None, ["(regex validation failed to run: %s)" % exc]
    lines = [ln for ln in out.stdout.splitlines()
             if "这不是 luajit" not in ln and ln.strip()]
    return out.returncode, lines


def _lua_verdict(text):
    if "SYNTAX_OK" in text:
        return True, "SYNTAX_OK"
    for ln in text.splitlines():
        if ln.startswith("ERR:") or "SYNTAX_SUSPECT" in ln:
            return False, ln.strip()
    return None, text.strip()[:120]


def run_lua_check(path):
    """Lua syntax validation: prefer the WAF container (authoritative luajit), then the local luajit; skip if neither is available."""
    sh = os.path.join(SCRIPT_DIR, "wafcheck.sh")
    if os.path.exists(sh) and shutil.which("bash") and shutil.which("docker"):
        try:
            out = subprocess.run(["bash", sh, "lua", path], capture_output=True,
                                 text=True, timeout=120).stdout
            ok, why = _lua_verdict(out)
            if ok is not None:
                return ok, "%s (container luajit, authoritative)" % why
            return None, "(container channel unavailable: %s)" % why
        except Exception:                                        # noqa: BLE001
            pass
    if shutil.which("luajit"):
        try:
            code = 'local f,e=loadfile(%r); print(f and "SYNTAX_OK" or ("ERR: "..tostring(e)))' % path
            out = subprocess.run(["luajit", "-e", code], capture_output=True,
                                 text=True, timeout=60).stdout
            ok, why = _lua_verdict(out)
            return ok, "%s (local luajit)" % why
        except Exception:                                        # noqa: BLE001
            pass
    return None, ("(no authoritative Lua syntax validation was performed: this machine has neither a WAF "
                  "container nor luajit -- run `wafcheck.sh lua` on the WAF host, or install luajit locally)")


def check_symbols(doc_path):
    """Symbol table vs the official docs: find names the docs have but the table lacks (a staleness signal after a version upgrade)."""
    if not os.path.exists(doc_path):
        return [("official docs not found", doc_path, 0, "specify the path with --doc")]
    with open(doc_path, encoding="utf-8") as fh:
        doc = fh.read()
    # URLs in the docs (e.g. waf.uusec.com) and require("waf.log") are not API names, so strip them first
    doc = re.sub(r"https?://\S+", " ", doc)
    doc = re.sub(r'require\s*\(\s*["\'][^"\']*["\']\s*\)', " ", doc)
    doc_names = set(re.findall(r"waf\.([A-Za-z_][A-Za-z0-9_]*)", doc))
    doc_names -= {"log", "util"}          # engine-embedded module names, only appear inside require
    known = WAF_FUNCS | WAF_VARS | WAF_CONSTS | PLUGIN_ONLY_VARS | WAF_UNDOC
    problems = []
    for name in sorted(doc_names - known):
        problems.append(("in the docs but missing from the symbol table", "waf.%s" % name, 0,
                         "update WAF_FUNCS/WAF_VARS at the top of rulecheck.py before this check covers it"))
    extra = sorted(known - doc_names)
    if extra:
        print("[known undocumented symbols] %s" % ", ".join("waf." + x for x in extra))
        print("  (these come from measurements of the built-in rules and are normal; the official docs do not list them)")
    return problems


def _load_dsl(text):
    text = text.strip()
    if os.path.exists(text):
        with open(text, encoding="utf-8-sig") as fh:
            text = fh.read()
    return json.loads(text)


def check_dsl(text):
    problems = []
    try:
        obj = _load_dsl(text)
    except Exception as exc:                                    # noqa: BLE001
        return [("JSON parse failed", str(exc)[:80], 0, "a DSL rule content must be valid JSON")]
    if not isinstance(obj, list) or len(obj) != 2:
        return [("structure error", "(root)", 0, "must be [action, conditions array]")]
    action, conds = obj
    if str(action) not in DSL_ACTIONS:
        problems.append(("bad action value", "[0] = %r" % (action,), 0,
                         'must be the number 1=block / 2=allow / 3=log-only (not "block"/"allow")'))
    if not isinstance(conds, list) or not conds:
        return problems + [("empty conditions array", "[1]", 0, "there must be at least one condition")]
    body = list(conds)
    if not isinstance(body[0], list):
        logic = body.pop(0)
        if logic not in DSL_LOGIC:
            problems.append(("bad logic operator value", repr(logic), 0,
                             'must be "&" / "|" / "~&" / "~|" (not "and"/"or")'))
    for idx, cond in enumerate(body):
        where = "condition[%d]" % (idx + 1)
        if not isinstance(cond, list) or len(cond) != 3:
            problems.append(("bad condition format", where, 0, "must be a [key, op, val] triple"))
            continue
        key, op, val = cond
        if key not in DSL_KEYS:
            near = difflib.get_close_matches(str(key), sorted(DSL_KEYS), n=1, cutoff=0.6)
            problems.append(("unknown parameter name", "%s key=%r" % (where, key), 0,
                             ("closest: " + near[0]) if near else "see management-api §3.2"))
        if op not in DSL_OPS:
            near = difflib.get_close_matches(str(op), sorted(DSL_OPS), n=2, cutoff=0.5)
            problems.append(("unknown operator", "%s op=%r" % (where, op), 0,
                             "the panel uses these symbols: * ~* . ~. - ~- ^ $ = ~= > < ("
                             + ("closest: " + " / ".join(near) if near else "see §3.2") + ")"))
            continue
        if op in (">", "<") and not re.match(r"^[+-]?\d+(\.\d+)?$", str(val)):
            problems.append(("value is not a number", "%s val=%r" % (where, val), 0,
                             "the > / < operators require a numeric value"))
        if op in (".", "~."):
            tool = os.path.join(SCRIPT_DIR, "pcrecheck.py")
            if os.path.exists(tool):
                try:
                    out = subprocess.run([sys.executable, tool, "regex", str(val)],
                                         capture_output=True, text=True, timeout=60)
                    if out.returncode == 2:
                        problems.append(("invalid regex", "%s val=%r" % (where, val), 0,
                                         "the panel validates with JS RegExp while the runtime is PCRE -- "
                                         "it is reported invalid under PCRE here, and must be fixed"))
                except Exception:                                # noqa: BLE001
                    pass
    return problems


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def report(title, problems):
    errs = [p for p in problems if len(p) < 5 or p[4] != "warn"]
    warns = [p for p in problems if len(p) == 5 and p[4] == "warn"]
    if not problems:
        print("[passed] %s" % title)
        return 0
    print("[problems found] %s -- %d error(s) / %d warning(s)" % (title, len(errs), len(warns)))
    for p in problems:
        kind, what, ln, why = p[0], p[1], p[2], p[3]
        mark = "⚠️ " if (len(p) == 5 and p[4] == "warn") else "❌ "
        loc = "line %s" % ln if ln else ""
        print("  %s%-22s %-26s %s" % (mark, kind, what, loc))
        if why:
            print("       ↳ %s" % why)
    return 1 if errs else 0


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[0]
    rest = argv[1:]
    phase, force_plugin, path = None, None, None
    i = 0
    positional = []
    while i < len(rest):
        a = rest[i]
        if a == "--phase" and i + 1 < len(rest):
            phase = int(rest[i + 1]); i += 2; continue
        if a == "--plugin":
            force_plugin = True; i += 1; continue
        if a == "--rule":
            force_plugin = False; i += 1; continue
        positional.append(a); i += 1
    if positional:
        path = positional[0]

    if cmd == "symbols":
        doc = DEFAULT_DOC
        if "--doc" in argv and argv.index("--doc") + 1 < len(argv):
            doc = argv[argv.index("--doc") + 1]
        print("[symbol table source] %s" % os.path.normpath(doc))
        return report("symbol table vs official docs", check_symbols(doc))

    if cmd == "dsl":
        if not path:
            sys.stderr.write("[error] usage: rulecheck.py dsl <file|JSON string>\n")
            return 2
        return report("DSL structure", check_dsl(path))

    if not path or not os.path.exists(path):
        sys.stderr.write("[error] file does not exist: %s\n" % path)
        return 2
    with open(path, encoding="utf-8-sig") as fh:
        src = fh.read()
    nocmt, bare = scan_lua(src)
    rc = 0

    if cmd in ("api", "all"):
        plugin, probs = check_api(path, nocmt, bare, force_plugin)
        rc |= report("%s · API/constants%s" % (path, "/ngx" if not plugin else ""), probs)
        if cmd == "all":
            print("       (detected as %s)" % ("plugin" if plugin else "rule"))
    else:
        plugin = is_plugin(nocmt) if force_plugin is None else force_plugin

    if cmd in ("phase", "all"):
        src_phase = None if force_plugin else detect_phase(src)
        use_phase = phase if phase is not None else src_phase
        if use_phase is None:
            if cmd == "phase":
                sys.stderr.write('[note] no --phase given, and the header comment has no "过滤阶段:", skipping the phase check\n')
            else:
                print('  (no "过滤阶段:" header comment, skipping the phase check -- the official built-in rules '
                      'are mostly minimal and carry no header comment; for your own rules please add one following '
                      'the template, or specify it with --phase)')
        else:
            origin = "--phase given" if phase is not None else "read from the header comment"
            if phase is not None and src_phase is not None and phase != src_phase:
                print("  ⚠️  --phase=%d disagrees with the header comment (%d); checking by --phase" % (phase, src_phase))
            rc |= report("%s · phase %d(%s, %s)" % (path, use_phase,
                                                  PHASE_NAME.get(use_phase, "?"), origin),
                         check_phase(bare, use_phase, plugin))

    if cmd in ("hooks", "all"):
        if cmd == "hooks" or plugin:
            rc |= report("%s · plugin hooks/fields" % path, check_hooks(nocmt, bare))

    if cmd in ("modules", "all"):
        listed, probs = check_modules(nocmt)
        if listed:
            print("[require list] %s" % ", ".join(sorted(set(listed))))
        rc |= report("%s · module availability" % path, probs)
        if probs:
            print("    " + MODULE_HINT.replace("\n", "\n    "))

    if cmd == "all":
        print("──── extra channels (syntax and regex) ────")
        if "--no-lua" in argv:
            print("[Lua syntax] skipped per --no-lua")
        else:
            ok, why = run_lua_check(path)
            if ok is True:
                print("[Lua syntax] ✅ %s" % why)
            elif ok is False:
                print("[Lua syntax] ❌ %s" % why)
                rc = 1
            else:
                print("[Lua syntax] ⚠️  %s" % why)
        if "--no-regex" in argv:
            print("[regex] skipped per --no-regex")
        else:
            rrc, lines = run_regex_check(path)
            print("[regex] " + ("skipped" if rrc is None else
                              ("all valid" if rrc == 0 else "invalid ones present (see below)")))
            for ln in lines[-12:]:
                print("    " + ln)
            if rrc not in (None, 0):
                rc = 1

    return rc


if __name__ == "__main__":
    sys.exit(main())
