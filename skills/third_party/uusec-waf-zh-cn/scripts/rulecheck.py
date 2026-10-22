#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rulecheck.py — 南墙 WAF 规则/插件「语义层」校验器（纯标准库，任何机器可跑）

补 pcrecheck.py / wafcheck.sh 的盲区：那两者只查「语法与正则」，本脚本查
「名字与阶段」—— 不存在的 API、拼错的常量、阶段不匹配的变量、规则里误用
插件专属变量/ngx、插件钩子名写错、require 了目标实例没有的模块、DSL 结构错误。
Lua 语法编译校验仍须 `wafcheck.sh lua`（容器内 luajit）。

用法：
  rulecheck.py api     <文件>                  # waf.* / log.* 符号存在性、常量拼写、ngx 误用
  rulecheck.py phase   <文件> --phase 0|1|2    # 阶段 × 变量矩阵
  rulecheck.py hooks   <插件文件>              # 插件阶段函数名与必备字段
  rulecheck.py modules <文件>                  # require() 的模块在目标实例是否存在
  rulecheck.py dsl     <文件|JSON 字符串>      # DSL(type=0) 结构校验
  rulecheck.py symbols [--doc <官方api文档>]   # 符号表是否与官方文档同步（版本升级后自查）
  rulecheck.py all     <文件> [--phase N] [--plugin] [--no-regex] [--no-lua]
                                              # 语义 + 正则 + Lua 语法（能拿到就跑，三件套一次过）

退出码：0 = 通过 / 1 = 发现问题 / 2 = 用法或环境错误
符号表来源：官方 API 文档（offline-docs/api.zh-CN.md）+ 内置规则实测（v7.2.5）；
模块清单实测于 v7.2.5 容器（`find /uuwaf/luajit/share/lua/5.1 -name '*.lua'`）。
"""
import difflib
import json
import os
import re
import shutil
import subprocess
import sys

# --------------------------------------------------------------------------- #
# 符号表（v7.2.5）
# --------------------------------------------------------------------------- #
WAF_FUNCS = {
    # —— 官方 api.zh-CN.md 收录 ——
    "startWith", "endWith", "toLower", "contains", "regex", "rgxMatch", "rgxGmatch",
    "rgxSub", "rgxGsub", "kvFilter", "knFilter", "jsonFilter", "base64Decode",
    "checkSQLI", "checkRCE", "checkPT", "checkXSS", "strCounter", "trim", "inArray",
    "pmMatch", "urlDecode", "htmlEntityDecode", "hexDecode", "block", "checkRobot",
    "checkTurnstile", "redirect", "ip2loc", "errLog", "searchEngineValid",
    # —— 官方文档未收录、但内置规则/引擎实测在使用 ——
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
PLUGIN_ONLY_VARS = {"msg", "rule_id", "deny", "ctx"}      # 规则里无效
# 引擎里存在、但官方文档未收录且 50 条内置规则从未用过（实测字节码）→ 只告警，不算错
WAF_UNDOC = {"jsonDecode", "checkJson", "split", "respContentEncoding"}
LOG_FUNCS = {"errLog", "utf8", "getReq", "encodeJson", "broker", "ip2loc"}
# 官方文档只列了前 5 个，log.ip2loc 等属"隐藏功能"（官方 kafka-logger 在用），故未知 log.* 只提示

# 阶段只读可见性：key = 阶段号，value = 该阶段**不可用**的变量
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

# 目标镜像（v7.2.5）可 require 的模块；带 * 的是前缀匹配（子模块）
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
MODULE_HINT = ("在目标实例核对可用模块：\n"
               "    docker exec <WAF容器> sh -c 'ls /uuwaf/luajit/share/lua/5.1/resty/'\n"
               "    docker exec <WAF容器> sh -c 'find /uuwaf/luajit/lib -name \"*.so\"'")

DSL_ACTIONS = {"1", "2", "3"}
DSL_LOGIC = {"&", "|", "~&", "~|"}
DSL_OPS = {"*", "~*", ".", "~.", "-", "~-", "^", "$", "=", "~=", ">", "<"}
DSL_KEYS = {"ip", "method", "reqUri", "uri", "queryString", "reqHeaders", "userAgent",
            "referer", "reqContentType", "XFF", "origin", "reqContentLength", "form",
            "status", "respHeaders", "respContentType", "respContentLength", "respBody"}


# --------------------------------------------------------------------------- #
# Lua 扫描：剥注释 / 剥字符串（保留行号）
# --------------------------------------------------------------------------- #
def scan_lua(src):
    """返回 (去注释文本, 去注释且去字符串文本)，两版行号均与原文件一致。"""
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
# 各检查
# --------------------------------------------------------------------------- #
def check_api(path, code_nocmt, code_bare, force_plugin=None):
    problems = []
    plugin = is_plugin(code_nocmt) if force_plugin is None else force_plugin

    # waf.<name>
    for m in re.finditer(r"\bwaf\.([A-Za-z_][A-Za-z0-9_]*)", code_bare):
        name, ln = m.group(1), line_of(code_bare, m.start())
        if name in PLUGIN_MODULES:
            continue                                   # 由 plugins 分支单独校验
        if name == "plugins":
            for pm in re.finditer(r"waf\.plugins\.([A-Za-z_][A-Za-z0-9_]*)", code_bare):
                mod = pm.group(1)
                if mod not in PLUGIN_MODULES:
                    problems.append(("未知检测模块", "waf.plugins.%s" % mod,
                                     line_of(code_bare, pm.start()),
                                     "可用: " + " / ".join(sorted(PLUGIN_MODULES))))
            continue
        if (name in WAF_CONSTS or name in WAF_FUNCS or name in WAF_VARS
                or name in PLUGIN_ONLY_VARS):
            continue
        if name in WAF_UNDOC:
            problems.append(("未文档化符号", "waf.%s" % name, ln,
                             "引擎里存在，但官方文档未收录、内置规则从未使用 —— 跨版本不稳定，"
                             "要用先在目标实例实测", "warn"))
            continue
        pool = sorted(WAF_FUNCS | WAF_VARS | WAF_CONSTS)
        near = difflib.get_close_matches(name, pool, n=2, cutoff=0.6)
        problems.append(("未知 API/变量", "waf.%s" % name, ln,
                         ("最接近: " + " / ".join("waf." + x for x in near)) if near
                         else "官方 API 文档与内置规则中均无此名字"))
    # log.<name>（仅插件有意义，但规则里写也只是无效，统一提示）
    for m in re.finditer(r"\blog\.([A-Za-z_][A-Za-z0-9_]*)", code_bare):
        name, ln = m.group(1), line_of(code_bare, m.start())
        if name not in LOG_FUNCS:
            near = difflib.get_close_matches(name, sorted(LOG_FUNCS), n=1, cutoff=0.6)
            problems.append(("日志函数未见于文档", "log.%s" % name, ln,
                             (("最接近: log." + near[0] + "；") if near else "") +
                             "官方文档只列 errLog/utf8/getReq/encodeJson/broker，"
                             "另有未公开函数存在（如 ip2loc）—— 请实测确认", "warn"))
    # 常量拼写（如 RULE_BLOK / RULE_BLOCK 少了 waf. 前缀的裸写）
    for m in re.finditer(r"\bwaf\.(RULE_[A-Z_]+)", code_bare):
        if m.group(1) not in WAF_CONSTS:
            problems.append(("常量拼写错误", "waf.%s" % m.group(1),
                             line_of(code_bare, m.start()),
                             "只有 waf.RULE_BLOCK / waf.RULE_ALLOW / waf.RULE_LOG_ONLY"))

    # 规则里误用插件专属能力
    if not plugin:
        for m in re.finditer(r"\bwaf\.([A-Za-z_][A-Za-z0-9_]*)", code_bare):
            name, ln = m.group(1), line_of(code_bare, m.start())
            if name in PLUGIN_ONLY_VARS:
                problems.append(("插件专属变量用在规则里", "waf.%s" % name, ln,
                                 "waf.msg / waf.rule_id / waf.deny / waf.ctx 只在插件里有效；"
                                 "规则跨事件共享状态请用 waf.ipCache"))
        for m in re.finditer(r"\bngx\b", code_bare):
            problems.append(("规则里使用了原生 ngx", "ngx", line_of(code_bare, m.start()),
                             "官方只给规则提供 waf.* 接口（内置规则 0 处使用 ngx）；"
                             "需要 ngx 请写成插件"))
        for m in re.finditer(r"\brequire\s*\(", code_bare):
            problems.append(("规则里使用 require", "require", line_of(code_bare, m.start()),
                             "规则不支持 require；需要外部库请写成插件"))
    return plugin, problems


def detect_phase(src):
    """从规则头注释「过滤阶段:」推断阶段号；识别不出返回 None。"""
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
            problems.append(("阶段不匹配", "waf.%s" % name, line_of(code_bare, m.start()),
                             "%s 拿不到该变量（面板也会禁用）" % PHASE_NAME[phase]))
    return problems


def check_hooks(code_nocmt, code_bare):
    problems = []
    found = set(re.findall(r"\bfunction\s+_M\.([A-Za-z_][A-Za-z0-9_]*)", code_nocmt))
    for h in sorted(found):
        if h in OLD_HOOKS:
            problems.append(("旧版钩子名", "_M.%s" % h, 0,
                             "v4.1.0 起改为 pre/post 小阶段（如 req_pre_filter / req_post_filter）"))
        elif not h.endswith("_filter"):
            problems.append(("非阶段函数", "_M.%s" % h, 0,
                             "阶段钩子应形如 req_pre_filter；辅助函数建议写成 local", "warn"))
        elif h not in HOOKS:
            near = difflib.get_close_matches(h, sorted(HOOKS), n=1, cutoff=0.6)
            problems.append(("未知阶段钩子", "_M.%s" % h, 0,
                             ("最接近: _M." + near[0]) if near else
                             "可用: " + " / ".join(sorted(HOOKS))))
    if not found:
        problems.append(("没有阶段函数", "(整个文件)", 0, "插件至少要实现一个 *_filter 钩子"))
    if not re.search(r"\breturn\s+_M\b", code_nocmt):
        problems.append(("缺少 return _M", "(文件末尾)", 0, "插件模块必须 return _M"))
    if not re.search(r"\bversion\s*=", code_nocmt) or not re.search(r"\bname\s*=", code_nocmt):
        problems.append(("缺少 _M.version / _M.name", "_M 表", 0, "模板必含这两个字段", "warn"))
    return problems


def check_modules(code_nocmt):
    problems, listed = [], []
    for m in re.finditer(r"""require\s*\(\s*["']([^"']+)["']""", code_nocmt):
        mod, ln = m.group(1), line_of(code_nocmt, m.start())
        listed.append(mod)
        if mod in MODULES_OK or mod.startswith(MODULES_OK_PREFIX):
            continue
        if mod in MODULES_KNOWN_ABSENT:
            problems.append(("模块实测不存在", mod, ln, "该镜像（v7.2.5）未内置此模块 —— 换实现，或先核对目标实例"))
        else:
            problems.append(("模块不在实测清单内", mod, ln,
                             "v7.2.5 实测清单里没有它 —— 可能未安装或版本不同，务必先核对"))
    return listed, problems


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DOC = os.path.join(SCRIPT_DIR, "..", "references", "offline-docs", "api.zh-CN.md")


def run_regex_check(path):
    """转调 pcrecheck.py 做正则校验（PCRE2 独立版）。返回 (rc, 输出行列表)。"""
    tool = os.path.join(SCRIPT_DIR, "pcrecheck.py")
    if not os.path.exists(tool):
        return None, ["（未找到 pcrecheck.py，跳过正则校验）"]
    try:
        out = subprocess.run([sys.executable, tool, "extract", path],
                             capture_output=True, text=True, timeout=180)
    except Exception as exc:                                     # noqa: BLE001
        return None, ["（正则校验执行失败：%s）" % exc]
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
    """Lua 语法校验：优先 WAF 容器（权威 luajit），其次本机 luajit，都没有则跳过。"""
    sh = os.path.join(SCRIPT_DIR, "wafcheck.sh")
    if os.path.exists(sh) and shutil.which("bash") and shutil.which("docker"):
        try:
            out = subprocess.run(["bash", sh, "lua", path], capture_output=True,
                                 text=True, timeout=120).stdout
            ok, why = _lua_verdict(out)
            if ok is not None:
                return ok, "%s（容器 luajit，权威）" % why
            return None, "（容器通道不可用：%s）" % why
        except Exception:                                        # noqa: BLE001
            pass
    if shutil.which("luajit"):
        try:
            code = 'local f,e=loadfile(%r); print(f and "SYNTAX_OK" or ("ERR: "..tostring(e)))' % path
            out = subprocess.run(["luajit", "-e", code], capture_output=True,
                                 text=True, timeout=60).stdout
            ok, why = _lua_verdict(out)
            return ok, "%s（本机 luajit）" % why
        except Exception:                                        # noqa: BLE001
            pass
    return None, ("（未做权威 Lua 语法校验：本机无 WAF 容器也无 luajit —— "
                  "可在 WAF 主机跑 `wafcheck.sh lua`，或本机装 luajit）")


def check_symbols(doc_path):
    """符号表 vs 官方文档：找出文档有而表里没有的名字（版本升级后的过期信号）。"""
    if not os.path.exists(doc_path):
        return [("找不到官方文档", doc_path, 0, "用 --doc 指定路径")]
    with open(doc_path, encoding="utf-8") as fh:
        doc = fh.read()
    # 文档里的 URL（如 waf.uusec.com）与 require("waf.log") 都不是 API 名，先剔除
    doc = re.sub(r"https?://\S+", " ", doc)
    doc = re.sub(r'require\s*\(\s*["\'][^"\']*["\']\s*\)', " ", doc)
    doc_names = set(re.findall(r"waf\.([A-Za-z_][A-Za-z0-9_]*)", doc))
    doc_names -= {"log", "util"}          # 引擎内嵌模块名，只在 require 里出现
    known = WAF_FUNCS | WAF_VARS | WAF_CONSTS | PLUGIN_ONLY_VARS | WAF_UNDOC
    problems = []
    for name in sorted(doc_names - known):
        problems.append(("文档有、符号表缺", "waf.%s" % name, 0,
                         "更新 rulecheck.py 顶部的 WAF_FUNCS/WAF_VARS 后本检查才覆盖它"))
    extra = sorted(known - doc_names)
    if extra:
        print("[已知的未文档化符号] %s" % ", ".join("waf." + x for x in extra))
        print("  （这些来自内置规则实测，属正常；官方文档未收录）")
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
        return [("JSON 解析失败", str(exc)[:80], 0, "DSL 规则 content 必须是合法 JSON")]
    if not isinstance(obj, list) or len(obj) != 2:
        return [("结构错误", "(根)", 0, "应为 [动作, 条件数组]")]
    action, conds = obj
    if str(action) not in DSL_ACTIONS:
        problems.append(("动作取值错误", "[0] = %r" % (action,), 0,
                         '应为数字 1=拦截 / 2=允许 / 3=只记录（不是 "block"/"allow"）'))
    if not isinstance(conds, list) or not conds:
        return problems + [("条件数组为空", "[1]", 0, "至少要有一个条件")]
    body = list(conds)
    if not isinstance(body[0], list):
        logic = body.pop(0)
        if logic not in DSL_LOGIC:
            problems.append(("逻辑符取值错误", repr(logic), 0,
                             '应为 "&" / "|" / "~&" / "~|"（不是 "and"/"or"）'))
    for idx, cond in enumerate(body):
        where = "条件[%d]" % (idx + 1)
        if not isinstance(cond, list) or len(cond) != 3:
            problems.append(("条件格式错误", where, 0, "应为 [key, op, val] 三元组"))
            continue
        key, op, val = cond
        if key not in DSL_KEYS:
            near = difflib.get_close_matches(str(key), sorted(DSL_KEYS), n=1, cutoff=0.6)
            problems.append(("参数名未知", "%s key=%r" % (where, key), 0,
                             ("最接近: " + near[0]) if near else "见 management-api §3.2"))
        if op not in DSL_OPS:
            near = difflib.get_close_matches(str(op), sorted(DSL_OPS), n=2, cutoff=0.5)
            problems.append(("操作符未知", "%s op=%r" % (where, op), 0,
                             "面板用符号：* ~* . ~. - ~- ^ $ = ~= > <（"
                             + ("最接近: " + " / ".join(near) if near else "见 §3.2") + "）"))
            continue
        if op in (">", "<") and not re.match(r"^[+-]?\d+(\.\d+)?$", str(val)):
            problems.append(("取值非数字", "%s val=%r" % (where, val), 0,
                             "操作符 > / < 要求数字取值"))
        if op in (".", "~."):
            tool = os.path.join(SCRIPT_DIR, "pcrecheck.py")
            if os.path.exists(tool):
                try:
                    out = subprocess.run([sys.executable, tool, "regex", str(val)],
                                         capture_output=True, text=True, timeout=60)
                    if out.returncode == 2:
                        problems.append(("正则非法", "%s val=%r" % (where, val), 0,
                                         "面板用 JS RegExp 校验、运行时是 PCRE —— "
                                         "此处按 PCRE 报非法，必须改"))
                except Exception:                                # noqa: BLE001
                    pass
    return problems


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def report(title, problems):
    errs = [p for p in problems if len(p) < 5 or p[4] != "warn"]
    warns = [p for p in problems if len(p) == 5 and p[4] == "warn"]
    if not problems:
        print("[通过] %s" % title)
        return 0
    print("[发现问题] %s —— 错误 %d 项 / 提示 %d 项" % (title, len(errs), len(warns)))
    for p in problems:
        kind, what, ln, why = p[0], p[1], p[2], p[3]
        mark = "⚠️ " if (len(p) == 5 and p[4] == "warn") else "❌ "
        loc = "第 %s 行" % ln if ln else ""
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
        print("[符号表来源] %s" % os.path.normpath(doc))
        return report("符号表 vs 官方文档", check_symbols(doc))

    if cmd == "dsl":
        if not path:
            sys.stderr.write("[错误] 用法: rulecheck.py dsl <文件|JSON 字符串>\n")
            return 2
        return report("DSL 结构", check_dsl(path))

    if not path or not os.path.exists(path):
        sys.stderr.write("[错误] 文件不存在: %s\n" % path)
        return 2
    with open(path, encoding="utf-8-sig") as fh:
        src = fh.read()
    nocmt, bare = scan_lua(src)
    rc = 0

    if cmd in ("api", "all"):
        plugin, probs = check_api(path, nocmt, bare, force_plugin)
        rc |= report("%s · API/常量%s" % (path, "/ngx" if not plugin else ""), probs)
        if cmd == "all":
            print("       （识别为%s）" % ("插件" if plugin else "规则"))
    else:
        plugin = is_plugin(nocmt) if force_plugin is None else force_plugin

    if cmd in ("phase", "all"):
        src_phase = None if force_plugin else detect_phase(src)
        use_phase = phase if phase is not None else src_phase
        if use_phase is None:
            if cmd == "phase":
                sys.stderr.write("[提示] 未提供 --phase，且头注释里没有「过滤阶段:」，跳过阶段检查\n")
            else:
                print("  （无「过滤阶段:」头注释，跳过阶段检查 —— 官方内置规则多为极简无头注释；"
                      "自研规则请按模板补上，或用 --phase 指定）")
        else:
            origin = "--phase 指定" if phase is not None else "读自头注释"
            if phase is not None and src_phase is not None and phase != src_phase:
                print("  ⚠️  --phase=%d 与头注释(%d)不一致，按 --phase 检查" % (phase, src_phase))
            rc |= report("%s · 阶段 %d(%s，%s)" % (path, use_phase,
                                                  PHASE_NAME.get(use_phase, "?"), origin),
                         check_phase(bare, use_phase, plugin))

    if cmd in ("hooks", "all"):
        if cmd == "hooks" or plugin:
            rc |= report("%s · 插件钩子/字段" % path, check_hooks(nocmt, bare))

    if cmd in ("modules", "all"):
        listed, probs = check_modules(nocmt)
        if listed:
            print("[require 清单] %s" % ", ".join(sorted(set(listed))))
        rc |= report("%s · 模块可用性" % path, probs)
        if probs:
            print("    " + MODULE_HINT.replace("\n", "\n    "))

    if cmd == "all":
        print("──── 附加通道（语法与正则）────")
        if "--no-lua" in argv:
            print("[Lua 语法] 已按 --no-lua 跳过")
        else:
            ok, why = run_lua_check(path)
            if ok is True:
                print("[Lua 语法] ✅ %s" % why)
            elif ok is False:
                print("[Lua 语法] ❌ %s" % why)
                rc = 1
            else:
                print("[Lua 语法] ⚠️  %s" % why)
        if "--no-regex" in argv:
            print("[正则] 已按 --no-regex 跳过")
        else:
            rrc, lines = run_regex_check(path)
            print("[正则] " + ("跳过" if rrc is None else
                              ("全部合法" if rrc == 0 else "存在非法（见下）")))
            for ln in lines[-12:]:
                print("    " + ln)
            if rrc not in (None, 0):
                rc = 1

    return rc


if __name__ == "__main__":
    sys.exit(main())
