#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UUSEC WAF（南墙）规则/插件离线校验器 —— 独立版，不依赖容器。

只用 Python 标准库（ctypes），通过绑定系统自带的 PCRE 动态库来校验正则，
因此在**任何有 Python 3 的机器**上都能跑 —— 包括和 WAF 不在同一台服务器的情况。

校验通道（按可信度）
--------------------
  P1  ctypes 绑定系统 PCRE2（libpcre2-8.so.0）—— **真 PCRE 引擎**，首选。
      注：WAF 运行时用的是 PCRE1 8.45；PCRE2 在 WAF 规则常用语法上一致，
      差异见 `engine` 子命令输出与 references/rule-authoring.md。
  P2  若系统无 PCRE2 库，则本工具不可用（会明确报错，不用 Python re 糊弄）。

⚠️ **不用 Python 的 `re` 模块校验**：`re` 不是 PCRE（`\\d`、`(?<=)` 变长后顾、
   占有量词、`(?(DEFINE))` 等行为都不同），用它校验会给出"全部通过"的假结论。
   本工具宁可报"环境不可用"，也不给假结论。

子命令
------
  engine                                    环境自检：PCRE 库/版本/JIT、grep -P 对照
  regex   [-o OPTS] <正则> [测试串 ...]      校验正则语法 + 逐条匹配
  cases   [-o OPTS] <正则> <测试串文件>      按行批量比对
  extract [-o OPTS] [--lua] [--no-validate] <文件.lua>
                                            提取 Lua 里的正则字面量并逐个校验
                                            （别名 file，与 wafcheck.sh 一致）
  lua     <文件.lua>                        Lua 冒烟检查（启发式，见下）

通用选项
--------
  -o OPTS   PCRE 选项字母，对齐 WAF 的 `"jos"` 约定，默认 "s"：
              s=DOTALL  i=忽略大小写  m=多行  u=UTF-8+UCP  x=扩展(忽略空白)
              j=JIT 编译（离线默认开）  o=只编译一次（离线无意义，忽略）
  --pattern-file F    从文件读正则（避免 shell 转义问题）
  --subject-file F    从文件读测试串（整份文件作为一个测试串）

退出码
------
  0=合法且样例全部命中   1=合法但有样例未命中   2=正则非法   3=环境错误

⚠️ 关于 `lua` 子命令
--------------------
  Python 标准库**没有 Lua 解析器**，本工具无法做权威的 Lua 语法校验。
  `lua` 子命令是**启发式冒烟检查**（括号/块关键字/字符串闭合），
  输出为 `BALANCED(heuristic)` 或 `SYNTAX_SUSPECT`，**刻意不使用 `SYNTAX_OK`
  这一措辞**，以免与 luajit 的权威结论混淆。
  权威校验仍需 luajit（在 WAF 主机上执行 `luajit -e 'loadfile(...)'`）。
"""
import ctypes
import ctypes.util
import json
import os
import re
import shutil
import subprocess
import sys

# --------------------------------------------------------------------------- #
# PCRE2 绑定
# --------------------------------------------------------------------------- #
PCRE2_CASELESS = 0x00000008
PCRE2_MULTILINE = 0x00000400
PCRE2_DOTALL = 0x00000020
PCRE2_EXTENDED = 0x00000080
PCRE2_UCP = 0x00020000
PCRE2_UTF = 0x00080000
PCRE2_JIT_COMPLETE = 0x00000001

_OPT = {
    "i": PCRE2_CASELESS,
    "m": PCRE2_MULTILINE,
    "s": PCRE2_DOTALL,
    "x": PCRE2_EXTENDED,
    "u": PCRE2_UTF | PCRE2_UCP,
}


class Pcre:
    """极简 PCRE2 封装（只用到 compile / match / error message / config）。"""

    def __init__(self, libname=None):
        self.path = None
        candidates = [libname] if libname else []
        found = ctypes.util.find_library("pcre2-8")
        if found:
            candidates.append(found)
        candidates += ["libpcre2-8.so.0", "libpcre2-8.so",
                       "libpcre2-8.dylib", "pcre2-8.dll"]
        last_err = None
        for cand in candidates:
            if not cand:
                continue
            try:
                self.lib = ctypes.CDLL(cand)
                self.path = cand
                break
            except OSError as exc:                              # noqa: PERF203
                last_err = exc
        else:
            raise RuntimeError(
                "找不到 PCRE2 动态库（libpcre2-8）。\n"
                "  Linux: apt install libpcre2-8-0 / dnf install pcre2\n"
                "  macOS: brew install pcre2\n"
                "  最后错误: %s" % last_err)

        L = self.lib
        L.pcre2_config_8.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        L.pcre2_config_8.restype = ctypes.c_int

        L.pcre2_compile_8.restype = ctypes.c_void_p
        L.pcre2_compile_8.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p]

        L.pcre2_code_free_8.argtypes = [ctypes.c_void_p]
        L.pcre2_code_free_8.restype = None

        L.pcre2_match_data_create_from_pattern_8.restype = ctypes.c_void_p
        L.pcre2_match_data_create_from_pattern_8.argtypes = [ctypes.c_void_p,
                                                             ctypes.c_void_p]
        L.pcre2_match_data_free_8.argtypes = [ctypes.c_void_p]
        L.pcre2_match_data_free_8.restype = None

        L.pcre2_match_8.restype = ctypes.c_int
        L.pcre2_match_8.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t,
            ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]

        L.pcre2_get_error_message_8.restype = ctypes.c_int
        L.pcre2_get_error_message_8.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                                ctypes.c_size_t]

        L.pcre2_jit_compile_8.restype = ctypes.c_int
        L.pcre2_jit_compile_8.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    # -- config ----------------------------------------------------------- #
    def _config_str(self, what):
        buf = ctypes.create_string_buffer(256)
        rc = self.lib.pcre2_config_8(what, ctypes.byref(buf))
        if rc <= 0:
            return None
        return buf.raw[:rc - 1].decode("utf-8", "replace")

    def _config_int(self, what):
        num = ctypes.c_uint32(0)
        rc = self.lib.pcre2_config_8(what, ctypes.byref(num))
        return num.value if rc >= 0 else None

    @property
    def version(self):
        # 实测：what=11 → "10.46 2025-08-27"；what=10 → Unicode 版本
        return self._config_str(11) or "?"

    @property
    def unicode_version(self):
        return self._config_str(10) or "?"

    @property
    def jit(self):
        return bool(self._config_int(1))

    def errmsg(self, code):
        buf = ctypes.create_string_buffer(256)
        rc = self.lib.pcre2_get_error_message_8(code, buf, len(buf))
        if rc < 0:
            return "PCRE2 error %d" % code
        return buf.raw[:rc].decode("utf-8", "replace")

    # -- compile / match -------------------------------------------------- #
    def compile(self, pattern, opts=0, use_jit=True):
        """返回 (code, None) 或 (None, 错误信息)。"""
        pb = pattern.encode("utf-8")
        ec = ctypes.c_int()
        eo = ctypes.c_size_t()
        code = self.lib.pcre2_compile_8(pb, len(pb), opts,
                                        ctypes.byref(ec), ctypes.byref(eo), None)
        if not code:
            return None, "偏移 %d: %s" % (eo.value, self.errmsg(ec.value))
        if use_jit:
            self.lib.pcre2_jit_compile_8(code, PCRE2_JIT_COMPLETE)
        return code, None

    def match(self, code, subject):
        md = self.lib.pcre2_match_data_create_from_pattern_8(code, None)
        if not md:
            return None
        try:
            sb = subject.encode("utf-8")
            rc = self.lib.pcre2_match_8(code, sb, len(sb), 0, 0, md, None)
            return rc >= 0
        finally:
            self.lib.pcre2_match_data_free_8(md)

    def free(self, code):
        if code:
            self.lib.pcre2_code_free_8(code)


def parse_opts(letters):
    flags = 0
    for ch in (letters or ""):
        if ch in ("j", "o"):
            continue
        if ch not in _OPT:
            sys.stderr.write("[错误] 未知选项字母 %r（可用 s i m u x j o）\n" % ch)
            sys.exit(3)
        flags |= _OPT[ch]
    return flags


# --------------------------------------------------------------------------- #
# Lua 词法扫描（用于正则提取与冒烟检查）
# --------------------------------------------------------------------------- #
def _long_open(src, i):
    """src[i] 起是否为长括号串开头，返回 (等号数, 内容起点) 或 None。"""
    if i >= len(src) or src[i] != "[":
        return None
    j = i + 1
    eq = 0
    while j < len(src) and src[j] == "=":
        eq += 1
        j += 1
    if j < len(src) and src[j] == "[":
        return eq, j + 1
    return None


def tokenize_lua(src):
    """扫描 Lua 源码，产出 token 列表。

    token = (kind, value, line)
      kind ∈ {short, long, ident, num, punct}
    处理：行注释 `--`、块注释 `--[[ ]] / --[=[ ]=]`、长字符串（任意层级）、
    短字符串（含转义）、多字符运算符。未闭合的字符串/注释返回 special token
    ("unclosed", 描述, line)。
    """
    toks = []
    i, n, line = 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r\f\v":
            i += 1
            continue

        # 注释
        if src.startswith("--", i):
            lo = _long_open(src, i + 2)
            if lo:
                eq, start = lo
                closer = "]" + "=" * eq + "]"
                k = src.find(closer, start)
                if k < 0:
                    toks.append(("unclosed", "块注释未闭合", line))
                    break
                line += src.count("\n", i, k)
                i = k + len(closer)
            else:
                k = src.find("\n", i)
                i = n if k < 0 else k
            continue

        # 长字符串
        lo = _long_open(src, i)
        if lo:
            eq, start = lo
            closer = "]" + "=" * eq + "]"
            k = src.find(closer, start)
            if k < 0:
                toks.append(("unclosed", "长字符串未闭合", line))
                break
            line_at = line
            line += src.count("\n", i, k)
            toks.append(("long", src[start:k], line_at))
            i = k + len(closer)
            continue

        # 短字符串（记录原始内容，含转义）
        if c in "\"'":
            quote = c
            j = i + 1
            buf = []
            ok = False
            while j < n:
                ch = src[j]
                if ch == "\\":
                    if j + 1 < n:
                        buf.append(src[j:j + 2])
                        j += 2
                        continue
                    break
                if ch == "\n":
                    break
                if ch == quote:
                    ok = True
                    j += 1
                    break
                buf.append(ch)
                j += 1
            if not ok:
                toks.append(("unclosed", "短字符串未闭合", line))
                break
            toks.append(("short", "".join(buf), line))
            i = j
            continue

        # 标识符 / 关键字
        if c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            toks.append(("ident", src[i:j], line))
            i = j
            continue

        # 数字（粗略，够用即可）
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            j = i
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            toks.append(("num", src[i:j], line))
            i = j
            continue

        # 多字符运算符
        for op in ("...", "..", "==", "~=", "<=", ">=", "::"):
            if src.startswith(op, i):
                toks.append(("punct", op, line))
                i += len(op)
                break
        else:
            toks.append(("punct", c, line))
            i += 1
    return toks


def unescape_lua_short(s):
    """只还原 \\\\ \\" \\' 三个转义，其余 \\X 原样保留（\\d \\t 等在 PCRE 里同样有意义）。"""
    out = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] in "\\\"'":
            out.append(s[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


_OPEN_BRACKETS = {"(": ")", "[": "]", "{": "}"}
_CLOSE_BRACKETS = {")": "(", "]": "[", "}": "{"}


def extract_literals(src):
    """提取 Lua 源码中的正则字面量。

    返回 [(kind, literal, line)]，kind ∈ {"确定", "疑似", "确定-非法"}。
      确定  在 waf.rgx*(…, 第2参数) 位置的字符串字面量，或作为该参数使用的变量
      疑似  长字符串，或名字像正则（pat/rgx/regex/re/reN/pattern）的变量
    比 awk 版更强的点：可跨行、支持 [=[ ]=] 层级长字符串、注释正确跳过、带行号。
    """
    toks = tokenize_lua(src)

    assigns = {}          # 变量名 → (literal, line)
    assign_long = set()   # 值为长字符串的变量名
    rgx_vars = set()      # 用作 rgx* 第 2 参数的变量名
    literals = []         # (literal, line, 来源)

    for idx, (kind, val, line) in enumerate(toks):
        # 赋值： ident = <short|long>
        if kind == "ident" and idx + 2 < len(toks):
            k1, v1, _ = toks[idx + 1]
            k2, v2, l2 = toks[idx + 2]
            if (k1 == "punct" and v1 == "="
                    and k2 in ("short", "long") and v2 != ""):
                lit = unescape_lua_short(v2) if k2 == "short" else v2
                assigns[val] = (lit, l2)
                if k2 == "long":
                    assign_long.add(val)

        # rgx*( … , <arg2>
        if kind == "ident" and val.startswith("rgx") and idx + 1 < len(toks):
            k1, v1, _ = toks[idx + 1]
            if not (k1 == "punct" and v1 == "("):
                continue
            depth = 1
            j = idx + 2
            arg2 = None
            while j < len(toks):
                k, v, _ = toks[j]
                if k == "punct" and v in _OPEN_BRACKETS:
                    depth += 1
                elif k == "punct" and v in _CLOSE_BRACKETS:
                    depth -= 1
                    if depth == 0:
                        break
                elif k == "punct" and v == "," and depth == 1:
                    j += 1
                    if j < len(toks):
                        arg2 = toks[j]
                    break
                j += 1
            if arg2 is None:
                continue
            k, v, l3 = arg2
            if k == "short" and v != "":
                literals.append((unescape_lua_short(v), l3, "内联"))
            elif k == "long" and v != "":
                literals.append((v, l3, "内联(长)"))
            elif k == "ident":
                rgx_vars.add(v)

    # 组装结果
    out = []
    seen = set()
    for lit, line, _src in literals:
        key = ("确定", lit)
        if key not in seen:
            seen.add(key)
            out.append(("确定", lit, line))

    # 被 rgx* 用作参数的变量 → 升为「确定」
    for name in rgx_vars:
        if name in assigns:
            lit, line = assigns[name]
            key = ("确定", lit)
            if key not in seen:
                seen.add(key)
                out.append(("确定", lit, line))

    # 已知「确定」的字面量集合，用于去重：已确定的不再重复报「疑似」
    confirmed = {lit for kind, lit, _ in out if kind == "确定"}

    name_re = re.compile(r"pat|rgx|regex|re$|re[0-9]|pattern", re.I)
    for name, (lit, line) in assigns.items():
        if not lit or lit in confirmed:
            continue
        is_susp = name in assign_long or name_re.search(name)
        if not is_susp:
            continue
        key = ("疑似", lit)
        if key not in seen:
            seen.add(key)
            out.append(("疑似", lit, line))

    out.sort(key=lambda r: (r[2], r[0], r[1]))
    return out


def lua_smoke_check(src):
    """启发式冒烟检查。返回 (ok, [问题描述])。

    刻意不使用 "SYNTAX_OK" 措辞 —— 这不是权威的 Lua 编译校验。
    """
    issues = []
    toks = tokenize_lua(src)
    for kind, val, line in toks:
        if kind == "unclosed":
            issues.append("第 %d 行: %s" % (line, val))

    # 括号配平
    stack = []
    for kind, val, line in toks:
        if kind != "punct":
            continue
        if val in _OPEN_BRACKETS:
            stack.append((val, line))
        elif val in _CLOSE_BRACKETS:
            if not stack or stack[-1][0] != _CLOSE_BRACKETS[val]:
                issues.append("第 %d 行: 多余的 '%s'" % (line, val))
            else:
                stack.pop()
    for val, line in stack:
        issues.append("第 %d 行: '%s' 未闭合" % (line, val))

    # 块关键字配平：for/while 后面的 do 不额外计入
    openers = 0
    pending_do = 0
    ends = 0
    repeats = 0
    untils = 0
    prev = None
    for kind, val, line in toks:
        if kind != "ident":
            prev = val if kind == "punct" else prev
            continue
        if val in ("for", "while"):
            openers += 1
            pending_do += 1
        elif val == "do":
            if pending_do > 0:
                pending_do -= 1
            else:
                openers += 1
        elif val in ("if", "function"):
            openers += 1
        elif val == "repeat":
            repeats += 1
        elif val == "until":
            untils += 1
        elif val == "end":
            ends += 1
        prev = val
    if openers != ends:
        issues.append("块关键字不配平：开启 %d 个（if/function/for/while/do）"
                      "vs %d 个 end" % (openers, ends))
    if repeats != untils:
        issues.append("repeat/until 不配平：%d vs %d" % (repeats, untils))
    return (not issues), issues


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
def eprint(*a):
    sys.stderr.write(" ".join(str(x) for x in a) + "\n")


def die(msg, code=3):
    eprint("[错误] %s" % msg)
    sys.exit(code)


def backend_desc(pcre):
    jit = "JIT" if pcre.jit else "无 JIT"
    return "PCRE2 %s (%s, %s, Unicode %s)" % (
        pcre.version, pcre.path, jit, pcre.unicode_version)


def grep_pcre_info():
    g = shutil.which("grep")
    if not g:
        return None
    try:
        ver = subprocess.run([g, "--version"], capture_output=True, text=True,
                             timeout=10).stdout.splitlines()
        ver = ver[0] if ver else "?"
    except Exception:                                            # noqa: BLE001
        ver = "?"
    lib = "?"
    if sys.platform.startswith("linux") and shutil.which("ldd"):
        try:
            out = subprocess.run(["ldd", g], capture_output=True, text=True,
                                 timeout=10).stdout
            m = re.search(r"(libpcre2?[-\w]*\.so[\w.]*)", out)
            if m:
                lib = m.group(1)
        except Exception:                                        # noqa: BLE001
            pass
    return ver, lib


# --------------------------------------------------------------------------- #
# 子命令
# --------------------------------------------------------------------------- #
def detect_waf_container():
    """若本机有可用的 UUWAF 容器，返回容器名，否则 None。

    仅在 `engine` 里做提示用（告诉使用者还有 PCRE1 精确通道），
    不参与本工具的实际校验。
    """
    if not shutil.which("docker"):
        return None
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}} {{.Image}}"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:                                            # noqa: BLE001
        return None
    for ln in out.splitlines():
        low = ln.lower()
        if "uusec/waf" in low or "uuwaf" in low:
            return ln.split()[0]
    for name in (ln.split()[0] for ln in out.splitlines() if ln.strip()):
        try:
            rc = subprocess.run(["docker", "exec", name, "sh", "-c",
                                 "test -x /uuwaf/sbin/uuwaf"],
                                capture_output=True, timeout=10).returncode
            if rc == 0:
                return name
        except Exception:                                        # noqa: BLE001
            continue
    return None


def _pcre1_verdict(container, pat, subj):
    """在 WAF 容器内用 PCRE1（grep -P 同源库）判定一个模式：返回「合法/非法/?」。

    这是本工具唯一的 PCRE1 真值来源；仅在 `engine` 的实测复核里使用。
    模式与样例经文件传递，不拼进 shell；全程不发 HTTP 请求。
    """
    import tempfile
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".p", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(pat)
            pf = fh.name
        subprocess.run(["docker", "cp", pf, "%s:/tmp/.pcre1.p" % container],
                       capture_output=True, timeout=15)
        rc = subprocess.run(["docker", "exec", container, "sh", "-c",
                             'grep -qP -f /tmp/.pcre1.p /dev/null'],
                            capture_output=True, text=True, timeout=15).returncode
        os.unlink(pf)
        if rc == 2:                       # grep -P：2 = 编译/语法错误
            return "非法"
        if rc in (0, 1):                  # 编译通过（命中与否不关心）
            return "合法"
        return "?"
    except Exception:                                            # noqa: BLE001
        return "?"


def cmd_engine(pcre):
    print("=== 校验引擎 ===")
    print("  ✅ %s" % backend_desc(pcre))
    print("     绑定方式: ctypes → 系统 PCRE2 动态库（真 PCRE 引擎，非 Python re）")
    info = grep_pcre_info()
    if info:
        print("  ·  宿主 grep: %s → %s（仅供参考，非本工具后端）" % info)
    print("  ✗  Python re : 主动拒绝（非 PCRE，会给出假结论）")
    print()
    print("=== 能力自检 ===")
    checks = [
        ("lookbehind 后顾", "(?<=x)y", "xy", True),
        ("非捕获组", "(?:x)y", "xy", True),
        ("非贪婪", "a{2,}?", "aaa", True),
        ("占有量词", "a++b", "aab", True),
        ("递归/子程序", r"^(?<p>a(?&p)?b)$", "aabb", True),
        ("命名分组", r"(?<n>\d+)", "12", True),
        ("条件组", r"(?(1)a|b)(x)?", "b", True),
    ]
    for label, pat, subj, want in checks:
        code, err = pcre.compile(pat)
        if code is None:
            print("  ⚠️  %s: 编译失败（%s）" % (label, err))
            continue
        try:
            got = pcre.match(code, subj)
        finally:
            pcre.free(code)
        print("  %s %s" % ("✅" if got == want else "❌", label))

    print("  --- 非法正则识别 ---")
    code, err = pcre.compile("abc(")
    print("  %s 非法正则识别：%s" % ("✅" if code is None else "❌", err))
    print()
    print("=== 与 WAF 运行时的关系（PCRE2 vs PCRE1 8.45）===")
    print("  WAF 运行时为 PCRE1 8.45 + JIT；本工具为 PCRE2。")
    print("  WAF 常用语法两边一致：字符类/量词/分组/前后顾/非贪婪/命名分组/子程序调用")
    print("    `(?&name)`/`(?(DEFINE)…)`/`\\K`/分支重置 `(?|…)`/占有量词/`(*SKIP)(*F)`/`\\p{…}`。")
    print("  ⚠️ 已知**真差异**（PCRE2 合法、PCRE1 8.45 拒绝）——写规则时避免：")
    print("    · 变长后顾 `(?<=a{1,3})` `(?<=ab+)`（PCRE1 要求后顾定长）")
    print("    · 裸整串递归 `(?R)`（PCRE1 报 'recursive call could loop indefinitely'）")

    cname = detect_waf_container()
    if cname:
        probe = [("\\K 环视复位", r"a\Kb", "ab"),
                 ("分支重置 (?|…)", r"(?|a(b)|c(d))", "ab"),
                 ("占有量词 a*+", r"a*+", "aaa"),
                 ("(*SKIP)(*F)", r"a(*SKIP)(*F)|b", "b"),
                 ("子程序 (?&n)", r"(?<n>a)(?&n)", "aa"),
                 ("条件组 (?(1)…)", r"(?(1)a|b)(x)?", "b"),
                 ("变长后顾 (?<=a{1,3})", r"(?<=a{1,3})b", "aab"),
                 ("裸递归 (?R)", r"(?R)", "a"),
                 ("定长后顾 (?<=ab)c", r"(?<=ab)c", "abc")]
        print()
        print("=== 本机 PCRE1 实测复核（容器 '%s'，与运行时同源）===" % cname)
        for label, pat, subj in probe:
            v1 = _pcre1_verdict(cname, pat, subj)
            code, _ = pcre.compile(pat)
            v2 = "合法" if code is not None else "非法"
            if code:
                pcre.free(code)
            note = "" if v1 == v2 else "  ← 差异！"
            print("  %-22s PCRE2=%-4s PCRE1=%-4s%s" % (label, v2, v1, note))
        print("  → 上表为本机实测，非静态清单；写规则以 PCRE1 列为准。")
    print()
    print("=== 本机是否有 WAF 容器（更高保真通道）===")
    cname = detect_waf_container()
    if cname:
        print("  ✅ 发现容器 '%s' —— 本机即为 WAF 主机。" % cname)
        print("     追求与运行时**同源**的 PCRE1 校验时，可改用：")
        print("       wafcheck.sh engine / regex / file   （后端 container）")
        print("     pcrecheck.py（本工具）与 wafcheck.sh 并存，按环境择一。")
    else:
        print("  ✗ 本机无 WAF 容器（正常——agent 常与 WAF 不同机）。")
        print("     Lua 的**权威**语法校验需在 WAF 主机执行 luajit；")
        print("     本机只能用 `pcrecheck.py lua` 做启发式冒烟检查。")


def _report_match(pcre, pat, opts, subjects, quiet_ok=False):
    code, err = pcre.compile(pat, opts)
    if code is None:
        print("[非法] %s" % pat)
        print("        %s" % err)
        return None
    try:
        print("[合法] %s" % pat)
        if not subjects:
            return 0
        fail = 0
        for s in subjects:
            hit = pcre.match(code, s)
            if hit:
                print("  命中    | %s" % s.replace("\n", "\\n"))
            else:
                print("  不命中  | %s" % s.replace("\n", "\\n"))
                fail = 1
        return fail
    finally:
        pcre.free(code)


def cmd_regex(pcre, args):
    opts_letters, pat, subjects, patfile, subjfile = _parse_common(args)
    if patfile:
        pat = _read_text(patfile).rstrip("\n")
    if subjfile:
        if not os.path.isfile(subjfile):
            die("测试串文件不存在: %s" % subjfile, 3)
        subjects = [_read_text(subjfile)]
    if not pat:
        die("用法: pcrecheck.py regex [-o OPTS] <正则> [测试串 ...]", 3)
    opts = parse_opts(opts_letters)
    print("[引擎] %s" % backend_desc(pcre))
    rc = _report_match(pcre, pat, opts, subjects)
    if rc is None:
        sys.exit(2)
    sys.exit(rc)


def cmd_cases(pcre, args):
    opts_letters, pat, rest, patfile, _subjfile = _parse_common(args)
    if patfile:
        pat = _read_text(patfile).rstrip("\n")
    if not pat or not rest:
        die("用法: pcrecheck.py cases [-o OPTS] <正则> <测试串文件>", 3)
    f = rest[0]
    if not os.path.isfile(f):
        die("测试串文件不存在: %s" % f, 3)
    opts = parse_opts(opts_letters)
    print("[引擎] %s" % backend_desc(pcre))
    code, err = pcre.compile(pat, opts)
    if code is None:
        print("[非法] %s" % pat)
        print("        %s" % err)
        sys.exit(2)
    print("[合法] %s" % pat)
    try:
        with open(f, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                s = raw.rstrip("\n")
                if s == "" or s.startswith("#"):
                    continue
                hit = pcre.match(code, s)
                print("  %s | %s" % ("命中  " if hit else "不命中", s))
    finally:
        pcre.free(code)


def cmd_extract(pcre, args):
    opts_letters = "s"
    do_lua = True
    do_validate = True
    files = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-o" and i + 1 < len(args):
            opts_letters = args[i + 1]
            i += 2
            continue
        if a == "--lua":
            do_lua = True
            i += 1
            continue
        if a == "--no-lua":
            do_lua = False
            i += 1
            continue
        if a == "--no-validate":
            do_validate = False
            i += 1
            continue
        files.append(a)
        i += 1
    if not files:
        die("用法: pcrecheck.py extract [-o OPTS] [--lua|--no-lua] [--no-validate] <文件.lua>", 3)
    f = files[0]
    if not os.path.isfile(f):
        die("文件不存在: %s" % f, 3)

    src = _read_text(f)
    print("[引擎] %s" % backend_desc(pcre))

    if do_lua:
        print("=== Lua 冒烟检查（启发式，非权威）===")
        ok, issues = lua_smoke_check(src)
        if ok:
            print("  BALANCED(heuristic)  —— 括号/块关键字/字符串闭合看起来正常")
            print("  ⚠️  这不是 luajit 编译校验；权威校验需在 WAF 主机执行 luajit")
        else:
            for it in issues:
                print("  SYNTAX_SUSPECT: %s" % it)

    lits = extract_literals(src)
    print()
    print("=== 提取到的正则 ===")
    if not lits:
        print("  （未提取到正则——该文件可能未用 waf.rgx*，而用 waf.startWith/pmMatch 等；官方示例多属此类）")
        return

    opts = parse_opts(opts_letters)
    bad = susp = 0
    for kind, lit, line in lits:
        if not do_validate:
            print("  [%s] L%-4d %s" % (kind, line, lit))
            continue
        code, err = pcre.compile(lit, opts)
        if code is None:
            if kind == "确定":
                bad += 1
                print("  [确定-非法] L%-4d %s" % (line, lit))
            else:
                susp += 1
                print("  [疑似-非法] L%-4d %s   <- 不确定是否作正则用，请人工确认" % (line, lit))
            print("                %s" % err)
        else:
            pcre.free(code)
            print("  [%s] L%-4d %s" % (kind, line, lit))
    print("共 %d 条：确定非法 %d 条，疑似非法 %d 条" % (len(lits), bad, susp))
    if bad:
        sys.exit(2)


def cmd_lua(pcre, args):
    files = [a for a in args if not a.startswith("-")]
    if not files:
        die("用法: pcrecheck.py lua <文件.lua>", 3)
    f = files[0]
    if not os.path.isfile(f):
        die("文件不存在: %s" % f, 3)
    ok, issues = lua_smoke_check(_read_text(f))
    if ok:
        print("BALANCED(heuristic)  %s" % f)
        print("⚠️  启发式检查，不是权威 Lua 编译校验。")
        print("   权威校验：在 WAF 主机执行 luajit -e 'loadfile(\"%s\")'" % f)
    else:
        print("SYNTAX_SUSPECT  %s" % f)
        for it in issues:
            print("  - %s" % it)
        sys.exit(1)


def _parse_common(args):
    """解析 [-o OPTS] [--pattern-file F] [-f|--subject-file F] <pat> [rest...]"""
    opts_letters = "s"
    patfile = None
    subjfile = None
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "--opt") and i + 1 < len(args):
            opts_letters = args[i + 1]
            i += 2
            continue
        if a == "--pattern-file" and i + 1 < len(args):
            patfile = args[i + 1]
            i += 2
            continue
        if a in ("-f", "--subject-file") and i + 1 < len(args):
            subjfile = args[i + 1]
            i += 2
            continue
        rest.append(a)
        i += 1
    pat = rest[0] if rest else None
    return opts_letters, pat, rest[1:], patfile, subjfile


def _read_text(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(0 if argv else 1)

    cmd, rest = argv[0], argv[1:]

    try:
        pcre = Pcre()
    except RuntimeError as exc:
        die(str(exc), 3)

    if cmd == "engine":
        cmd_engine(pcre)
    elif cmd == "regex":
        cmd_regex(pcre, rest)
    elif cmd == "cases":
        cmd_cases(pcre, rest)
    elif cmd in ("extract", "file"):        # file 为兼容 wafcheck.sh 的别名
        cmd_extract(pcre, rest)
    elif cmd == "lua":
        cmd_lua(pcre, rest)
    else:
        die("未知子命令: %s（可用 engine/regex/cases/extract(别名 file)/lua）" % cmd, 1)


if __name__ == "__main__":
    main()
