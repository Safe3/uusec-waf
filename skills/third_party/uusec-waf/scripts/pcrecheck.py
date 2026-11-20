#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UUSEC WAF (uuwaf) rule/plugin offline validator -- standalone edition, no container required.

Uses only the Python standard library (ctypes) and binds the PCRE shared library
that ships with the system to validate regular expressions, so it runs on **any
machine with Python 3** -- including machines that are not the same server as the WAF.

Validation channels (by trustworthiness)
----------------------------------------
  P1  ctypes binding to system PCRE2 (libpcre2-8.so.0) -- a **real PCRE engine**, preferred.
      Note: the WAF runtime uses PCRE1 8.45; PCRE2 behaves identically on the syntax
      commonly used in WAF rules. For the differences, see the `engine` subcommand
      output and references/rule-authoring.md.
  P2  If the system has no PCRE2 library, this tool is unavailable (it reports an
      explicit error instead of faking it with Python `re`).

⚠️ **Do not validate with Python's `re` module**: `re` is not PCRE (`\\d`,
   variable-length lookbehind `(?<=)`, possessive quantifiers, `(?(DEFINE))` and
   others all behave differently), so using it would yield a false "everything
   passes" conclusion. This tool would rather report "environment unavailable"
   than give a false conclusion.

Subcommands
-----------
  engine                                    Environment self-check: PCRE library/version/JIT, grep -P comparison
  regex   [-o OPTS] <regex> [subject ...]   Validate regex syntax + match one by one
  cases   [-o OPTS] <regex> <subject file>  Batch comparison, line by line
  extract [-o OPTS] [--lua] [--no-validate] <file.lua>
                                            Extract regex literals embedded in Lua and validate each
                                            (alias file, same as wafcheck.sh)
  lua     <file.lua>                        Lua smoke check (heuristic, see below)

Common options
--------------
  -o OPTS   PCRE option letters, matching the WAF's `"jos"` convention, default "s":
              s=DOTALL  i=case-insensitive  m=multiline  u=UTF-8+UCP  x=extended (ignore whitespace)
              j=JIT compile (on by default offline)  o=compile only once (meaningless offline, ignored)
  --pattern-file F    Read the regex from a file (avoids shell escaping problems)
  --subject-file F    Read the test subject from a file (the whole file as one subject)

Exit codes
----------
  0=valid and all samples matched   1=valid but some samples did not match   2=regex invalid   3=environment error

⚠️ About the `lua` subcommand
-----------------------------
  The Python standard library has **no Lua parser**, so this tool cannot perform
  authoritative Lua syntax validation.
  The `lua` subcommand is a **heuristic smoke check** (brackets/block keywords/string
  closure), and it outputs `BALANCED(heuristic)` or `SYNTAX_SUSPECT`, **deliberately
  avoiding the wording `SYNTAX_OK`** so as not to be confused with luajit's
  authoritative conclusion.
  Authoritative validation still requires luajit (run `luajit -e 'loadfile(...)'` on
  the WAF host).
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
# PCRE2 binding
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
    """Minimal PCRE2 wrapper (only compile / match / error message / config are used)."""

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
                "PCRE2 shared library not found (libpcre2-8).\n"
                "  Linux: apt install libpcre2-8-0 / dnf install pcre2\n"
                "  macOS: brew install pcre2\n"
                "  last error: %s" % last_err)

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
        # Measured: what=11 -> "10.46 2025-08-27"; what=10 -> Unicode version
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
        """Return (code, None) or (None, error message)."""
        pb = pattern.encode("utf-8")
        ec = ctypes.c_int()
        eo = ctypes.c_size_t()
        code = self.lib.pcre2_compile_8(pb, len(pb), opts,
                                        ctypes.byref(ec), ctypes.byref(eo), None)
        if not code:
            return None, "offset %d: %s" % (eo.value, self.errmsg(ec.value))
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
            sys.stderr.write("[error] unknown option letter %r (available: s i m u x j o)\n" % ch)
            sys.exit(3)
        flags |= _OPT[ch]
    return flags


# --------------------------------------------------------------------------- #
# Lua lexical scan (used for regex extraction and smoke checks)
# --------------------------------------------------------------------------- #
def _long_open(src, i):
    """Whether a long-bracket string begins at src[i]; returns (equals count, content start) or None."""
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
    """Scan Lua source and produce a list of tokens.

    token = (kind, value, line)
      kind in {short, long, ident, num, punct}
    Handles: line comments `--`, block comments `--[[ ]] / --[=[ ]=]`, long strings
    (any level), short strings (with escapes), multi-character operators. An
    unclosed string/comment yields a special token ("unclosed", description, line).
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

        # comment
        if src.startswith("--", i):
            lo = _long_open(src, i + 2)
            if lo:
                eq, start = lo
                closer = "]" + "=" * eq + "]"
                k = src.find(closer, start)
                if k < 0:
                    toks.append(("unclosed", "block comment not closed", line))
                    break
                line += src.count("\n", i, k)
                i = k + len(closer)
            else:
                k = src.find("\n", i)
                i = n if k < 0 else k
            continue

        # long string
        lo = _long_open(src, i)
        if lo:
            eq, start = lo
            closer = "]" + "=" * eq + "]"
            k = src.find(closer, start)
            if k < 0:
                toks.append(("unclosed", "long string not closed", line))
                break
            line_at = line
            line += src.count("\n", i, k)
            toks.append(("long", src[start:k], line_at))
            i = k + len(closer)
            continue

        # short string (record the raw content, escapes included)
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
                toks.append(("unclosed", "short string not closed", line))
                break
            toks.append(("short", "".join(buf), line))
            i = j
            continue

        # identifier / keyword
        if c.isalpha() or c == "_":
            j = i
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            toks.append(("ident", src[i:j], line))
            i = j
            continue

        # number (rough, good enough)
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            j = i
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            toks.append(("num", src[i:j], line))
            i = j
            continue

        # multi-character operator
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
    """Restore only the three escapes \\\\ \\" \\'; keep every other \\X as-is (\\d \\t etc. are just as meaningful in PCRE)."""
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
    """Extract regex literals from Lua source.

    Returns [(kind, literal, line)], kind in {"definite", "suspected", "definite-invalid"}.
      definite   a string literal in the waf.rgx*(..., 2nd argument) position, or a
                 variable used as that argument
      suspected  a long string, or a variable whose name looks like a regex
                 (pat/rgx/regex/re/reN/pattern)
    Stronger than the awk version: spans multiple lines, supports [=[ ]=] leveled
    long strings, skips comments correctly, and carries line numbers.
    """
    toks = tokenize_lua(src)

    assigns = {}          # variable name -> (literal, line)
    assign_long = set()   # names of variables whose value is a long string
    rgx_vars = set()      # names of variables used as rgx*'s 2nd argument
    literals = []         # (literal, line, source)

    for idx, (kind, val, line) in enumerate(toks):
        # assignment: ident = <short|long>
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
                literals.append((unescape_lua_short(v), l3, "inline"))
            elif k == "long" and v != "":
                literals.append((v, l3, "inline(long)"))
            elif k == "ident":
                rgx_vars.add(v)

    # assemble the results
    out = []
    seen = set()
    for lit, line, _src in literals:
        key = ("definite", lit)
        if key not in seen:
            seen.add(key)
            out.append(("definite", lit, line))

    # variables used as a rgx* argument -> promoted to "definite"
    for name in rgx_vars:
        if name in assigns:
            lit, line = assigns[name]
            key = ("definite", lit)
            if key not in seen:
                seen.add(key)
                out.append(("definite", lit, line))

    # set of literals already known to be "definite", used for dedup: what is
    # already definite is not reported again as "suspected"
    confirmed = {lit for kind, lit, _ in out if kind == "definite"}

    name_re = re.compile(r"pat|rgx|regex|re$|re[0-9]|pattern", re.I)
    for name, (lit, line) in assigns.items():
        if not lit or lit in confirmed:
            continue
        is_susp = name in assign_long or name_re.search(name)
        if not is_susp:
            continue
        key = ("suspected", lit)
        if key not in seen:
            seen.add(key)
            out.append(("suspected", lit, line))

    out.sort(key=lambda r: (r[2], r[0], r[1]))
    return out


def lua_smoke_check(src):
    """Heuristic smoke check. Returns (ok, [issue descriptions]).

    Deliberately avoids the wording "SYNTAX_OK" -- this is not an authoritative
    Lua compilation check.
    """
    issues = []
    toks = tokenize_lua(src)
    for kind, val, line in toks:
        if kind == "unclosed":
            issues.append("line %d: %s" % (line, val))

    # bracket balancing
    stack = []
    for kind, val, line in toks:
        if kind != "punct":
            continue
        if val in _OPEN_BRACKETS:
            stack.append((val, line))
        elif val in _CLOSE_BRACKETS:
            if not stack or stack[-1][0] != _CLOSE_BRACKETS[val]:
                issues.append("line %d: stray '%s'" % (line, val))
            else:
                stack.pop()
    for val, line in stack:
        issues.append("line %d: '%s' not closed" % (line, val))

    # block keyword balancing: the do following for/while is not counted separately
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
        issues.append("block keywords unbalanced: %d openers (if/function/for/while/do)"
                      " vs %d end" % (openers, ends))
    if repeats != untils:
        issues.append("repeat/until unbalanced: %d vs %d" % (repeats, untils))
    return (not issues), issues


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def eprint(*a):
    sys.stderr.write(" ".join(str(x) for x in a) + "\n")


def die(msg, code=3):
    eprint("[error] %s" % msg)
    sys.exit(code)


def backend_desc(pcre):
    jit = "JIT" if pcre.jit else "no JIT"
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
# Subcommands
# --------------------------------------------------------------------------- #
def detect_waf_container():
    """If a usable UUWAF container exists on this machine, return its name, else None.

    Used only for a hint inside `engine` (to tell the user there is also an exact
    PCRE1 channel); it takes no part in this tool's actual validation.
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
    """Judge a pattern with PCRE1 (the same library grep -P uses) inside the WAF container: returns "valid/invalid/?".

    This is this tool's only source of PCRE1 ground truth; it is used only for the
    measured cross-check performed by `engine`.
    Patterns and samples are passed through files, never spliced into a shell; no
    HTTP request is sent at any point.
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
        if rc == 2:                       # grep -P: 2 = compile/syntax error
            return "invalid"
        if rc in (0, 1):                  # compiled fine (match or not does not matter)
            return "valid"
        return "?"
    except Exception:                                            # noqa: BLE001
        return "?"


def cmd_engine(pcre):
    print("=== Validation engine ===")
    print("  ✅ %s" % backend_desc(pcre))
    print("     Binding: ctypes -> system PCRE2 shared library (a real PCRE engine, not Python re)")
    info = grep_pcre_info()
    if info:
        print("  ·  host grep: %s -> %s (for reference only, not this tool's backend)" % info)
    print("  ✗  Python re : deliberately refused (not PCRE, would give a false conclusion)")
    print()
    print("=== Capability self-check ===")
    checks = [
        ("lookbehind", "(?<=x)y", "xy", True),
        ("non-capturing group", "(?:x)y", "xy", True),
        ("non-greedy", "a{2,}?", "aaa", True),
        ("possessive quantifier", "a++b", "aab", True),
        ("recursion/subroutine", r"^(?<p>a(?&p)?b)$", "aabb", True),
        ("named group", r"(?<n>\d+)", "12", True),
        ("conditional group", r"(?(1)a|b)(x)?", "b", True),
    ]
    for label, pat, subj, want in checks:
        code, err = pcre.compile(pat)
        if code is None:
            print("  ⚠️  %s: compile failed (%s)" % (label, err))
            continue
        try:
            got = pcre.match(code, subj)
        finally:
            pcre.free(code)
        print("  %s %s" % ("✅" if got == want else "❌", label))

    print("  --- invalid regex detection ---")
    code, err = pcre.compile("abc(")
    print("  %s invalid regex detection: %s" % ("✅" if code is None else "❌", err))
    print()
    print("=== Relationship to the WAF runtime (PCRE2 vs PCRE1 8.45) ===")
    print("  The WAF runtime is PCRE1 8.45 + JIT; this tool is PCRE2.")
    print("  Syntax commonly used in WAF rules agrees on both sides: character classes/quantifiers/groups/lookaround/non-greedy/named groups/subroutine calls")
    print("    `(?&name)`/`(?(DEFINE)…)`/`\\K`/branch reset `(?|…)`/possessive quantifiers/`(*SKIP)(*F)`/`\\p{…}`.")
    print("  ⚠️ Known **real differences** (valid in PCRE2, rejected by PCRE1 8.45) -- avoid these when writing rules:")
    print("    · variable-length lookbehind `(?<=a{1,3})` `(?<=ab+)` (PCRE1 requires a fixed-length lookbehind)")
    print("    · bare whole-pattern recursion `(?R)` (PCRE1 reports 'recursive call could loop indefinitely')")

    cname = detect_waf_container()
    if cname:
        probe = [("\\K reset", r"a\Kb", "ab"),
                 ("branch reset (?|…)", r"(?|a(b)|c(d))", "ab"),
                 ("possessive quantifier a*+", r"a*+", "aaa"),
                 ("(*SKIP)(*F)", r"a(*SKIP)(*F)|b", "b"),
                 ("subroutine (?&n)", r"(?<n>a)(?&n)", "aa"),
                 ("conditional group (?(1)…)", r"(?(1)a|b)(x)?", "b"),
                 ("variable-length lookbehind (?<=a{1,3})", r"(?<=a{1,3})b", "aab"),
                 ("bare recursion (?R)", r"(?R)", "a"),
                 ("fixed-length lookbehind (?<=ab)c", r"(?<=ab)c", "abc")]
        print()
        print("=== Measured PCRE1 cross-check on this machine (container '%s', same library as the runtime) ===" % cname)
        for label, pat, subj in probe:
            v1 = _pcre1_verdict(cname, pat, subj)
            code, _ = pcre.compile(pat)
            v2 = "valid" if code is not None else "invalid"
            if code:
                pcre.free(code)
            note = "" if v1 == v2 else "  <- difference!"
            print("  %-22s PCRE2=%-4s PCRE1=%-4s%s" % (label, v2, v1, note))
        print("  -> the table above is measured on this machine, not a static list; when writing rules, go by the PCRE1 column.")
    print()
    print("=== Whether this machine has a WAF container (a higher-fidelity channel) ===")
    cname = detect_waf_container()
    if cname:
        print("  ✅ found container '%s' -- this machine is the WAF host." % cname)
        print("     For PCRE1 validation from the **same library** as the runtime, use instead:")
        print("       wafcheck.sh engine / regex / file   (backend container)")
        print("     pcrecheck.py (this tool) and wafcheck.sh coexist; pick one according to your environment.")
    else:
        print("  ✗ no WAF container on this machine (normal -- an agent is often not on the same machine as the WAF).")
        print("     **Authoritative** Lua syntax validation requires running luajit on the WAF host;")
        print("     on this machine only `pcrecheck.py lua` is available, as a heuristic smoke check.")


def _report_match(pcre, pat, opts, subjects, quiet_ok=False):
    code, err = pcre.compile(pat, opts)
    if code is None:
        print("[invalid] %s" % pat)
        print("        %s" % err)
        return None
    try:
        print("[valid] %s" % pat)
        if not subjects:
            return 0
        fail = 0
        for s in subjects:
            hit = pcre.match(code, s)
            if hit:
                print("  match    | %s" % s.replace("\n", "\\n"))
            else:
                print("  no match | %s" % s.replace("\n", "\\n"))
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
            die("subject file not found: %s" % subjfile, 3)
        subjects = [_read_text(subjfile)]
    if not pat:
        die("usage: pcrecheck.py regex [-o OPTS] <regex> [subject ...]", 3)
    opts = parse_opts(opts_letters)
    print("[engine] %s" % backend_desc(pcre))
    rc = _report_match(pcre, pat, opts, subjects)
    if rc is None:
        sys.exit(2)
    sys.exit(rc)


def cmd_cases(pcre, args):
    opts_letters, pat, rest, patfile, _subjfile = _parse_common(args)
    if patfile:
        pat = _read_text(patfile).rstrip("\n")
    if not pat or not rest:
        die("usage: pcrecheck.py cases [-o OPTS] <regex> <subject file>", 3)
    f = rest[0]
    if not os.path.isfile(f):
        die("subject file not found: %s" % f, 3)
    opts = parse_opts(opts_letters)
    print("[engine] %s" % backend_desc(pcre))
    code, err = pcre.compile(pat, opts)
    if code is None:
        print("[invalid] %s" % pat)
        print("        %s" % err)
        sys.exit(2)
    print("[valid] %s" % pat)
    try:
        with open(f, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                s = raw.rstrip("\n")
                if s == "" or s.startswith("#"):
                    continue
                hit = pcre.match(code, s)
                print("  %s | %s" % ("match   " if hit else "no match", s))
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
        die("usage: pcrecheck.py extract [-o OPTS] [--lua|--no-lua] [--no-validate] <file.lua>", 3)
    f = files[0]
    if not os.path.isfile(f):
        die("file not found: %s" % f, 3)

    src = _read_text(f)
    print("[engine] %s" % backend_desc(pcre))

    if do_lua:
        print("=== Lua smoke check (heuristic, not authoritative) ===")
        ok, issues = lua_smoke_check(src)
        if ok:
            print("  BALANCED(heuristic)  -- brackets/block keywords/string closure look fine")
            print("  ⚠️  this is not a luajit compilation check; authoritative validation requires luajit on the WAF host")
        else:
            for it in issues:
                print("  SYNTAX_SUSPECT: %s" % it)

    lits = extract_literals(src)
    print()
    print("=== Extracted regexes ===")
    if not lits:
        print("  (no regex extracted -- the file may not use waf.rgx* but waf.startWith/pmMatch etc.; most official examples are of that kind)")
        return

    opts = parse_opts(opts_letters)
    bad = susp = 0
    for kind, lit, line in lits:
        if not do_validate:
            print("  [%s] L%-4d %s" % (kind, line, lit))
            continue
        code, err = pcre.compile(lit, opts)
        if code is None:
            if kind == "definite":
                bad += 1
                print("  [definite-invalid] L%-4d %s" % (line, lit))
            else:
                susp += 1
                print("  [suspected-invalid] L%-4d %s   <- not certain it is used as a regex, please confirm manually" % (line, lit))
            print("                %s" % err)
        else:
            pcre.free(code)
            print("  [%s] L%-4d %s" % (kind, line, lit))
    print("total %d: definite-invalid %d, suspected-invalid %d" % (len(lits), bad, susp))
    if bad:
        sys.exit(2)


def cmd_lua(pcre, args):
    files = [a for a in args if not a.startswith("-")]
    if not files:
        die("usage: pcrecheck.py lua <file.lua>", 3)
    f = files[0]
    if not os.path.isfile(f):
        die("file not found: %s" % f, 3)
    ok, issues = lua_smoke_check(_read_text(f))
    if ok:
        print("BALANCED(heuristic)  %s" % f)
        print("⚠️  heuristic check, not an authoritative Lua compilation check.")
        print("   authoritative validation: run luajit -e 'loadfile(\"%s\")' on the WAF host" % f)
    else:
        print("SYNTAX_SUSPECT  %s" % f)
        for it in issues:
            print("  - %s" % it)
        sys.exit(1)


def _parse_common(args):
    """Parse [-o OPTS] [--pattern-file F] [-f|--subject-file F] <pat> [rest...]"""
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
    elif cmd in ("extract", "file"):        # file is an alias for compatibility with wafcheck.sh
        cmd_extract(pcre, rest)
    elif cmd == "lua":
        cmd_lua(pcre, rest)
    else:
        die("unknown subcommand: %s (available: engine/regex/cases/extract(alias file)/lua)" % cmd, 1)


if __name__ == "__main__":
    main()
