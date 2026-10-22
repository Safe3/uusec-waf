# Rule Authoring

> **Read `internals.md` first**: execution order (ascending ID), `RULE_ALLOW` short-circuiting the whole chain, the rule library and the ruleset being separate, and built-in rules being unmodifiable — these four things directly determine whether a rule can take effect.
> The full inventory of API variables and functions is in `offline-docs/api.zh-CN.md` (official text). This document only covers **how to write it correctly**.

---

## 1. Rule Template

```lua
--[[
Rule name: <name>
Filtering stage: <request phase / response header phase / response body phase>
Threat level: <low / medium / high / critical>
Rule description: <functional overview; do not write specific threshold parameters, so the description stays accurate after parameters are changed>
--]]

-- <--- Configuration parameters --->
-- all tunables are gathered here, self-explanatory names, each annotated
local enableXXX      = true        -- master switch
local threshold      = 100         -- maximum number of requests allowed within the time window
local timeWindow     = 60          -- statistics time window, in seconds
local banDuration    = 300         -- ban duration after exceeding the limit, in seconds
local countStatic    = false       -- whether to count static resource requests

-- <--- Utility functions --->
-- split complex logic into local functions, named starting with a verb
local function isDynamic(waf)
    return waf.isQueryString or ((waf.reqContentLength or 0) > 0)
end

-- <--- Main logic --->
local uri = waf.uri or ""          -- nil safety

if not enableXXX then return false end

-- ...detection logic...

return false                    -- pass (do not block)
-- return waf.RULE_BLOCK, "reason" -- block
-- return waf.RULE_ALLOW, "reason" -- allowlist (⚠️ skips the entire subsequent rule chain)
-- return waf.RULE_LOG_ONLY, "reason" -- log only (v7.2.0+)
```

Three return-value constants:

| Constant | Value | Meaning |
|:---|:---|:---|
| `waf.RULE_BLOCK` | 1 | Block |
| `waf.RULE_ALLOW` | 2 | Allow (**skips all subsequent rules**) |
| `waf.RULE_LOG_ONLY` | 3 | Log only (per-rule observation mode, v7.2.0+) |

**Sectioned skeleton**: delimit sections with `-- <--- name --->`; recommended order = configuration parameters → utility functions → main logic.
Configuration parameters are always **grouped up front** (easier to modify and hand off).
> Why it matters: **tunables are gathered at the top and each is annotated**, so you can see at a glance what this rule can tune and how — you do not have to read the whole body when adjusting a rule's behavior, and delivery and review are faster.

---

## 2. Authoring Conventions

| Convention | Description |
|:---|:---|
| **Header block is mandatory** | Rule name / filtering stage / threat level / rule description |
| **Parameters grouped up front** | Thresholds, time window, ban duration and switches are gathered at the top as local variables, **each annotated** |
| **Sectioned skeleton** | `-- <--- Configuration parameters --->` / `-- <--- Utility functions --->` / `-- <--- Main logic --->` |
| **Self-explanatory naming** | Variable names carry units and semantics (`banDuration` rather than `t`); booleans use `enable*` / `is*` / `count*` |
| **No parameters in the description** | The rule description gives the functional overview (e.g. "block access from this ip for 10 minutes after more than 10 cumulative attacks"), so it stays accurate when thresholds change |
| **Restrained commenting** | Necessary explanations go at the top and in the parameter section; keep comments in the body sparse |
| **Phase awareness** | The request phase only has request variables; `waf.status` exists only in the response header phase; `waf.respBody` only in the response body phase |
| **nil safety** | Guard with `(waf.host or "")`, `(waf.uri or "")` |
| **`waf.ipBlock` — write with care** | Not marked read-only officially, but built-in rule 13 uses a "read-only + renew" pattern (the value passed to `set` comes from `get`); **a rule calling `incr` itself double-counts against the engine's block writes**. Prefer `waf.ipCache` for state storage |
| **No `ngx` in rules** | Rules run in a **restricted sandbox** (the global-name allowlist has been measured; `ngx` is not on it) → using `ngx` raises an error outright, and `require` is unavailable too. If you need `ngx`, write a plugin (see `internals.md` §5-2) |
| **Local aliases** | `local rgx, kv = waf.rgxMatch, waf.kvFilter` at the top — avoids a table lookup on every request (an idiom used by the built-ins) |
| **Cheapest predicate first** | Use `startWith` / `contains` / header-field emptiness checks to bail out early before entering regex or the semantic engine |
| **Sweep the whole input surface** | `form["FORM"]`(+`valOnly`) → `form["FILES"]`(`knFilter`) → `queryString` → `cookies` → `reqHeaders` → `uri` → `referer`/`userAgent`; miss one surface and it is a bypass channel |
| **Multiple decoding** | Match after `htmlEntityDecode` / `urlDecode` / `base64Decode` (standard practice in the built-ins) |
| **Semantic engine first** | `checkSQLI` / `checkRCE` / `checkXSS` / `checkPT` — **do not hand-roll regexes for semantic detection**; signature regexes only cover the specific families the semantic engine misses |
| **Malformed means block** | `hErr` / `qErr` / `cErr` / `fErr` anything other than `unknown` is judged a malicious construction |
| **Type defense** | `waf.reqHeaders.cookie` may be a table (multiple Cookie headers) — test with `type()` and use `table.concat` before use |
| **Regex must be validated first** | See "§2-2, Regex: Engine, Options and Validation"; use PCRE syntax and the `"jos"` options |
| **A character class containing `.` needs an extra `..` check** | `[A-Za-z0-9._:-]+` can match `..`, so you must add `not waf.contains(uri, "..")` |
| **Self-check before delivery** | Syntax validation + regex validation + should-block/should-pass samples (see "§5, Rule Output Specification") |

---

## 2-2. Regex: Engine, Options and Validation

### The engine is PCRE (PCRE1 8.45 + JIT)

Measured against the `sbin/uuwaf` binary:

| Evidence | Conclusion |
|:---|:---|
| Version string **`8.45 2021-06-15`** | **PCRE1 8.45** (not PCRE2, not RE2) |
| Symbols `pcre_exec` / `pcre_compile` / `pcre_study` / `pcre_fullinfo` present | Dynamically linked against **PCRE1** |
| **`pcre_jit_exec` present** | **JIT enabled** |
| `pcre2_compile_8` appears **0 times** | **Not PCRE2** |
| Container `lib64/libpcre.so.1.2.10`, `grep -P` depends on `libpcre.so.1` | Same library at runtime |

The official documentation for `waf.rgxMatch` / `rgxGmatch` / `rgxSub` / `rgxGsub` says **"usage is the same as `ngx.re.*`"**, therefore **the syntax = PCRE1 8.45**.

**Supported by PCRE but not by Lua pattern strings** (the key difference when authoring rules):

- Character classes, quantifiers, groups, anchors, and escapes such as `\d\w\s\b`
- Lookahead/lookbehind `(?=)` `(?<=)`
- Non-greedy `*?` `+?`
- Named groups `(?<name>…)`
- Verbs `(*FAIL)` `(*SKIP)`

**How PCRE1 8.45 relates to PCRE2** (measured; running `pcrecheck.py engine` on a WAF host re-checks each item with the PCRE1 inside the container):

- ✅ **Supported by both** (safe to use): character classes, quantifiers, groups, anchors, `\d\w\s\b`, lookahead/lookbehind (**fixed length**), non-greedy `*?`, named groups `(?<n>…)`, subroutines `(?&n)` / `(?(DEFINE)…)`, conditional groups, **`\K` lookaround reset**, **branch reset `(?|…)`**, possessive quantifiers, `(*SKIP)(*F)`, `\p{…}`.
- ❌ **Legal only in PCRE2, rejected by PCRE1 8.45** (avoid when authoring rules):
  - **Variable-length lookbehind** `(?<=a{1,3})` `(?<=ab+)` — PCRE1 requires lookbehind to be **fixed length** (it reports `lookbehind assertion is not fixed length`).
  - **Bare whole-pattern recursion** `(?R)` — PCRE1 reports `recursive call could loop indefinitely`.

### Options: use `"jos"`

| Option | Meaning | Recommendation |
|:---|:---|:---|
| `j` | JIT compilation | ✅ Always on (the engine ships with JIT) |
| `o` | Compile once and cache | ✅ Always on (rules are reused within the same worker) |
| `s` | Single-line mode (`.` matches newlines) | ✅ Recommended (required when matching `\r\n` injection-style payloads) |
| `i` | Case-insensitive | As needed |
| `u` | UTF-8 mode | Consider it when the content contains multibyte characters and uses `.`/character classes |
| `m` | Multiline | As needed |

### Validation is mandatory (**two channels, pick one per environment**)

**The test is simple: is this machine a WAF host (does it have a UUWAF container)?**

| Scenario | Which one | Why |
|:---|:---|:---|
| The agent and the WAF are on **different machines** (**the normal case**) | `scripts/pcrecheck.py` | ctypes binds the system PCRE2; no container needed, it runs on any machine with Python3 |
| This machine **is** the WAF host | `scripts/wafcheck.sh` | PCRE1 inside the container, **linked against the same library** as the runtime — the highest fidelity |
| You need **authoritative Lua syntax validation** | Only on a WAF host, via `wafcheck.sh lua` (luajit) | The Python standard library has no Lua parser |

> **When you have neither a WAF container nor lua/luajit installed** (very common): `pcrecheck.py lua` is only a heuristic smoke test. Pick one of three, in order of preference:
> ① have the WAF host validate for you (`wafcheck.sh lua`, authoritative); ② install a luajit on the host machine (`apt install luajit` / your package manager, same Lua 5.1 syntax) and self-check;
> ③ if neither is available, you **must state "no authoritative Lua syntax validation was performed" in the delivery notes** — never quietly treat it as passing.

> 🔴 **Do not validate with Python's `re` module or `grep -E`**: they are not PCRE — `\d`, variable-length lookbehind, possessive quantifiers, `(?(DEFINE))` and the like all behave differently, and they will hand you the false conclusion "everything passes".
> 🔴 **Do not use the return value of `grep -P` as the sole evidence and skip the samples**: the host's `grep -P` may be linked against PCRE2, which is not the same library as the PCRE1 at runtime.
> ℹ️ **Differences between PCRE2 and PCRE1**: `pcrecheck.py` is PCRE2, the WAF runtime is PCRE1 8.45. **Measured**: both consistently support `\K`, branch reset `(?|…)`, subroutines `(?&n)`, `(?(DEFINE)…)`, possessive quantifiers, `(*SKIP)(*F)`, `\p{…}`. **There are only two real differences**: **variable-length lookbehind** (`(?<=a{1,3})`) and **bare recursion** (`(?R)`) — legal in PCRE2, rejected by PCRE1, so avoid them when authoring rules. When this machine is itself a WAF host, `pcrecheck.py engine` re-checks each item against the PCRE1 inside the container (it does not rely on a static list).

**① Standalone `pcrecheck.py` (the default choice)**

```bash
python3 <skill-dir>/scripts/pcrecheck.py engine                      # self-check: PCRE version/JIT/capabilities
python3 <skill-dir>/scripts/pcrecheck.py regex '<regex>' '<should-match>' '<should-not-match>'
python3 <skill-dir>/scripts/pcrecheck.py cases '<regex>' <test-subject-file>  # batch by line, skips blank lines and # comments
python3 <skill-dir>/scripts/pcrecheck.py extract <rule-file>          # extract every regex and validate each (alias: file)
python3 <skill-dir>/scripts/pcrecheck.py lua <rule-file>              # heuristic smoke test (not authoritative)

# Common options
-o OPTS              option letters, aligned with `"jos"`, default "s": s=i=m=u=x=j=o= (j/o have no side effects during validation)
--pattern-file F     read the regex from a file (avoids shell escaping)
--subject-file F     read the test subject from a file (the whole file is one test subject)
```

> Regexes and samples are always passed in through **files/arguments**, never spliced into a shell string — patterns and samples containing backslashes, `$( )` or quotes survive intact and are not executed by command substitution.
> The `extract` extractor is stronger than the awk version: it **supports `rgx*()` calls spanning lines**, **supports `[=[ ]=]` leveled long strings**, and **correctly skips comments** (it does not mistake a fake call inside a comment for a regex).

**② Container-based `wafcheck.sh` (WAF host only)**

```bash
bash <skill-dir>/scripts/wafcheck.sh engine
bash <skill-dir>/scripts/wafcheck.sh regex '<regex>' '<should-match>' '<should-not-match>'
bash <skill-dir>/scripts/wafcheck.sh cases '<regex>' <test-subject-file>
bash <skill-dir>/scripts/wafcheck.sh lua   <rule-file>    # authoritative Lua validation → SYNTAX_OK
bash <skill-dir>/scripts/wafcheck.sh file  <rule-file>    # Lua + regex (awk extractor)
```

The script locates the WAF container automatically (image name containing `uusec/waf`, or `/uuwaf/sbin/uuwaf` present inside the container); you can also specify it with `WAF_CONTAINER=<name>` or `--container <name>`.

**③ Minimal manual command (for a quick eyeball check only, never as delivery validation)**

```bash
# syntax: exit code 0=match / 1=no match / 2=invalid regex (the reason is printed to stderr)
docker exec <waf-container> sh -c 'printf "%s" "<test-subject>" | grep -qP "<regex>"'
```

> ⚠️ This command splices the regex and the test subject into a shell string — **backslashes, `$` and quotes get mangled, or even executed by the shell**. **Delivery validation must use the two scripts above.**
> Measured: `grep -qP "abc("` → **exit 2** (invalid).
> Measured inside the container: `grep (GNU grep) 3.1` dynamically linked against `libpcre.so.1 → libpcre.so.1.2.10` (PCRE1), `LuaJIT 2.1`.

**④ Validate Lua syntax and string escaping together**

Authoritative Lua validation exists only in the container version (`wafcheck.sh lua`, which goes through luajit):

```bash
docker exec -i <waf-container> sh -c 'cat > /tmp/rule.lua' < <rule-file>
docker exec <waf-container> sh -c '/uuwaf/luajit/bin/luajit -e \
  "local f,e=loadfile(\"/tmp/rule.lua\"); print(f and \"SYNTAX_OK\" or (\"ERR: \"..tostring(e)))"'
```

> ⚠️ Measured: inside a Lua short string, `"\d"` reports `invalid escape sequence` — **a `\d` in a regex must be written as `\\d` inside `"…"`**; with a `[[ ]]` long string it is **preserved as-is** (`[[\d]]` is just `\d`). This is the pitfall hit most often when authoring rules that contain regexes.
> Without a container, use `pcrecheck.py extract`: it **unescapes short strings according to Lua semantics** (`\\-` → `\-`) before validating, distinguishes short from long strings, and correctly skips comments.

### Deliver after validation

**Any rule/plugin containing a regex must pass validation before delivery**, together with:
- Samples that should match (≥2)
- Samples that should not match (≥2, including boundary cases and bypass attempts)

> Measured example: `^/file/[A-Za-z0-9._:-]+$` matches `/file/..` (because the character class contains `.`) → proof that "a character class containing `.` must have an extra `..` check".
> Measured example: a prefix match like `^/api/v1/` **also matches `/api/v1/../../etc/passwd`** → proof that the prefix form is unsafe.

---

## 2-3. Semantic Self-Check: rulecheck.py (covering the blind spots of syntax/regex)

Passing Lua syntax and having valid regexes **does not mean the rule works**. The following mistakes can only be caught at the semantic layer:

| Mistake | Example | Runtime symptom |
|:---|:---|:---|
| Non-existent API | `waf.getHeader(...)`, `waf.checkSQLI2(...)` | Runtime error, rule stops working |
| Misspelled constant | `waf.RULE_BLOK` | Condition always false / always true |
| Phase mismatch | Using `waf.status`, `waf.respBody` in the request phase | You never get a value (the panel disables them too) |
| Misusing plugin capabilities in a rule | `waf.msg`, `waf.ctx`, `ngx.*`, `require(...)` | Error — the rule sandbox has no `ngx`/`require`, and `msg`/`ctx` exist only in plugins |
| Wrong plugin hook | `_M.req_filter` (the old name before v4.1.0) | The plugin **silently does not run** |
| Requiring a module that does not exist | `require("resty.redis")` | Plugin raises a runtime error (see the list in `plugin-authoring.md` §10) |

```bash
python3 <skill-dir>/scripts/rulecheck.py all <file> [--phase 0|1|2] [--plugin]
python3 <skill-dir>/scripts/rulecheck.py dsl '<content JSON>'        # DSL(type=0) structure (including regex validity)
python3 <skill-dir>/scripts/rulecheck.py symbols                     # after a version upgrade: is the symbol table in sync with the official docs
bash    <skill-dir>/scripts/wafcheck.sh semantics <file>             # the same entry point on a WAF host
```

`all` **also runs the Lua syntax and regex checks** (it uses the authoritative channel when a WAF container or a local luajit is available, otherwise it honestly reports "no authoritative validation performed") —
so **one command ≈ the three-piece set**; `--no-lua` / `--no-regex` turn the individual parts off.

- When `--phase` is omitted it is **auto-detected from the `Filtering stage:` header comment**; if it cannot tell, it says so (most official built-in rules have no header comment, which is normal).
- Exit codes: `0` = pass (including warnings only) / `1` = errors present / `2` = usage error.
- It only covers **names and phases**: whether it compiles still requires `wafcheck.sh lua`, and regexes still require `pcrecheck.py`. **Only running all three counts as a complete validation.**

---

## 3. Phases and Available Variables

| Phase (`phase`) | Available variables |
|:---|:---|
| **Request phase** (0) | `waf.ip` `waf.scheme` `waf.httpVersion` `waf.host` `waf.uri` `waf.method` `waf.reqUri` `waf.userAgent` `waf.referer` `waf.reqContentType` `waf.XFF` `waf.origin` `waf.reqHeaders` `waf.hErr` `waf.isQueryString` `waf.reqContentLength` `waf.queryString` `waf.qErr` `waf.form` `waf.form["RAW"]` `waf.form["FORM"]` `waf.form["FILES"]` `waf.fErr` `waf.cookies` `waf.cErr` `waf.requestLine` `waf.ipBlock` `waf.ipCache` |
| **Response HTTP header phase** (1) | the above + `waf.status` `waf.respHeaders` `waf.respContentLength` `waf.respContentType` |
| **Response body phase** (2) | the above + `waf.respBody` `waf.replaceFilter` |

**Hard constraint of the panel (front-end logic, measured)**: **in the request phase, `waf.status` and the parameters related to response headers / response content are disabled**; they are only enabled once you switch to the response header or response body phase.
(Front-end behavior: `phase===0` disables parameters 13–17; `phase===1` enables 13–16 and still disables parameter 17; `phase===2` enables all of them.)

> Mapped to variables: **the request phase cannot get `waf.status`, `waf.respHeaders` or `waf.respBody`**.
> **Counting by response status (e.g. 404 brute-force protection) must use the response HTTP header phase** — this is exactly why built-in rule 70 sits at `phase=1`.

Key details:

- `waf.uri` is the **decoded, parameter-free** URI → `==` equality and anchored regexes are not disturbed by the query string.
- `waf.reqUri` is the **raw URI, including parameters**.
- `waf.isQueryString` is a **bool** (whether request parameters exist), `waf.queryString` is a **table**.
- `waf.form["FILES"]` structure: `{name={[1]="filename",[2]="file content"}}`; `waf.form["FORM"]` structure: `{uid="12", vid={[1]="select",[2]="a from b"}}`.
- In the response header phase, `waf.status` is an integer.
- To modify content in the response body phase you must **both** assign `waf.respBody = newstr` and set `waf.replaceFilter = true`; and it only works when `respContentType` is text/html, text/plain, json or xml.

---

## 3-2. Visual Rules (DSL)

Besides Lua rules, the panel also provides a **visual rule builder**; the rules it produces have `type=0` and a JSON `content`. **Not covered by the official docs**; the structures below are taken from the panel front-end implementation (v7.2.5 — that is, the very code that serializes this JSON).

### Data format

```js
// the panel's actual serialization logic (RuleMgr)
e = []                       // collect conditions
for each condition: e[i] = [key, op, val]
if (#e > 1) then table.insert(e, 1, dslLogic) end     // multiple conditions: the logic operator is inserted at index 1
content = JSON.stringify([dsl_action, e])
```

| Position | Meaning | **Stored value** |
|:---|:---|:---|
| `[0]` | Action `dsl_action` | **`1`** block / **`2`** allow / **`3`** log only |
| `[1][0]` | Logic `dsl_logic` (**present only with multiple conditions**) | **`"&"`** AND / **`"\|"`** OR / **`"~&"`** NAND / **`"~\|"`** NOR |
| `[1][i]` | Condition | `[ key, op, val ]` triple |

**Examples**:

```json
[1, [["uri", "*", "/.env"]]]
[1, ["&", ["ip", "=", "203.0.113.9"], ["uri", "*", "/.env"]]]
[2, ["|", ["uri", "^", "/static/"], ["uri", "^", "/assets/"]]]
```

🔴 **Two pitfalls hit frequently**:

1. **What is stored is numbers and symbols, not English names**. The panel i18n contains display-only keys such as `include` / `ipMatch` / `startsWith` / `block`, and they are **not the stored values** — writing JSON based on the i18n produces invalid rules.
2. **Negation = the prefix `~`** (`~*` `~.` `~-` `~=`); logical NAND/NOR are `"~&"` / `"~\|"`.

**The complete value tables for parameters (key) and operators (op) are in `management-api.md` §3.2** (all request-side and response-side fields, plus the operator symbol table).

### Panel built-in validation (copying its logic = the officially sanctioned self-check standard)

```js
// the operator ends with "." (i.e. regex / notRegex) → validate whether the regex is legal
if (op.endsWith("."))   { try { new RegExp(val, "") } catch(e) { report an error and abort } }
// the operator is > or < → the value must be a number
else if (op === ">" || op === "<") {
    if (!/^[+-]?\d+(\.\d+)?$/.test(val)) { report the error "The value must be number" }
}
```

> **Key point**: the panel validates with the JS `RegExp`, while **the runtime is PCRE**. The two are highly compatible but not fully equivalent — when you use syntax where they differ (variable-length lookbehind, bare recursion), validate once more with the check scripts (`pcrecheck.py regex`; on a WAF host you can use `wafcheck.sh regex` to go through PCRE1).
> The panel dynamically disables response-side parameters according to `phase`: **the request phase disables `status` / `resp*`**, and they are only enabled once you switch to the response header or response body phase.

### When to use the DSL and when to use Lua

| Scenario | Choice |
|:---|:---|
| Simple combinations of IP / path / header conditions | **DSL** (no code to write, maintained visually in the panel) |
| Counting, rate, shared memory, multi-step decisions, response rewriting | **Lua** |

> The two coexist in the same rule library and follow the same ID allocation rules.

---

## 4. Pattern Library

Each pattern is marked with **whether it comes from an official built-in rule** (built-in rules are the most reliable reference for style).

### 4.1 CC / rate protection (in the style of official built-in rule 66)

```lua
if not waf.startWith(waf.toLower(waf.uri), "/api/") then
    return false
end

-- exclude real search engines so that indexing is not affected
local se, ok = waf.searchEngineValid({"180.76.76.76"}, waf.ip, waf.userAgent)
if se and ok then
    return false
end

local sh = waf.ipCache
local ccIp = 'cc-' .. waf.ip
local c, f = sh:get(ccIp)
if not c then
    sh:set(ccIp, 1, 60, 1)                 -- 60-second counting window, flag=1 means counting
else
    if f == 2 then
        return waf.block(true)             -- banned: reset TCP (no log entry)
    end
    sh:incr(ccIp, 1)
    if c + 1 >= 100 then
        sh:set(ccIp, c + 1, 300, 2)        -- ban for 300 seconds, flag=2 means banned
        return waf.RULE_BLOCK, ccIp
    end
end
return false
```

Key point: `get` returns `value, flag`; the 4th argument of `set(key, value, exptime, flag)` is a **custom state flag**.

> `flag` is a **convention** in the official examples (the official docs do not define its value range): `1` / `2` distinguish the two states "counting" and "already banned/being verified", so that a single key can carry the dual semantics of "counter + state".
> The official anti-cc example annotates them the same way: `-- 设置1分钟也就是60秒访问计数时间` / `-- 设置5分钟也就是300秒拦截时间`.

### 4.2 Bot-attack protection (in the style of official built-in rule 68)

Structurally the same as 4.1, except that **crossing the threshold starts human verification** rather than returning a block directly:

```lua
local sh = waf.ipCache
local robotIp = 'rb:' .. waf.ip
local c, f = sh:get(robotIp)

if not c then
    sh:set(robotIp, 1, 60, 1)            -- 60-second counting window, flag=1 means counting
else
    if f == 2 then
        return waf.checkRobot(waf)       -- already in verification state: show the slide-to-rotate captcha
    end
    sh:incr(robotIp, 1)
    if c + 1 >= 360 then
        sh:set(robotIp, c + 1, 1800, 2)  -- enter verification state, 30-minute verification window
        return waf.RULE_BLOCK, robotIp   -- crossing the threshold for the first time still returns a block
    end
end
return false
```

> **Note the two distinct branches**:
> - **First crossing of the threshold** → `sh:set(..., 2)` sets the verification state + **returns `RULE_BLOCK`**;
> - **From then on, when `flag == 2`** → only then does it call `waf.checkRobot(waf)` and show the captcha.
>
> So it is "block once first, then switch to requiring verification", not "start the captcha right away".

- `waf.checkRobot(waf, expireTime?, max?)`: by default re-verifies after 600 seconds / 18000 times.
- `waf.checkTurnstile(waf, siteKey, secret, expireTime?, max?)`: uses Cloudflare Turnstile.
- 🔴 When using human verification you **must also allow `/static/` and `/api/v1/captcha/`**, otherwise the CSS/JS of the verification page is blocked and the page cannot render.

### 4.3 Response-status protection (official built-in rule 70, response HTTP header phase)

```lua
local sh = waf.ipCache
local ccIp = '404-' .. waf.ip
local c, f = sh:get(ccIp)
if f == 2 then
    return waf.block(true)
end
if waf.status ~= 404 then
    return false
end
if not c then
    sh:set(ccIp, 1, 60, 1)
else
    sh:incr(ccIp, 1)
    if c + 1 >= 10 then
        sh:set(ccIp, c + 1, 300, 2)
        return waf.RULE_BLOCK, ccIp
    end
end
return false
```

> **To count failures by response status you must use the response HTTP header phase + `waf.status`**. "Counting by request count" in the request phase is only approximate protection.

### 4.4 Reading "the attack count of a blocked IP" (official built-in rule 13, `waf.ipBlock` usage)

```lua
local ib = waf.ipBlock
local c = ib:get(waf.ip)
if c and c >= 10 then
    ib:set(waf.ip, c, 600, 1)          -- 3rd arg 600 = TTL, renew for 10 minutes, the count is not changed
    return waf.RULE_BLOCK, "ip blocked for continue attack: " .. waf.ip
end
return false
```

> `waf.ipBlock` is the record of **"blocked IPs"**: key = IP, value = **cumulative block count**. **It is written automatically by the WAF engine when a rule blocks** (a plugin blocking does **not** write it automatically; you must call `ngx_kv.ipBlock:incr(waf.ip, 1, 0, 600)` yourself).
> Its purpose is precisely **judging how many attacks an IP has made** — that is exactly what official built-in rule 13 "high-frequency attack protection" does; you can also read it in your own rules for tiered handling.
> 🔴 **TTL = 600 seconds (10 minutes)**: `ib:set(waf.ip, c, 600, 1)` in rule 13 **resets the TTL to 10 minutes** (it does not increment the count). **Once blocks stop being triggered the count clears naturally** and the ban lifts by itself — the official description is "after more than 10 cumulative attacks, block that ip for **10 minutes**".
> 🔴 The rule side is **read-only**: you may `get` and do a TTL-renewing `set`, but you **must not overwrite the count**; use `waf.ipCache` for state storage.
> 🔴 Rules that depend on `waf.ipBlock` **have requirements on their ID position** (see `internals.md` §2).

### 4.5 Uploaded-file detection (`waf.knFilter`)

```lua
local function fileContentMatch(v)
    local m = waf.rgxMatch(v, "<\\?php|<jsp:|<%(?i:!|\\s*@)", "jos")
    if m then
        return m, v
    end
    return false
end
if waf.form then
    local m, d = waf.knFilter(waf.form["FILES"], fileContentMatch, 0)   -- p=0 matches file content, p=1 matches the file name
    if m then return waf.RULE_BLOCK, d end
end
```

### 4.6 Key-value detection (`waf.kvFilter` / `waf.jsonFilter`)

```lua
local function rceMatch(v)
    if waf.checkRCE(v) then
        return true, v
    end
    return false
end

-- match key-value pairs such as queryString / cookies (valOnly=true matches only the value)
local m, d = waf.kvFilter(waf.queryString, rceMatch, true)

-- walk the JSON body (parsed=false means v is a string)
local m, d = waf.jsonFilter(waf.form["RAW"], rceMatch, false, true)
```

### 4.7 Allowlist (⚠️ high risk, keep it narrow)

> **The cost, stressed once more**: after it matches, **no subsequent rule and no ML validation runs** (plugin hooks in the response header phase are skipped as well; the exact list is in `internals.md` §3-3) — the allowed scope must be narrow enough that "even with no further inspection it is still safe".

> **Precondition for it to work**: rules execute in ascending ID order, so the semantics of "match and skip all subsequent rules" **only hold when the ID is smaller than every blocking rule**. To put a custom rule at the very front, use the officially reserved **ID 9** (seed-data description: "left spare, for the highest-priority custom rule") — that slot is not restricted to any one purpose; allowing is merely one of its uses.

```lua
if waf.host == "app.example.com"
   and waf.method == "POST"
   and (waf.uri or "") == "/api/v1/task/submit"           -- exact match preferred
   and not waf.contains((waf.uri or ""), "..")            -- prevent path traversal
   and waf.reqContentType
   and waf.startWith(waf.toLower(waf.reqContentType), "application/json")
then
    return waf.RULE_ALLOW, "allowed: <business description> (<false-positive root cause>)"
end
```

**Allowlist entry self-check table** (must be verified item by item when delivering an allowlist):

| Case | Expectation |
|:---|:---|
| Same path, changed User-Agent | Not allowed |
| Same path, changed method | Not allowed |
| Same path, suffix `/x` added | Not allowed |
| Same path, `../` inserted | Not allowed |
| Same path, content-type changed | Not allowed |
| Different host, same path | Not allowed |

### 4.8 Data masking (response body phase)

```lua
if waf.respContentLength == 0 or waf.respContentLength >= 2097152 then
    return
end

local newstr, n, err = waf.rgxGsub(waf.respBody, [[\b1[3-9]\d{9}\b]], function(m)
    return m[0]:sub(1, 3) .. "****" .. m[0]:sub(-4)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
if n > 0 then
    waf.respBody = newstr
    waf.replaceFilter = true          -- tell UUWAF to perform the replacement
end
```

> **Data masking is a commercial-edition capability** (not available in the community edition). But **the mechanism of modifying `respBody` inside a rule is itself generic** — this snippet demonstrates the combined use of `waf.rgxGsub` + `waf.respBody` + `waf.replaceFilter`, which applies to sensitive-word replacement, URL rewriting and any other response-content rewriting scenario.
> Large response bodies are short-circuited first by `respContentLength`, to avoid pointless overhead.

### 4.9 Region-based access control

```lua
local country, province, city, iso = waf.ip2loc(waf.ip, "zh-CN")
if country == "中国" then
    return false
end
return waf.RULE_BLOCK, "region restriction"
```

### 4.10 Official built-in idioms (distilled from the 50 built-in rules, directly reusable)

| Idiom | Form | Why |
|:---|:---|:---|
| **Local aliases** | `local rgx, kv = waf.rgxMatch, waf.kvFilter` | Avoids repeating the table lookup on every request |
| **Cheapest predicate first** | `if not waf.startWith(waf.toLower(waf.uri), "/api/") then return false end` | Zero-cost early exit for non-target traffic |
| **Length / header-field short-circuit** | `if waf.reqHeaders.next_action == nil then return false end`; `if waf.reqContentLength >= 131072 then …` | Rules out most requests without parsing the body |
| **Sweep the whole input surface** | FORM → FILES → queryString → cookies → reqHeaders → uri → requestLine → referer → userAgent | Miss one surface and it is a bypass channel |
| **Multiple decoding** | Match after `htmlEntityDecode` / `urlDecode` / `base64Decode` | Counteracts encoding-based bypasses |
| **Semantic engine + signature complement** | `checkXSS(v) or rgx(v, "<narrow signature family>", "jos")` | The semantic engine has broad coverage; a narrow regex fills in a specific family |
| **Semantic level varies by input surface** | The built-ins use different levels per surface (SQLi rule: form/query/cookie=3, request headers=default; command-injection rule: form=1, query=2, cookie=0, request headers=1) | **There is no single standard**: the higher the level, the stricter and the more false positives; when unsure, copy the corresponding built-in rule |
| **Malformed means block** | Block outright when `hErr` / `qErr` / `cErr` / `fErr` is not `unknown` | A parse failure is usually a malicious construction |
| **Type defense** | `waf.reqHeaders.cookie` may be a table → test with `type()` first, then `table.concat` | Measured: this branch exists in official rule 72 |
| **Evidence into the log** | `return waf.RULE_BLOCK, <matched value or RAW>` | The only clue for later forensics and for converging false positives |
| **Disconnect during a ban** | `return waf.block(true)` | A second match resets TCP directly, saving bandwidth |

> ⚠️ **Do not copy the style of the built-in samples blindly**: the official built-ins contain non-standard returns (e.g. rule 65 returns `true, RAW, false` instead of the `waf.RULE_BLOCK` constant). **Always use the three constants as return values, and follow this template's structure.**

### 4.11 Detection primitives and matching APIs quick reference (selection table)

| Need | Use | Description |
|:---|:---|:---|
| SQL injection | `waf.checkSQLI(str[, level])` | Semantic engine; `level` 0~3, the higher the stricter |
| Command injection | `waf.checkRCE(str[, level])` | Same as above |
| XSS | `waf.checkXSS(str)` | Same as above |
| Path traversal | `waf.checkPT(str)` | Same as above |
| Built-in signature modules | `waf.plugins.<module>.check()` | **Takes no arguments**; returns `true, evidence` / `false, nil`; modules: `scannerDetection` / `fileLeakDetection` / `weakPwdDetection` / `sqlErrorDetection` / `phpErrorDetection` / `javaErrorDetection` / `javaClassDetection`; **not covered by the official docs, but the built-in rules themselves use them** (module list in `pitfalls.md` §7) |
| Fast multi-string matching | `waf.pmMatch(sstr, {"a","b","c"})` | Multi-pattern matching, returns on the first hit; better than `for` + `inArray` |
| Simple contains / prefix-suffix | `waf.contains` / `startWith` / `endWith` | The cheapest; prefer these |
| Regex | `waf.rgxMatch` / `rgxGmatch` / `rgxSub` / `rgxGsub` | Avoid if you can; always carry `"jo"` |
| Encode/decode | `base64Decode` / `urlDecode` / `htmlEntityDecode` / `hexDecode` | Decode before matching |
| Key-value / upload / JSON walking | `kvFilter` / `knFilter` / `jsonFilter` | See §4.5, §4.6 |
| Geolocation | `waf.ip2loc(ip[, lang])` | Returns `country, province, city, iso_code` |
| Root domain | `waf.getRootDomain(host)` | **Not covered by the official docs**; used by the built-in RFI rule; mind the version dependency when using it |
| Redirect / human verification / block | `waf.redirect(uri[, status])` / `checkRobot` / `checkTurnstile` / `waf.block(reset)` | All are **used together with `return`** |

> The full signatures, parameters and return values are authoritative in `offline-docs/api.zh-CN.md` (official text); this table is only for selection.

> ⚠️ **The engine has 6 more names that the official docs do not cover** (read from the string table of `sbin/uuwaf`, v7.2.5):
>
> | Name | What it is | Safe to use? |
> |:---|:---|:---|
> | `waf.getRootDomain(host)` | Gets the **root domain** of that host (used to judge whether a redirect target belongs to your own domains) | Used by the built-in RFI rule |
> | `waf.plugins.<module>.check()` | Calls an engine built-in detection module (see the previous row of this section) | Used by the built-in rules |
> | `waf.jsonDecode(str)` | JSON parsing (a `util` module function, based on `cjson.safe`, returns `value[, err]` without raising) | Not covered by the official docs, not used by the built-ins |
> | `waf.checkJson(v)` | **JSON attack semantic detection** (parallel to `checkSQLI`/`checkXSS`/`checkPT`/`checkRCE`) | Same as above |
> | `waf.split(str, sep)` | String splitting (a `util` utility function, in the same group as `trim`/`inArray`) | Same as above |
> | `waf.respContentEncoding` | The `Content-Encoding` (gzip etc.) state in the response phase | Same as above |
>
> ⚠️ This group is internal implementation and may change at any version — test it on the target instance first if you want to use it, and **never write it into delivered rules**; the APIs covered by the official docs are enough for ordinary needs.
>
> **Two mechanical facts** (which explain why this table's advice is correct):
> - `checkSQLI` is backed by **`resty.libinjection`** (wrapped as `purify_sql` in the engine) → tokenization + a fingerprint-style semantic engine, which is why a higher `level` is stricter and produces more false positives.
> - `pmMatch` is backed by **`ahocorasick`** (the Aho-Corasick C extension `libac.so`) → multi-pattern matching in a single scan, which is why you should not compare strings one by one with `for` + `inArray`.
>
> See `internals.md` §3-3 for how to re-verify this.

---

## 5. Rule Output Specification

When the user asks you to write a rule, output in the following structure:

1. **Requirement analysis** → decide between a basic rule, an advanced rule or a plugin
2. **Approach summary** → what to block, how to block it, the applicable scope
3. **Threat model** → attack type, key characteristics, bypass methods
4. **Rule code** → ready to copy (configuration parameters up front, sectioned skeleton)
5. **Test samples** → should-block + should-pass + boundaries (**including bypass attempts**)
6. **False-positive analysis** → business scenarios that may be wrongly blocked
7. **Deployment advice** → ID/ordering, canary (`RULE_LOG_ONLY` observation), rollback method
8. **Validation results** → **the syntax and regex validation output you actually ran** (not "it should be fine")

### 🔴 Validation before delivery is mandatory (hard requirement)

**An unvalidated rule/plugin must not be delivered**. At minimum you must complete:

| Validation | Command | Pass criterion |
|:---|:---|:---|
| Lua syntax | WAF host: `wafcheck.sh lua <file>` (authoritative) / other machine: `pcrecheck.py lua <file>` (heuristic) | `SYNTAX_OK` / `BALANCED(heuristic)` |
| Every regex | `pcrecheck.py regex` (PCRE2) or `wafcheck.sh regex` (PCRE1, WAF host) | Exit code 0/1 (**2 = invalid regex, must be fixed**) |
| Should-block samples | `pcrecheck.py cases` | All match |
| Should-pass samples | Same as above | None match (including bypass attempts such as `..`, case changes, appended suffixes) |
| **Semantic check** | `rulecheck.py all <file> [--phase N]` | No ❌ items: API/constant/phase/ngx/require/hook |
| **Module check** (plugins) | `rulecheck.py modules <plugin file>` | Every module `require`d is on the measured list |

### Pre-delivery self-check table (things a machine cannot catch — go through them one by one)

| Item | Ask yourself |
|:---|:---|
| Nature of the predicate | Are you writing a **decidable fact** or an **enumeration of symptoms**? If the file name / endpoint / parameter name changes, do you still catch it (enumeration always misses)? |
| Allowed scope | If you use `RULE_ALLOW`: have you constrained host + method + exact path + content-type? Have you added the `..` check? Do you know it skips plugins along with everything else? |
| Bypass samples | `..`, case changes, appended suffixes (`.bak`/`.old`), URL encoding, multiple encoding, null bytes, over-long parameters — have you thought about each of them once? |
| Performance | Is there a `for` loop over a large table (you should use `pmMatch`/`inArray`)? Do the regexes carry `jo`? Is heavy work (parsing a large body) put on every request? |
| Log safety | Will `Authorization` / `Cookie` / passwords be written into `error_log`? |
| Canary | Is the first rollout `RULE_LOG_ONLY`? How do you compare during the observation period (the set blocked by the new rule vs the original rule)? |
| Rollback | Did you back up before changing? If something goes wrong, can you stop the bleeding in five minutes per `operations.md` §7? |

**Include the validation commands, the channel used and the results in the delivery**, so the user can reproduce them.
> Pick one channel per environment: **the agent and the WAF being on different machines is the norm → use `pcrecheck.py` (PCRE2)**; if this machine is the WAF host → use `wafcheck.sh` (PCRE1, same library). When validating with PCRE2, **state it honestly**, and avoid the syntax with **real differences**: variable-length lookbehind `(?<=a{1,3})` and bare recursion `(?R)` (`\K` and `(?|…)` are in fact supported by both). **Do not use Python `re`.**

---

## 6. Rules vs Plugins: Selection Principles

| Option | Applies to | Complexity |
|:---|:---|:---|
| **DSL visual rule** | Simple combinations of IP / path / header conditions | Lowest |
| **Lua advanced rule** | CC protection, semantic detection, rate limiting, response rewriting | Medium |
| **Plugin** | Multi-phase processing, native `ngx` objects, external libraries/network requests, cross-phase shared data, cookie renewal | Highest |

**Key differences**:

| Dimension | Rule | Plugin |
|:---|:---|:---|
| Phase | Request / response header / response body (as a whole) | Each phase is further split into pre / post (10 functions) |
| Relation to the rule chain | **Inside the rule chain**; `RULE_ALLOW` skips subsequent rules and ML validation | **Outside** the rule chain; after an allow, **the whole response header phase is skipped** (hooks included), while the other phases still run |
| Execution order | Ascending rule ID | Descending `priority` (larger runs first) |
| Native `ngx` | Should not be relied on | Legitimate usage |
| Data sharing | Shared memory dict | `waf.ctx` (between phases) + shared memory dict |

> **If an advanced rule can solve it, use an advanced rule** — do not escalate to a plugin. Plugins cost more to develop and maintain.

---

## 7. Troubleshooting Order

When a rule does not take effect, check in this order:

1. **Is the site in observation mode** (`mode`) — in observation mode nothing is blocked.
2. **Is the rule in the ruleset used by that site** — created but not attached to a ruleset = a dead rule.
3. **Is it being pre-empted by a rule with a smaller ID** — especially allowlist-type rules (`RULE_ALLOW` short-circuits the whole chain).
4. **Does the rule's ID position meet the requirement** — post-processing rules that depend on `waf.ipBlock` counting have hard position requirements.
5. **Has the rule been rolled back by the panel** — changes to built-in auto-maintained entries are rolled back (the criterion is the ID range, not `type`/`uid`).
6. **Did the write fail because `waf_nodes` is empty** — it reports `No waf nodes`.
