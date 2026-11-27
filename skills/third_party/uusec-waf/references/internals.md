# Runtime Mechanics and Features

> These contents are **not covered, or are only vaguely described, in the official API documentation**; they come from implementation-level research on running instances (nginx configuration, built-in detection module source, built-in rule Lua source, frontend implementation inside the Go binary) and from empirical testing.
> When writing rules and troubleshooting, you **must read this document first**, otherwise you will write rules that "look correct but do not take effect".

---

## 1. Request Processing Pipeline

```
client
  │
  ├─ 80 / 443  ← nginx listens directly (listen.conf); 443 uses http2
  │
  ▼
ssl_certificate_by_lua_block  → waf.http_ssl_phase()     [SSL phase, plugin ssl_pre/post]
  │
  ▼
rewrite_by_lua_block          → waf.req_filter()         [request phase: rule chain + plugin req_pre/post]
  │
  ▼
upstream waf_backend          → waf.http_balancer_phase() [select backend per site configuration]
  │
  ▼
header_filter_by_lua_block    → waf.resp_header_filter() [response header phase: rules + plugins]
  │
  ▼
body_filter_by_lua_block      → waf.resp_body_filter()   [response page phase: rules + plugins]
  │
  ▼
log_by_lua_block              → waf.http_log_phase()     [log phase: plugin log_pre/post]
```

Key points:

- **The rule chain executes at three positions: `req_filter` / `resp_header_filter` / `resp_body_filter`**, corresponding one-to-one with the "filtering phase" in `rule-authoring.md`.
- **Plugins are outside the rule chain**: plugin hooks **wrap the rule chain in pairs** — `req_pre_filter` (official name: **pre-request-phase filter**) → rule chain → `req_post_filter` (**post-request-phase filter**).
  **Rules have no such notion of "pre-phase / post-phase"**: a rule belongs only to the phase body (`phase` 0/1/2); "pre/post phase" are hook positions unique to plugins, and the rule chain itself is the main flow of that phase.
  (Verifiable: the bytecode address order in `req_filter` = `req_pre_filter` 0325 → rule chain 0391/0570 → `req_post_filter` 0818; the response header / response body phases are isomorphic.)
- 🔴 **But "outside" ≠ "unaffected"**: after a `RULE_ALLOW` hit, the flag `waf_ctx.in_whitelist` is set, and **the degree of impact differs by phase** — see §3.3 for the exact list. Just remember the conclusion: **the response header phase is skipped in its entirety (including that phase's plugin hooks), while the plugin hooks of the request / response page / log phases still execute**.
- **The admin backend is independent**: the console is on `4443`, its configuration is in `/uuwaf/web/conf/config.json` (the `addr` field); it **does not go through the data plane**.
- **The data plane reads the database itself** (it does not rely on the control plane pushing to it): `sbin/uuwaf` contains a set of direct SQL queries — `select \`id\`,\`phase\`,\`type\`,\`content\` from waf_rules`, `select \`id\`,\`content\` from waf_ruleset`, `select \`id\`,\`name\`,\`content\` from waf_plugins where \`enabled\`=1`, plus one each for sites and certificates; the control plane invalidates the cache with `set_purge`. This explains "rule changes take effect within seconds and require no restart".
- **Plugin execution priority**: on the engine side `priority` is sorted with `table.sort` (descending), which works together with the **absence of `order by`** in the `waf_plugins` query (the order is sorted by Lua, not by SQL).
- **Built-in management plane**: it serves on port `4447`, and `waf_nodes` in `config.json` points to it (`["127.0.0.1:4447"]`). This is exactly why **writing rules/plugins requires `waf_nodes` to be non-empty**.

---

## 2. Execution Order: Rules Run in Ascending ID Order

- Rules execute **in ascending rule ID order**, and **once a block is hit, subsequent rules are no longer matched**.
- **The order of the ruleset array does not affect the execution order** (the array only expresses "which ones are enabled", see `management-api.md` §3.3).
- **ID partitioning is a hard convention** (based on the official seed data and CHANGELOG v6.7.0):

| Segment | Ownership |
|:---|:---|
| **`9`** | **Officially reserved slot**. Verbatim official seed SQL (the `INSERT INTO waf_rules` inside the control-plane binary): `(9, 1, 3, 'Custom', 0, 1, 'Reserved for defining custom highest-priority rules', 'return false', ...)` — name `Custom`, description "**reserved for defining custom highest-priority rules**", content merely `return false` (the Chinese shown in the panel is the i18n display of that field) |
| `10 ~ 499` | **Official built-in rules** |
| **`500 ~`** | **Custom rules** (allocated by auto-increment) |

> **The developer's statement** (consistent with the official seed and the official repository): **within the same phase, rules execute in ascending rule ID order**.
>
> **Why we can conclude that "the order is determined by ID" rather than "by the ruleset array"** (four mutually independent reasons):
> 1. **In the official seed, the `content` of the `Default` ruleset is in descending ID order** (`[75,74,73,…,19,…]`, see the same seed SQL). If execution order equaled array order, then ID 9, the "highest-priority reserved slot", would always come last, and there would be no reason for the official project to reserve it deliberately.
> 2. **The upstream community rule comment (see below) explicitly requires swapping position with the first built-in rule**, while custom rule IDs start at 500 — "execute first" cannot possibly be achieved through array position.
> 3. **The panel does not sort when saving a ruleset** (`filter` + `JSON.stringify`, keeping only the checked items) → `content` is merely an "enabled list" and carries no ordering semantics.
> 4. **The engine executes in ascending ID order**; neither the array order inside `content` nor the display order in the panel (on this machine the default set is in descending ID order) determines the execution sequence.
>
> Verbatim official CHANGELOG (v6.7.0): "**Prevent default rules from overriding custom rules; adjust the starting value of the custom rule id range to 500**".
> This is why **custom rules come after all official built-in rules by default**, and therefore **cannot directly play the role of a "front-line master gate"** — unless the **ID 9** slot deliberately left by the official project is used.
>
> ⚠️ **Do not infer "whether this rule is self-built" from the ID value**: ID 9 is the official reserved **highest-priority custom slot**, and any self-built feature may be placed there. The criterion is **content and provenance**, not which segment the ID falls into.

- The official CHANGELOG explicitly states: "**Added the allowlist rule feature; after a successful match, the remaining rules are no longer matched**" — this is the official basis for the `RULE_ALLOW` short-circuit (see the next section).
- Corollary: **for rules that need "front-line master gate" semantics (allow, pre-admission validation, unified blocking, rate limiting…), the ID must be smaller than all blocking-type rule IDs**; the official project reserved **ID 9** for this (see the table above). It is not restricted to any particular use — any function requiring "execute before all built-in rules" goes here, and the concrete implementation is up to the user.

> The verbatim header comment of the upstream community rule `rules/third_party/frequent-block-detection.lua` (author MCQSJ) confirms this:
> "!!! Note: because of UUSEC WAF's characteristics, this rule's taking effect has requirements on the **rule ID**; you need to **swap this rule's position with the first rule** of UUSEC WAF's own rules for it to take effect!!!"
> That is, **post-positioned rules that rely on the cumulative count in `waf.ipBlock`** must land at a position where "the count has already been produced but the block has not yet happened".

> When saving a ruleset the panel **does not sort** (`filter` + `JSON.stringify`, keeping only the checked items), so the order in `content` is the **check history**
> — the official seed's `Default` set is stored in descending ID order. **Do not** infer the execution sequence from the array order or the panel display order.

---

## 3. `RULE_ALLOW` Skips the Entire Rule Chain (the understanding with the highest cost)

Verbatim comment of the allowlist rule:

> "Note: this rule's ID must be smaller than all blocking-type rule IDs, otherwise the allowlist will not work."

Verbatim official CHANGELOG (the v6.x allowlist feature entry):

> "Added the allowlist rule feature; **after a successful match, the remaining rules are no longer matched**"

Only the two sentences together give the complete semantics: **`RULE_ALLOW` does not mean "this one rule does not block", it means "skip all subsequent rules"** — and moreover **it is not only rules that are short-circuited** (the impact on plugins differs by phase, see §3.3).

Compare against the mechanics semantics of `RULE_ALLOW`:

| Item | Conclusion |
|:---|:---|
| Trigger condition | `host` / `method` / `uri` / `content-type`, etc. — these are only **trigger conditions** |
| Scope of effect | **The entire rule chain after the hit** — not the scope bounded by the conditions themselves |
| Also skipped | SQLi / RCE / XSS / webshell / path traversal / sensitive file / RFI detection on the same path, **as well as frequency and CC protection (13 / 66 / 70)** |
| Net effect | Equivalent to opening a **rule vacuum tunnel** for that path |

**Design self-check**: before using `RULE_ALLOW`, ask yourself "what protection is left on this path after the bypass" — the answer is often "none": **neither subsequent rules nor ML validation run anymore**, and only log-type plugins still record.

**Therefore the allow conditions must be as narrow as possible**:

1. **Exact match is preferable to prefix**: `(waf.uri or "") == "/api/v1/task/submit"` is better than `waf.startWith(waf.uri, "/api/v1/")`.
2. **Use anchored regexes `^…$` when the path contains variables**: a prefix form would also match `/upload/<uuid>/../../etc/passwd`.
3. **Multiple locks**: `host` + `method` + path + `content-type` (plus UA or a custom header when necessary).
4. **Add a `..` check**: a regex whose character class contains `.` (such as `[A-Za-z0-9._:-]+`) can match `/a/../b`, so you **must** additionally add `not waf.contains((waf.uri or ""), "..")`.
5. **Do not allow an entire sensitive-file category**: allowing once permanently turns off the alerts for that path (for example, for private-key previews allow only `.pub`, not the whole path).

The official definition of `waf.uri` is **the decoded URI without parameters**, so the `==` equality check and anchored regexes are not disturbed by the query (`?offset=…&token=…` has no effect).

---

## 3.2. Rules vs Plugins: Scope and Available Capabilities (the most easily confused pair of concepts)

| Dimension | Rule | Plugin |
|:---|:---|:---|
| **Scope** | **Site-level**: site → one ruleset → rules; changing the site changes the set | **Global**: a single plugin library applies to all sites; for per-site differentiation, write the site configuration inside the plugin (e.g. `site_auth_config`) |
| **Execution position** | **Inside** the rule chain (`phase` is fixed; a rule runs in only one phase) | **Outside** the rule chain, with 10 hooks in total per phase (pre/post) |
| **Bypassed by an allow?** | Yes — a `RULE_ALLOW` hit skips all subsequent rules and ML validation | **Partly** — the plugin hooks of the response header phase are skipped in their entirety, the other phases still execute (exact list in §3.3) |
| **Available API** | Only `waf.*` | `waf.*` **+ native `ngx`** (`ngx.req` / `ngx.header` / `ngx.exit` / `ngx.shared` …) |
| **`ngx` availability** | ❌ **Do not use**: the official API only provides `waf.*`, 0 of the 50 built-in rules use `ngx`, and it is not guaranteed across versions | ✅ Legitimate usage; all official plugins use it directly |
| **Passing state across phases** | ❌ Impossible (a rule runs in only one phase); use `waf.ipCache` for cross-request state | ✅ `waf.ctx` is shared between pre/post and the phases |
| **`require`** | ❌ Not supported | ✅ Supported (module list in `plugin-authoring.md` §10) |
| **Where to write it** | Panel "Rule Management" (`type=1` Lua / `type=0` DSL) | Panel "Plugin Management" |
| **Gradual rollout means** | `RULE_LOG_ONLY` + ruleset enable/disable | The `enabled` switch + the plugin's internal master switch + `priority` |

> In one sentence: **Rules = site-level, inside the chain, only `waf.*`; plugins = global, outside the chain, able to span phases, may use `ngx`.**
> **Do not treat plugins as "a mandatory layer that the allowlist cannot bypass"** — an allow skips part of the plugin processing (§3.3); to truly enforce something, the only options are **not writing an allow rule**, or adding another layer outside the WAF.

---

## 3.3. What Exactly Is Skipped After a `RULE_ALLOW` Hit (code-level evidence)

Evidence method: `sbin/uuwaf` embeds 12 segments of **LuaJIT bytecode**, and the 17.9 KB segment is the implementation of `waf.req_filter` / `resp_header_filter` / `resp_body_filter` / `http_log_phase`. After exporting it, disassemble with `luajit -bl` inside the container to read the control flow (there are no line numbers; identification relies on string constants and jump targets).

After a `RULE_ALLOW` hit (the same applies to a site `ip_whitelist` / `url_whitelist` hit), the engine marks `waf_ctx.in_whitelist`, and the subsequent behavior **differs by phase**:

| Position | Behavior after an allowlist hit | Disassembly evidence |
|:---|:---|:---|
| Request phase · remaining rules | ❌ Skipped (the rule loop breaks) | After the rule returns `2`, `in_whitelist = true` → break out of the loop |
| Request phase · ML validation | ❌ Skipped | After the loop, `if in_whitelist then goto tail` |
| Request phase · `req_post_filter` | ✅ **Still executes** | That call site executes unconditionally (at the tail) |
| Request phase · `req_pre_filter` | ✅ Has necessarily already executed (before the rule chain) | The call site precedes the rule chain |
| Response header phase `resp_header` | First runs `resp_header_pre_filter` → then ❌ **returns early for the whole block** (**`resp_header_post_filter` is skipped**, and status/header handling is skipped too) | The entry point calls pre first; `if in_whitelist then return` |
| Response page phase `resp_body` | 🔸 Skips body processing such as decompression/replacement, **`resp_body_post_filter` still executes** | `if in_whitelist then goto <post call site>` |
| Log phase `log` | ✅ **Does not check the flag at all** → `log_pre_filter` / `log_post_filter` run as usual | There is no `in_whitelist` reference inside that function |

> **In one sentence**: "after an allow, plugins do not run either" **holds only for the response header phase**; plugins in the request phase and the log phase execute as usual — so **an allow does not cause audit/log loss**, but you **also cannot rely on plugins to make up for detection**.

**Re-verify yourself after changing versions** (the engine logic may change after an upgrade):

```bash
docker exec <container> cat /uuwaf/sbin/uuwaf > /tmp/uuwaf.bin
python3 - <<'P'
import re
d = open('/tmp/uuwaf.bin','rb').read()
offs = [m.start() for m in re.finditer(rb'\x1bLJ', d)]        # LuaJIT bytecode magic number
for i, o in enumerate(offs):
    end = offs[i+1] if i+1 < len(offs) else len(d)
    open('/tmp/lj_%02d.ljbc' % i, 'wb').write(d[o:end])
P
docker cp /tmp/lj_04.ljbc <container>:/tmp/   # the segment containing RULE_ALLOW / *_filter / in_whitelist
docker exec <container> /uuwaf/luajit/bin/luajit -bl /tmp/lj_04.ljbc | grep -n 'in_whitelist\|pre_filter\|post_filter'
```

---

## 3.4. What `rule_id = -1` Is (official FAQ)

When `rule_id = -1` appears in a block page/log, it **is not a hit by some rule**; it means **that domain is not configured in site management**:
UUSEC WAF blocks access to unconfigured domains by default (to prevent legal risks caused by malicious domain resolution pointing at it). To troubleshoot this kind of "inexplicable block", check the site list first.

---

## 4. Rule Library and Ruleset Are Separate

| Concept | Carrier | Key conclusion |
|:---|:---|:---|
| Rule library | `waf_rules` / `GET /rules` | Rule definitions. **A rule created but not attached to a ruleset = a dead rule, it does not take effect** |
| Ruleset | `waf_ruleset.content` (JSON array) | The enabled list. One site attaches one set; one set can be referenced by multiple sites |

- To determine whether a rule is in effect: **first check whether it is in the array of the ruleset used by the site** (rather than checking whether it exists).
- The default ruleset `Default` cannot be deleted.
- **Low-risk remediation order**: ① modify the ruleset (disable a rule) → ② add a custom rule and attach it to the set → ③ modify the rule body (cautiously, see the next section).

---

## 5. Built-in Automatic Rules Cannot Be Modified

- Built-in blocking rules are **automatically maintained** by the panel, and **changes are rolled back** (the official CHANGELOG entry "prevent default rules from overriding custom rules" is where this mechanism comes from).
- ⚠️ **Do not compare the "seed SQL inside the binary" against the online rules to judge whether they have been modified**: the seed comes in **two copies, Chinese and English** (two `INSERT`s for the same id), and the online database may be the result of initializing with an **older version** and upgrading all the way up, so the two are inherently inconsistent (in testing, 46 of the 50 built-ins matched one seed copy verbatim; `20`/`24`/`75` not matching does not mean they were modified). The criterion is **whether the change was rolled back**, not comparing text against the seed.
- 📌 **ID `9` does not count as "modifying a built-in"**: the official seed defines it as a **reserved custom slot** (content merely `return false`, reference in §2), i.e. a slot left for users to build on (modifying it is not rolled back). The real built-ins are `10~499`.
- ⚠️ **`type` has nothing to do with "whether it is a built-in"**: `type` is the **rule editing type** (`0`=DSL visual rule / `1`=Lua rule). The criteria are the **ID segment** (`9`=reserved slot, `10~499`=built-in, `≥500`=custom), the **fixed name**, and **whether changes are rolled back**.
- This means: even if a built-in rule's criteria have obvious defects, you **cannot modify it directly**.

Known defects in built-in rule criteria (reproduced in testing):

| Rule | Defect |
|:---|:---|
| 22 Boundary anomaly blocking | `waf.strCounter(ct, "boundary")` also counts occurrences of the word inside the **value** of `boundary`, so a boundary whose value itself contains that word (e.g. `--abc-boundary-123`) is counted twice and misjudged as anomalous |
| 11 Invalid protocol | The detection logic is in the kernel (not Lua) and includes checks of the `checkContentDisposition` kind; it cannot be modified from the Lua side |

**How to handle this**: a built-in rule's criteria cannot be changed (the panel maintains them automatically), so **do not modify it directly** — the only options are: disable that entry in the **ruleset**, or use rule 9 to precisely allow a confirmed false positive (`rule-authoring.md` §4.7).

1. Create a new **custom rule** that reproduces the built-in rule's detection logic;
2. Inside the custom rule, precisely allow the **confirmed business false positives** (short-circuit before `return false`);
3. Turn off the original built-in rule in the **ruleset**;
4. Attach the custom rule to the ruleset.

> The order cannot be reversed: **the custom rule must take over first, and only then can the built-in rule be turned off**, otherwise a protection gap appears.

---

## 5.2. Rules Run in a **Restricted Sandbox** (`ngx` Is Unusable — Not Just "Not Recommended")

The initialization module of `sbin/uuwaf` builds a restricted-environment `_G` substitute for rules (`env._G = env`),
and injects global names **according to an allowlist**. Verbatim allowlist measured on v7.2.5 (bytecode string table):

```
_VERSION error ipairs next pairs select tonumber tostring type unpack
os.clock os.difftime os.time
string.byte string.char string.find string.format string.gmatch string.gsub
string.len string.lower string.match string.reverse string.sub string.upper
table.insert table.maxn table.remove table.sort table.concat
```

**`ngx` is not in the allowlist** → accessing `ngx` (or `ngx.xxx`) inside a rule raises an error immediately; `require` is likewise unavailable.
This explains why the 50 official built-in rules use `ngx` **zero times** — it is not a style issue, it is that **it does not exist in the environment**.

> **Plugins are not subject to this sandbox**: official plugins all use `ngx` / `resty.*` / `require` directly.
> To "do detection with ngx" → write it as a plugin (see `plugin-authoring.md`).
> The verification method is the same as §3.3 (export the bytecode and search for `_VERSION error ipairs`).

---

## 6. Available Storage: Shared Memory Dicts

The nginx configuration declares **9 shared memory dicts** (verbatim `lua_shared_dict` measured on this machine):

| Dict | Capacity | Purpose |
|:---|:---|:---|
| `ipCache` | 16m | Visiting IP counter / state (read-write) |
| `ipBlock` | 8m | Record of blocked IPs (key=IP, value=cumulative block count; the engine writes it automatically when a rule blocks) |
| `stats` | 2m | Statistics |
| **`db`** | **32m** | **General-purpose key-value store (largest capacity)** |
| `robot` | 16m | Human verification state |
| `purge` | 4m | CDN cache purge |
| `lock` | 2m | Locks |
| `live` | 2m | Live state |
| `search_engines` | 8m | Search engine verification |

### Available on the Rule Side

| Variable | Semantics | Constraints |
|:---|:---|:---|
| `waf.ipBlock` | **The record of "blocked IPs"**: key=IP, value=cumulative block count | The official docs state "for usage see `ngx.shared.DICT`"; **both read and write APIs are available** |
| `waf.ipCache` | Key-value store for the visiting IP counter / state | The official docs state "for usage see `ngx.shared.DICT`" |

**Who writes to `waf.ipBlock` (key point)**:

| Who blocks | Auto-written? |
|:---|:---|
| **Rule block** | ✅ **Automatic** — the engine performs `ip.incr.ipBlock` in the `resp_header_post_filter` / `resp_body_post_filter` phases |
| **Plugin block** | ❌ **Not automatic** — the plugin must call `ngx_kv.ipBlock:incr(waf.ip, 1, 0, 600)` itself |

> **Its purpose is exactly "to record the blocked IPs", and the number of attacks from that IP can be judged from it** — this is the implementation basis of official built-in rule 13.
> **TTL = 600 seconds (10 minutes)**: each rule block **resets the TTL to 10 minutes** and **does not increment the count**; once blocking stops triggering, the count naturally returns to zero and the ban lifts by itself.
> ⚠️ The official docs do not mark `waf.ipBlock` as "read-only" — like other `ngx.shared.DICT`s it is read-write.
> But **the way built-in rule 13 is written is deliberately "read-only + renewal"** (the value of `set` comes from the result of `get`, which means the count is left untouched),
> because incrementing the count is the job of the engine's blocking action; if the rule does `incr` itself it would cause double counting.

Built-in rule 13 (high-frequency attack protection) demonstrates the correct use of `waf.ipBlock` — **read the cumulative count + renew, without incrementing it yourself** (code in `rule-authoring.md` §4.4).

Built-in rules 66 / 68 / 70 demonstrate reading and writing `waf.ipCache` (`get` / `set` / `incr`, with `exptime` and `flag`):

```lua
local sh = waf.ipCache
local key = 'cc-' .. waf.ip
local c, f = sh:get(key)
if not c then
    sh:set(key, 1, 60, 1)        -- 60-second counting window, flag=1 counting
elseif f == 2 then
    return waf.block(true)       -- banned: reset TCP
else
    sh:incr(key, 1)
    if c + 1 >= 100 then
        sh:set(key, c + 1, 300, 2)  -- 5-minute ban, flag=2 banned
        return waf.RULE_BLOCK, key
    end
end
```

`flag` is a **custom state bit** (the official docs define no value range): `1` = counting, `2` = banned. It lets the same key carry the dual semantics of "count + state".

### Available on the Plugin Side: Native `ngx.shared`

Inside a plugin you **can use the native `ngx` object** (`local ngx = ngx`), so all shared dicts are directly accessible:

```lua
local ngx_kv = ngx.shared
ngx_kv.db:set(session_key, expire_time, duration)   -- store sessions in the 32m db
ngx_kv.ipCache:get(key)                              -- the same storage as the rule side
ngx_kv.ipBlock:incr(waf.ip, 1, 0, 600)               -- manually accumulate the block count
```

> 🔴 **Do not rely on native `ngx` when writing rules**. Measured: **among the 51 built-in rules, the number of occurrences of `ngx.` is 0** — built-in rules uniformly use the `waf.*` wrapper API.
> Reason: rules may run in a restricted environment different from that of plugins, and native `ngx` may not be available. **The reliable cross-environment practice is to stick to `waf.*`**: `waf.ipCache` / `waf.ipBlock` / `waf.errLog` / `waf.rgx*` / `waf.block`.
> Plugins are the opposite — the plugin template itself requires operating `ngx` directly (`ngx.req.get_headers()`, `ngx.header`, `ngx.exit()`), which is the legitimate use of the native context.

### Which Storage to Choose

| Need | Choose |
|:---|:---|
| Access frequency / state counting | `waf.ipCache` |
| Reading an existing block count | `waf.ipBlock` (read-only) |
| General key-value needing more space (sessions, mappings, caches) | Plugins use `ngx.shared.db` (32m) |
| Writing logs | `waf.errLog(...)` (rules) / `require("waf.log").errLog(...)` (plugins) |

---

## 7. Location of the Built-in Detection Modules

The built-in detection logic is divided into two layers:

| Layer | Location | Form | Modifiable? |
|:---|:---|:---|:---|
| **Pure Lua detection modules** | `/uuwaf/waf/plugins/*.w` | Plaintext Lua (AC automaton + signature string table) | Modifiable at the filesystem level, **but a container update will overwrite them, so they should not be changed** |
| **Kernel / binary decisions** | nginx module + Go service | Not readable | Not modifiable |

**The list of plaintext-readable modules and the false-positive troubleshooting workflow are in `pitfalls.md` §7.**

---

## 8. Upstream Request Headers

Headers injected when the WAF forwards to the upstream (official FAQ):

| Header | Meaning |
|:---|:---|
| `X-Waf-Ip` | Real client IP |
| `X-Waf-Id` | Which WAF node the request came from (value = `id` in `config.json`); **used to distinguish the source in cluster mode** |
| `X-Waf-Cache` | `HIT` = cached, `MISS` = not cached |

When an upstream application needs the real IP, **read `X-Waf-Ip` first**, and `X-Forwarded-For` second.

---

## 9. Observation Mode

Three levels of "log only, do not block":

| Level | Location | Granularity |
|:---|:---|:---|
| **Site level** | The site `mode` field | The whole site |
| **Rule level** | The rule's `return waf.RULE_LOG_ONLY, …` | A single rule |
| **Ruleset level** | The ruleset content (disable a rule) | That site |

- `waf.RULE_LOG_ONLY` (value `3`) has been available since **v7.2.0** and is used for the **observation mode of a single rule**.
- **v7.2.0 is declared incompatible with rules from older versions** and does not support a direct upgrade from older versions — check the version watershed before upgrading.
- Site-level observation mode still records logs even when a rule returns `RULE_ALLOW`, so **when the allowlist does not take effect**, first confirm whether the site is in observation mode.

---

## 10. Version Watersheds (must-check before upgrading)

| Version | Change |
|:---|:---|
| **v7.2.0** | Added the three constants `RULE_BLOCK` / `RULE_ALLOW` / `RULE_LOG_ONLY`; **incompatible with older-version rules, direct upgrade not supported** |
| **v7.1.0** | Plugins support `priority`; phase functions return two bools to control the flow |
| **v4.1.0** | Plugins introduced pre/post sub-phases (previously `req_filter` / `resp_header_filter` / `resp_body_filter` / `log`) |
| **v7.2.5** | Community edition maximum number of sites 10 → **16** |

### Feature → Minimum Version (confirm the target instance version before writing rules)

| Feature | Minimum version |
|:---|:---|
| The three constants `waf.RULE_BLOCK` / `RULE_ALLOW` / `RULE_LOG_ONLY`, single-rule observation mode | **v7.2.0** (and that version is incompatible with older-version rules and does not support a direct upgrade) |
| Plugin `priority`, phase functions returning two bools | v7.1.0 |
| Plugin pre/post sub-phases (the old names `req_filter` etc. are obsolete) | v4.1.0 |
| Community edition site limit 16 | v7.2.5 |
| Automatic database schema creation | v6.8.0 |
| `UUWAF_DB_DSN` (custom database), certificate wildcarding all domains | v6.7.0 |

> Reading the target instance version: the `version` from `GET /setting/license` (or `waf.py -i <instance> ping`).

For the full change history see `offline-docs/CHANGELOG.zh-CN.md` and the online `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/CHANGELOG.md`.

---

## 11. Community Edition Capability Boundaries

| Item | Community edition |
|:---|:---|
| Price | Completely free |
| Number of sites | Maximum **16** |
| Vulnerability protection / CC protection / backdoor detection / business security / CDN acceleration / advanced rules / plugin extension / compliance auditing / log reports / region restriction / load balancing / block pages / free certificates | ✅ Supported |
| Machine learning / cluster management / host defense / RASP / data masking / enhanced rules / multi-tenancy / custom development / technical support | ❌ Requires the Professional or Commercial edition |

Official effectiveness evaluation (community edition): detection rate 74.77%, false positive rate 0.09%, accuracy 99.42% (sample size 33669).
For the full comparison table see `offline-docs/product-introduction.md`.
