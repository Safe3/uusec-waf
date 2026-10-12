# Pitfalls, Lessons, and Implementation Addenda

> This document records things **that the official docs do not describe but that will make you do the wrong thing**. Everything here comes from implementation-level research on a running instance (nginx configuration, the source of built-in rules and detection modules, the Go binary with its embedded frontend) and from actual measurement.
> Before authoring rules, diagnosing false positives, or running diagnostics, **scan this document once**.

---

## 🔴 1. Do Not Send Crafted Requests to the WAF Data Plane (the most expensive lesson)

**Symptom**: to reproduce a false positive, you send crafted requests to port 80 / 443 of the WAF (the data plane).

**Consequences**:

| Element | Behavior |
|:---|:---|
| Rule triggered | **13 "High-frequency attack protection"** |
| Criterion | The **cumulative block count for that IP in `waf.ipBlock` ≥ 10** |
| Source of the count | **Written automatically by the WAF engine when a rule blocks** (not automatic for plugins, which must call `ngx_kv.ipBlock:incr(...)` manually) |
| Count TTL | **600 seconds (10 minutes)** -- each rule block **resets** that IP's TTL, but does **not increment the count** |
| Storage | The Lua **shared memory dict `ipBlock`** (8m), **not in the database**, and there is **no Redis** in the container |
| Ban strength | Once hit, **every request is blocked**, and each block renews the TTL to 10 minutes |
| Self-healing | ✅ **The count is cleared once the TTL expires**, so the ban lifts by itself (as long as you stop triggering blocks) |
| Blast radius | The banned object is **the IP that sent the request** -- if you send from the local machine or a container, you will also ban that machine's / container's IP, **affecting every service on the same path** |
| How to lift it | ① `PUT /setting/ipBlock/unlock` (body `{"ip":"<IP>"}`) lifts it immediately; ② stop triggering blocks and wait for the TTL to expire. ⚠️ **It is not `check`** -- `check` only queries the state (`{locked:bool}`) |

> ⚠️ **"It only grows, never decays, and must be lifted manually" is a common misconception**. The official description of rule 13 is
> "after more than 10 cumulative attacks, block that ip's access **for 10 minutes**" -- the third argument `600` of
> `ib:set(waf.ip, c, 600, 1)` is the TTL, a **ban window** rather than something "permanent".
> The reason it feels "unstoppable" is that **continuously generating blocked requests during debugging keeps refreshing the TTL**.
> **The right move: stop making requests and wait 10 minutes**.

**Discipline**:

1. **As soon as you find a request has been banned, stop every request that goes through the data plane** (otherwise the TTL keeps being renewed) and fall back to control-plane channels.
2. During diagnosis, use only: the console API (4443), the database (read-only), and the source of the built-in detection modules (`/uuwaf/waf/plugins/*.w`).
3. When you need to verify "whether a given rule is in effect", prefer reading the signature tables and the logs over crafting requests.
4. If end-to-end verification is truly required, obtain explicit authorization first.
5. **Boundary**: a **small amount of genuine traffic is allowed** (e.g. you opening a blocked page once yourself in a browser); **bulk sending or crafting attack payloads to verify rules is forbidden** -- every block adds to that IP's rule 13 count.

---

## 🔴 2. Credentials and Sensitive Field Inventory

The items below are **never written to disk, never echoed back, never written into persona files / the knowledge base, and never transmitted through the conversation**; when they must be shown, mask them field by field:

| Source | Sensitive content |
|:---|:---|
| `GET /setting` | `dsn` (database connection string, contains the password), `jwt_key`, `api_token`, `ml_token` |
| `GET /users` | `otp_url` (**embeds the TOTP secret in plaintext**), `pwd` (password field, **treat as sensitive**) |
| `GET /certs` | `key` (**private key PEM in plaintext**), `dns_credential` (**DNS provider credentials**, used for DNS-01 validation) |
| `request` returned by `POST /logs` | The raw HTTP message, including sensitive headers such as `Authorization` / `Cookie` **stored verbatim** |
| `config.json` | `dsn` / `jwt_key` / `api_token` / `ml_token` |
| **The `UUWAF_DB_DSN` environment variable** | The database connection string, **containing the database password**. `docker inspect` and `docker compose config` both echo it verbatim -> mask the whole segment when viewing it (see `deployment.md` §3) |
| **MySQL password** | `MYSQL_PASSWORD` in `.env`, `MYSQL_ROOT_PASSWORD` in the compose file, the DB account password -- handle as above |
| Panel default credentials | `admin` / `#Passw0rd` (**this user must be deleted after deployment**) |

**Obtaining the `GET /setting` response = holding full panel privileges** (you can connect straight to the business database and forge tokens). Such endpoints should only ever be called by authorized clients.

> 🔴 **Log-writing discipline**: in rules / plugins, **do not write request content into logs**.
> `waf.errLog(log.getReq())` and `waf.errLog(waf.form["RAW"])` write `Authorization` / `Cookie` / form passwords
> **verbatim into `/uuwaf/logs/error.log`**. Write only "criterion + hit summary", e.g. `waf.errLog("hit: uri=" .. waf.uri)`.

**Where to keep the Api-Token**: in a configuration file with 600 permissions or in an environment variable, **read by a script**, never through the model context. See the implementation in `scripts/waf.py`.

---

## 🔴 3. Documented vs. Actual Behavior (measured)

When using the panel REST API, the following spots **will go wrong if you follow official-doc intuition**:

| Item | Doc / intuition | Actual |
|:---|:---|:---|
| Querying logs | Use `GET` | **Must use `POST /logs`**; `GET /logs` returns `{"message":"Not Found"}` |
| Log time range | Pass dates | **Must include hours, minutes and seconds** `["YYYY-MM-DD HH:MM:SS", ...]`; a bare date returns **0 records without any error** (silent failure) |
| Log level "all" | Omit it or pass 0 | **`level: 5` = all** |
| Type of the `query` field | String | Must be an **object**; passing a string raises `Unmarshal type error: expected=web.LogQuery, got=string` |
| Parsing the returned JSON | Standard JSON | Some endpoints carry a **UTF-8 BOM** (e.g. `GET /setting/ipBlock/all` returns `\ufeff[...]`) -> decode with `utf-8-sig`, otherwise `json.loads` fails outright |
| Rule `content` line endings | Uniformly `\n` | **Not uniform**: of the 51 measured rules, 4 use CRLF / 47 use LF. If a fetch->edit->write-back normalizes line endings, it produces a **spurious whole-file diff** |
| Fetching rule bodies | `GET /ruleset/rules` or `GET /rules/{id}` | The former returns a **summary** (`content` is always `""`, `level`/`type` zeroed) and its **`id` parameter has no effect** (it always returns everything); the latter **does not exist** (404). The body must go through `GET /rules` |
| Ruleset array order | Assumed to determine execution order | **Execution is by ascending rule ID**; the array order only expresses "which ones are enabled" |
| Create/update | Both use POST | **POST = create, PUT = update** (frontend: `id===0?"POST":"PUT"`) |
| Writing rules/plugins | Just POST | Requires `waf_nodes` to be **non-empty**, otherwise it reports `No waf nodes` |
| `waf.uri` | Includes parameters | **Decoded, without parameters** (`waf.reqUri` is the one with parameters) |
| `waf.isQueryString` | String | It is a **bool**; `waf.queryString` is the one that is a table |
| Deleting a ruleset | Any set can be deleted | **The default set cannot be deleted** |

---

## 🟠 4. Traps That Go Wrong Without Erroring

These are the most dangerous -- **no error, silent failure**.

| Trap | Symptom | Correct approach |
|:---|:---|:---|
| **Scope of the `RULE_ALLOW` short-circuit** | You think it only allows the current rule, but it actually **skips the entire remaining rule chain + ML validation** (including SQLi/RCE/XSS/rate/CC protection), and the response header phase **skips plugin hooks entirely** as well | Allow conditions must be **extremely narrow** (host + method + exact path + content-type), plus a `..` check; the exact checklist is in `internals.md` §3-3 |
| **Wide prefix allow** | `waf.startWith(uri, "/api/v1/")` looks like it allows one feature, but actually tunnels the whole prefix | Use `(waf.uri or "") == "<exact path>"`; for variable parts use an anchored regex `^…$` |
| **Character class containing `.`** | `[A-Za-z0-9._:-]+` can match `..`, so `/a/../b` also gets allowed | Add **a separate** `not waf.contains((waf.uri or ""), "..")` |
| **Rule created but never attached to a ruleset** | The rule exists and is visible in the panel, but has no effect at all | After editing, confirm it is in the array of the ruleset used by the site |
| **Preempted by a lower-ID rule** | The new rule is written but has no effect | Check whether a lower-ID rule (especially an allowlist) handles it first |
| **Position requirements when relying on `waf.ipBlock`** | The rule is written but has no effect | Such rules have hard requirements on the ID position |
| **Modifying built-in automatic rules** | It seems to work right after the edit, **then the panel rolls it back** | Do not modify built-in rules; to stop a detection, change the **ruleset** enable list; criterion flaws can only be contained by an exact allow in rule 9 (see `rule-authoring.md` §4.7) |
| **Editing config and forgetting to restart** | Changing the listen port / console certificate has no effect | These two plus the captcha image require a restart; everything else takes effect immediately |
| **`waf_nodes` is empty** | Writing rules/plugins reports `No waf nodes` | Configure the node address (it does not need to actually be online) |

---

## 🟠 5. The Full Semantics of `waf.ipBlock`

**Its purpose is to "record blocked IPs", and it can be used to judge how many times that IP has attacked** -- it is the basis of the official built-in rule 13 "High-frequency attack protection".
The code of rule 13 and its key writing points are in `rule-authoring.md` §4.4; the table below is the full semantics:

| Property | Conclusion |
|:---|:---|
| **Semantics** | **Records blocked IPs** (key = IP, value = cumulative block count) |
| **How it is written (rules)** | ✅ **Written automatically by the WAF engine when a rule blocks** -- no need to write it by hand in the rule |
| **How it is written (plugins)** | ❌ **Not automatic** -- a plugin block must call `ngx_kv.ipBlock:incr(waf.ip, 1, 0, 600)` itself |
| **Where the engine writes** | The response phase (`ip.incr.ipBlock` inside `resp_header_post_filter` / `resp_body_post_filter`) |
| **TTL** | **600 seconds (10 minutes)**. Each rule block **resets** that IP's TTL to 10 minutes (`set`, not `incr`) and **does not increment the count** |
| Count increments | Incremented by **the engine's block writes**; rule 13 itself **does not increment** (it only reads + renews) |
| Threshold | Built-in rule 13 uses **10** |
| Self-clearing | ✅ Cleared once the TTL expires. **It lifts naturally as long as no new block is triggered** |
| Permissions on the rule side | 🔴 **Read-only** -- you may `get`, and you may do a **renewal-style `set`** (value equal to the stored value), but you **cannot overwrite the count**. Use `waf.ipCache` for state storage |
| Rule position | 🔴 Rules that depend on it have **hard requirements on the ID position** (see `internals.md` §2) |
| Official description | Rule 13: "after more than 10 cumulative attacks, block that ip's access **for 10 minutes**" |

**Corollaries**:
- To judge "how many times an IP has attacked", just read `waf.ipBlock:get(ip)` (that is exactly what built-in rule 13 does).
- Do not generate blocked requests while debugging (it keeps renewing the TTL); and do not set the threshold too low.
- **To lift a ban quickly**: stop making requests and wait 10 minutes, or remove that entry under "IP ban" in the panel (endpoint `PUT /setting/ipBlock/unlock`).

---

## 🟠 6. Shared Memory Dicts and Initialization Variables, in Full

The official docs mention only `waf.ipBlock` / `waf.ipCache`; **there is far more usable storage than those two**:

nginx declares **9 shared memory dicts**, of which:

| Dict | Capacity | Description |
|:---|:---|:---|
| `db` | **32m** | **The largest**, suited to plugins storing sessions, mappings, and custom caches |
| `ipCache` | 16m | Access IP counters (shared by rules and plugins) |
| `robot` | 16m | Human-verification state |
| `ipBlock` | 8m | Blocked IPs (**read-only on the rule side**) |
| `search_engines` | 8m | Search engine verification |
| `purge` | 4m | Cache purging |
| `lock` `live` `stats` | 2m | Locks / live state / statistics |

**In plugins** you access them directly through native `ngx.shared`; **in rules** you may only use the `waf.*` wrappers (`waf.ipCache` / `waf.ipBlock`).
For the read/write semantics of each dict, the writer and TTL of `ipBlock`, and code examples, see `internals.md` §6.

> **Cross-environment conclusion**: rules write `waf.*`, plugins write native `ngx`. Mixing them up is a common source of bugs.
> Evidence: an actual measurement found `ngx.` appearing **0 times** across the 51 built-in rules, while the plugin template itself requires operating on `ngx` directly.

---

## 🟠 7. The Built-in Detection Modules Are Readable -- a Shortcut for False-Positive Triage

False-positive triage **does not require crafting requests** -- the built-in pure-Lua detection modules are plaintext, so you can read the signature tables directly:

```
/uuwaf/waf/plugins/file_leak_detection.w    sensitive file leak signature table (includes .env / .git/ / .ssh/ etc.)
/uuwaf/waf/plugins/scanner_detection.w      scanner UA / URI signature strings
/uuwaf/waf/plugins/weak_pwd_detection.w     weak password regex table
/uuwaf/waf/plugins/sql_error_detection.w    SQL error signature strings
/uuwaf/waf/plugins/java_error_detection.w   Java error signature strings
/uuwaf/waf/plugins/java_class_detection.w   Java deserialization class names (compiled bytecode)
/uuwaf/waf/plugins/php_error_detection.w    PHP error signature strings
```

Triage flow: **locate the specific rule ID in the logs -> read the corresponding signature table -> confirm the trigger word -> decide whether it is a business false positive or a real attack**.

**Which built-in rules can "see" the JSON body of a request** (when narrowing down false positives on JSON endpoints, use this first instead of trying one rule at a time):

| Can see the JSON body | `46` (JSON SQLi), `48` (JSON RCE), `64` (FastJSON) -- they go through `jsonFilter(form["RAW"], …)` |
|:---|:---|
| **Cannot see it** | `45`/`47` (conventional SQLi/command injection), `54` (generic attack), `56` (XSS), `51` (RFI) -- they only go through `kvFilter(form["FORM"] \| queryString \| cookies \| reqHeaders)`; in a JSON request `form["FORM"]` is empty |
| Scanning the **response content** | `58`/`59`/`60`/`61`/`62` (data leakage and the various error texts) -- these belong to the **response phase** |

> On the request side only the first three can see the JSON body, whereas on the response side it is the last five -- the phases differ, and a rule only covers its own phase.

> ⚠️ These files are **read-only references**; do not modify them: a container update overwrites them, and it goes beyond the boundary of "using the WAF".

**Some detections cannot be corrected from the Lua side**: for example "Invalid protocol" (including the `checkContentDisposition` decision) is not implemented in a Lua module and cannot be changed directly -- and the built-in rules themselves cannot be changed either (the panel's maintenance would roll it back). Such false positives can only be handled with an exact allow in rule 9 (`rule-authoring.md` §4.7).

---

## 🟡 8. Other Implementation Addenda

| Item | Description |
|:---|:---|
| **Built-in management-plane port** | `4447` (`waf_nodes` points at it). The control plane `4443` and the data plane `80/443` are **three independent entry points** |
| **Purpose of `X-Waf-Id`** | In cluster mode the upstream uses it to tell which node a request came from; the value = the `id` in each node's `config.json` |
| **Database time column** | The time column of the log table is `updated_at`; **there is no `time` column** |
| **Where ban state lives** | In the **shared memory dict `ipBlock`** (8m), **not in the database**. There is **no Redis** in the container (no trace of Redis in `/uuwaf/conf` or `sbin/uuwaf`), and the ban list does not go through Redis |
| **IP ban panel endpoints** | `GET /setting/ipBlock/all` retrieves the list; `PUT /setting/ipBlock/{action}` has **4 actions** (body is `{ip}` for all): `check`=query state (query only, does not change the ban) / `unlock`=unban / `checkAll`=check all / `unlockAll`=unban all |
| **`access_log off`** | Data-plane access logging is off; logs mainly go to the database (`log_db: true`) |
| **LuaJIT can be validated offline** | Inside the container `/uuwaf/luajit/bin/luajit-*` can perform a **syntax check** with `loadfile` (`wafcheck.sh lua` takes this path); validate rules after writing them and before going live |
| **`client_max_body_size 0`** | No limit on request body size (handled by site-level rule 43 "request body size limit") |
| **`server_tokens off`** | Confirm this value when deploying the panel, to avoid leaking version information |
| **Cache path** | `/tmp/disk_cache_uuwaf`, `max_size=8g`, `inactive=60m` |

### Rule Syntax Self-Check

After writing a rule, validate the syntax before going live (this only compiles/matches locally and sends no requests).

**The full command set, backend choices and minimal commands are in `rule-authoring.md` §2-2.** Three key points:

1. **Regex**: `pcrecheck.py regex` (PCRE2, any machine) or `wafcheck.sh regex` (PCRE1, WAF hosts only).
2. **Only luajit can do authoritative Lua validation**, so it **can only be done when the local machine is itself a WAF host** (`wafcheck.sh lua` -> `SYNTAX_OK`).
   On a machine that is not the WAF, `pcrecheck.py lua` only does a heuristic smoke test (it outputs `BALANCED(heuristic)`, **not** `SYNTAX_OK`).
3. **`\d` in a Lua short string must be written `\\d`**; in a `[[ ]]` long string it is kept as-is. This is the most frequently hit pitfall when writing rules containing regexes.

---

## 🟡 9. Authorization and Operating Boundaries (general discipline)

1. **Everything is read-only during diagnosis**: the panel API, read-only database queries, reading source code.
2. **🔴 Unauthorized write operations on the database are strictly forbidden**: read-only. `INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`/`TRUNCATE` and the like are all forbidden -- **equally forbidden for testing, verification, and log cleanup**; logs are original records, so logs produced by testing are kept as-is with their origin noted, and are never deleted, cleared, or altered.
3. **Any production write operation requires explicit authorization first**: changing rules, changing rulesets, unbanning IPs, changing site configuration, changing allowlists, **database write operations**.
4. **List all open questions at once**; do not ask while working.
5. **Self-check before delivering a change**: does the change leave a protection gap? Does it require a restart? What is the rollback path?
6. **Acceptance is based on the actual effective state, not on API return values** -- a 200 response does not mean the rule is in effect.
7. **Do not create or modify configuration on external systems on the user's behalf**: if you can provide directly pasteable content, hand it to the user to execute.
