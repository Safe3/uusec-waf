# Console REST API (control plane)

> **Sources of authority**: the panel front-end implementation (JS embedded in `/uuwaf/waf-service`) + the official FAQ "How to call the UUSEC WAF console REST API".
> Every path is tagged with a **risk level** (graded by destructiveness and sensitivity); look at that column before acting.

Risk legend:

| Marker | Meaning |
|:---|:---|
| 🔴 High risk | Destructive or irreversible, interrupts service, or returns plaintext credentials (private key / password / token) — **back up first, confirm the target instance first** |
| 🟠 Caution | Write operations with side effects (creating/deleting/modifying sites / rules / rulesets / certificates / plugins / users / CDN / IP lists); they can be rebuilt, but they change the live protection state |
| — | Read-only query, does not change the service state |

---

## 1. Authentication

Every request carries the HTTP header:

```
Api-Token: <token>
```

- Copy the token in the panel under "System Settings -> API Access Token" (**copying requires logging into the panel**; afterwards a call only needs that token).
- `Api-Token` is valid for all read and write paths (`GET /setting/license`, `GET /ruleset`, `POST /logs`, etc.); **no JWT is required**.
- A failed authentication returns `{"message":"missing or malformed jwt"}` (HTTP 400/401). A single mistyped character in the token triggers this error — when troubleshooting, suspect the token's character-for-character correctness first.

### Base URL

```
https://<panel address>:<default 4443>/api/v1
```

- Default port **4443**, determined by the `addr` field in `/uuwaf/web/conf/config.json` (default `:4443`).
- The panel usually uses a **self-signed certificate**, so the client must skip certificate verification.
- **4443 is the control-plane entrance**: it does not go through the WAF data plane and does not consume attack counters — the only safe channel during diagnosis.

---

## 2. General Rules (Important)

| Rule | Description |
|:---|:---|
| **POST = create, PUT = update** | Front-end logic is `id === 0 ? "POST" : "PUT"`. When updating, the body must carry `id`. |
| **Log and audit queries use POST** | `GET /logs` returns `{"message":"Not Found"}`; you must use `POST /logs` with a body. |
| **The three forms of DELETE** | ① bulk via body `{keys:[1,2]}` (`/sites`, `/certs`, `/plugins`, `/ml`, `/cdn`); ② single delete via path `/rules/{id}`, `/ruleset/{id}`, `/users/{id}` (**no body**); ③ parameterless bulk purge `/cdn/purge`, `/logs/purge`, `/audits/purge`, `/ml/purge` |
| **Rule/plugin write operations need a non-empty `waf_nodes`** | An empty array reports `No waf nodes`. It is enough that the node addresses are configured; the nodes need not actually be online. |
| **The default ruleset cannot be deleted** | `DELETE /ruleset/{id}` is rejected for the `Default` set. |
| **Config changes take effect immediately** | Rules, sites, certificates and so on take effect as soon as the panel saves them; **no restart is needed**. Exceptions: listening ports, the admin panel certificate and the CAPTCHA image pool require a restart (see `operations.md`). |

---

## 3. Endpoint Inventory

### 3.1 Sites `/sites`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| GET | `/sites` | Site list + ruleset dropdown options | — |
| POST | `/sites` | Create a site | 🟠 Caution |
| PUT | `/sites` | Update a site (with `id`) | 🟠 Caution |
| DELETE | `/sites` | Bulk delete `{"keys":[id,...]}` | 🟠 Caution |

**`GET /sites` response structure**:

```json
{
  "options": [ {"label":"<ruleset name>","value":2}, {"label":"Default","value":1} ],
  "sites":   [ { ...site object... } ]
}
```

- `options` holds the **ruleset dropdown entries** (`label` = name / `value` = `ruleset_id`); the front end uses it to render the select box when creating a site.
- **`hosts` is an array of strings** (e.g. `["example.com","*.example.com"]`), not a string.

**Site object field semantics** (returned by `GET /sites`; **types and defaults are as of v7.2.5**):

| Field | Type | Default | Semantics |
|:---|:---|:---|:---|
| `id` `usr` `updated_at` | int/str/str | — | Identity and audit |
| `hosts` | array[str] | `[]` | List of domains this site takes over; supports `*` wildcards (e.g. `["example.com","*.example.com"]`) |
| `description` | str | `""` | Site note |
| **`mode`** | **bool** | `true` | 🔴 **Protection switch**: `true` = **block mode** (intercept), `false` = **log-only mode** (record only, do not block). **It is a `bool`, not an int** |
| `ruleset_id` | int | `1` | ID of the mounted ruleset (corresponds to `options[].value`) |
| `scheme` | str | `"http"` | **Upstream connection protocol** (origin-fetch protocol, `http`/`https`) |
| **`servers`** | array[obj] | `[{"ip":"127.0.0.1","port":8080,"weight":1}]` | **Upstream host list**. Each entry is `{ip, port, weight}`; `weight` = weight (works together with `type` below for load balancing) |
| **`type`** | str | `"roundrobin"` | **Load-balancing algorithm** (see the enum below; note it **differs from the i18n key names**) |
| `ip_whitelist` `url_whitelist` | array[str] | `[]` | Site-level whitelist. IP accepts a single IP or a CIDR; URL accepts route expressions such as `/foo/*`, `/foo/:name` |
| `custom_host` | str | `""` | **Rewrites the request's Host header when proxying** (empty = no rewrite) |
| `deny_page` | str | default block page HTML | Custom block page content |
| `is_websocket` `is_ml` `is_cache` `force_ssl` | **bool** | `false`/`false`/`false`/`false` | WebSocket support / machine learning / cache acceleration / force HTTPS. **All are bool** |
| `ip_source` | int | `0` | **Source of the client's real IP**: `0` = network connection (socket) / `1` = X-Forwarded-For / `2` = HTTP request header (see below) |
| `ip_order` | int | `2` | **The n-th IP counting from the end** (effective only when `ip_source` is 1 or 2) |
| `ip_header` | str | `"X-Real-IP"` | **Header name** (effective only when `ip_source=2`) |

**`type` (load balancing) enum** — 🔴 the i18n key names and the live values are **inconsistent**; the live values are authoritative:

| Live value | Panel label | Meaning |
|:---|:---|:---|
| `roundrobin` | weighted round-robin | Weighted round-robin (default) |
| `chash` | consistent hashing | Consistent hashing by client IP (**not** `iphash`) |
| `swrr` | smooth weighted round-robin | Smooth Weighted Round-Robin (**not** `SWRR`) |

**`ip_source` enum**:

| Value | Meaning | Companion field |
|:---|:---|:---|
| `0` | Network connection (socket peer IP) | — |
| `1` | `X-Forwarded-For` | `ip_order` (the n-th from the end) |
| `2` | Custom HTTP request header | `ip_order` + `ip_header` (header name, default `X-Real-IP`) |

> `ip_source` / `ip_order` / `ip_header` determine the value of `waf.ip`. If the upstream has multiple proxy layers, misconfiguring them here makes **all IP-based protections (CC, brute force, bans) fail across the board** — a high-frequency blind spot in troubleshooting.

### 3.2 Rules `/rules`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| GET | `/rules` | Rule list (**including the full `content`**) | — |
| POST | `/rules` | Create a rule (requires `waf_nodes`) | 🟠 Caution |
| PUT | `/rules` | Update a rule (with `id`) (requires `waf_nodes`) | 🟠 Caution |
| DELETE | `/rules/{id}` | Single delete | 🟠 Caution |

> ⚠️ **There is no `GET /rules/{id}`**: `/rules/13` returns `{"message":"Not Found"}`.
> The only ways to fetch a single rule's body are: `GET /rules` and filter locally, or take it by `id` from the `/rules` list result.
> (`/rules/{id}` appears only in the front-end delete logic, with method `delete`.)

**Rule object fields**: `id` `uid` `level` `name` `phase` `type` `description` `content` `updated_at` `usr`

| Field | Values | Description |
|:---|:---|:---|
| `id` | int | Rule ID (`9` = officially reserved / `10~499` = built-in / `500~` = custom, see below) |
| `level` | 0 ~ 4 | Threat level: 0=info 1=low 2=medium 3=high 4=critical |
| `phase` | 0 ~ 2 | Filter phase: `0` = request phase, `1` = response HTTP header phase, `2` = response page phase |
| **`type`** | **0 / 1** | **Rule editing type**: **`0` = DSL visual rule, `1` = Lua rule** (panel `typeOption:{dsl:"DSL rule", lua:"LUA rule"}`) |
| `content` | str | Rule body, whose **format is determined by `type`** (see below). It may be **CRLF or LF** (out of 51 entries, 4 CRLF / 47 LF) |
| **`name`** | str | 🔴 **It is only a real rule name when `type=1` (Lua)**; when `type=0` (DSL) `name` is an **empty string** and the whole rule content lives in `content` (JSON) |
| `uid` | int | Rules written by the panel are all `1` (**not** a "built-in/custom" criterion — for the criterion see the ID range) |
| `usr` | str | Creator username |

**The two formats of `content` (determined by `type`)**:

| `type` | Format | Example |
|:---|:---|:---|
| **1 (Lua)** | Full Lua source text | `local ib = waf.ipBlock\nlocal c = ib:get(waf.ip)\n...` |
| **0 (DSL)** | JSON: `[action, [conditions…]]` | `[1,["&",["ip","=","203.0.113.9"],["uri","*","/.env"]]]` |

For DSL structural details see `rule-authoring.md` §2 "Visual rules (DSL)".

**The complete syntax of a DSL rule** (taken from the panel front end v7.2.5 implementation; not covered by the official docs):

`content` = JSON array `[action, [conditions…]]`; the action is a **number** and a condition is `[field, operator, value]`:

| Action | Value | Logic | Value |
|:---|:---|:---|:---|
| Block `block` | `1` | Logical AND | `"&"` |
| Allow `allow` | `2` | Logical OR | `"\|"` |
| Log only `logOnly` | `3` | Logical NOT AND | `"~&"` |
| — | — | Logical NOT OR | `"~\|"` |

**Condition fields (key)** — request side: `ip` `method` `reqUri` `uri` `queryString` `reqHeaders` `userAgent` `referer` `reqContentType` `XFF` `origin` `reqContentLength` `form`; response side: `status` `respHeaders` `respContentType` `respContentLength` `respBody`.

**Condition operators (op)** — 🔴 **they are symbols, not English names**, and **negation = the prefix `~`**:

| Operation | Symbol | Operation | Symbol |
|:---|:---|:---|:---|
| String contains | `*` | String does not contain | `~*` |
| Regex match | `.` | Regex does not match | `~.` |
| IP match | `-` | IP does not match | `~-` |
| Starts with string | `^` | Ends with string | `$` |
| Equals | `=` | Not equals | `~=` |
| Greater than | `>` | Less than | `<` |

> 🔴 **`type` is not a "built-in / custom" criterion**. To decide whether something is built-in you have to look at the **ID range** and at **whether changes get rolled back** (see below).

**The actual criteria for "built-in vs custom"**:

| Criterion | Description |
|:---|:---|
| **ID range** | **`9`** = **officially reserved slot** (seed data: name `"Custom"`, description `"Reserved as a spare, for custom rules with the highest priority"`, content is only `return false`); **`10 ~ 499`** = official built-in rules; **`500 ~`** = custom rules (allocated by auto-increment) |
| **Name** | Built-in rules have fixed names (e.g. `SQL error detection`, `Anti-CC attack rule`) |
| **Whether changes get rolled back** | Built-in rules are **automatically maintained** by the panel and **changes are rolled back** — this is the real reason built-in rules cannot be modified directly |

> Official CHANGELOG (v6.7.0): "To prevent default rules from overriding custom rules, the starting value of the custom rule id range has been adjusted to 500."
> **ID 9 is the "custom highest priority" slot left open by the official build**: any in-house function that needs to "run before all built-in rules" can go here (no restriction on its use). So **do not infer whether something is in-house from the "ID size"**; look at the content and the source.
> **Directly modifying a built-in entry gets rolled back by the panel's automatic maintenance** (official CHANGELOG: "prevent default rules from overriding custom rules"); to stop a built-in detection, what you change is the enablement list of the **ruleset**, not the rule itself.

### 3.3 Rulesets `/ruleset`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| GET | `/ruleset` | Ruleset list (`id` `uid` `name` `content` `updated_at` `usr`) | — |
| POST | `/ruleset` | Create a ruleset | 🟠 Caution |
| PUT | `/ruleset` | Update a ruleset | 🟠 Caution |
| DELETE | `/ruleset/{id}` | Single delete (the default set cannot be deleted) | 🟠 Caution |
| GET | `/ruleset/rules` | **Summary** of the rules inside a ruleset | — |
| GET | `/ruleset/rules?id=N` | Same as above (the `id` parameter **does not affect the result**) | — |

**`content` is a JSON array string** whose elements are rule IDs:

```json
"[66,68,70,50,49,47,45,43,29,19,17,16,15,13,10,9]"
```

> ⚠️ **The array order has no practical meaning**: rules execute in **ascending rule ID order**, not in array order. The array only expresses "which ones are enabled" —
> when the panel saves, it is simply `filter(rules that still exist)` + `JSON.stringify`, with no sorting; the official seed `Default` set also stores IDs in descending order (evidence in `internals.md` §2).

> ⚠️ **The trap in `GET /ruleset/rules`**: what it returns is a **summary** — `content` is always the empty string `""`, `level` / `type` / `uid` are zeroed, and `updated_at` is empty.
> - Fetching a rule body **must** go through `GET /rules` (the list already contains the full text; there is no `GET /rules/{id}`).
> - **The `id` query parameter has no effect**: `?id=1`, `?id=2` and passing nothing all return **all 51 entries** (a full summary of the rule library). **It does not filter by ruleset**, so do not use it to "read the members of a ruleset".
> - To get the members of a ruleset, use `GET /ruleset` and take the `content` array.

**A ruleset ≠ a rule** (the most common conceptual mistake):

| Concept | Carrier | Role |
|:---|:---|:---|
| **Rule** | `GET /rules` (`waf_rules`) | The **definition** of a rule, stored in the **rule library** |
| **Ruleset** | `GET /ruleset` (`waf_ruleset.content`) | The **enablement list** of rules; decides which rules take effect externally |

- A rule can sit in several rulesets, and can also be **created without being attached to any ruleset at all** (in which case it is dead and has no effect).
- A site mounts **one** ruleset (`ruleset_id`); one ruleset can be referenced by **several** sites.
- **Most false-positive handling only needs a ruleset change** (enable/disable one entry) without touching the rule body — this is the lowest-risk handling method.

### 3.4 Logs `/logs`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| POST | `/logs` | Log query | — |
| GET | `/logs/total` | Totals `[total, today, 7 days, blocked]` | — |
| GET | `/logs/top` | Top data `{attackers, sites, types}` | — |
| GET | `/logs/live` | Live status `{usage:{cpu,mem,disk}, req, atk, geo}` | — |
| POST | `/logs/report` | Log report, body `{}` | — |
| POST | `/logs/download` | Export logs as CSV: the body **is the query object itself** `{"level":5,"host":"","url":"","ip":"","time_range":[]}` (**no** `page`/`page_size`); returns `text/csv`, with the filename taken from `Content-Disposition` (e.g. `attack_log.csv`) | — |
| GET | `/logs/newVersion` | Whether a new version exists `{newer: bool}` | — |
| DELETE | `/logs/purge` | Purge logs | 🔴 High risk |

> **Response structure quick reference**: `/logs/total` → `[total requests, today, 7 days, blocked count]`; `/logs/top` → `{attackers, sites, types}` (today's TOP 10); `/logs/live` → `{usage:{cpu,mem,disk}, req, atk, geo}` (`atk`/`geo` are **JSON strings** and need a second parse).

**Query body**:

```json
{
  "page": 1,
  "page_size": 20,
  "query": {
    "level": 5,
    "host": "",
    "url": "",
    "ip": "",
    "time_range": []
  }
}
```

The exact `query` fields (**not covered by the official API docs; taken from the front-end implementation**):

| Field | Type | Description |
|:---|:---|:---|
| `level` | int | **`5` = all**; 0=info 1=low 2=medium 3=high 4=critical |
| `host` | string | Filter by domain; an empty string = no filtering |
| `url` | string | Filter by URL (substring) |
| `ip` | string | Filter by source IP |
| `time_range` | array | Time range |

> 🔴 **Two easy pitfalls with `time_range`**:
> 1. **It must carry hours, minutes and seconds**. `["YYYY-MM-DD HH:MM:SS","YYYY-MM-DD HH:MM:SS"]` works; a date-only `["YYYY-MM-DD","YYYY-MM-DD"]` returns **0 entries without raising an error** — it **silently returns an empty result**, which is very easily misjudged as "no attacks".
> 2. `[]` means no time restriction.

**Queries use `POST`, not `GET`**:

```
GET /logs → {"message":"Not Found"}
```

**Response structure**: `{"data":[...], "total":N}`. The fields of each record in `data`:

| Field | Description |
|:---|:---|
| `id` `uid` `updated_at` | Identity and time |
| `name` | **Name of the matched rule** (e.g. "high-frequency attack protection") |
| `level` | The log entry's level |
| `ip` `country` `province` `city` `latitude` `longitude` | Source and geolocation |
| `host` `url` | Requested domain and path |
| `exploit` | Summary of the detection basis |
| `request` | 🔴 **The full raw HTTP request message** |

> 🔴 **The `request` field contains credentials**: common sensitive headers such as `Authorization`, `Cookie` and `X-Api-Token` are **stored verbatim**.
> **Hard rule: by default do not print, do not write to disk and do not echo back the `request` field**; when an investigation truly requires it, extract only the necessary fragments, and never reproduce credentials in a conversation or a file.

> **`updated_at` is the time column**: there is no `time` column in the database table, so using it by mistake returns no data.

### 3.5 Audits `/audits`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| POST | `/audits` | Audit query `{page, page_size}` | — |
| POST | `/audits/download` | Export CSV (the first 10000 entries of the current filtered result) | — |
| DELETE | `/audits/purge` | Purge audits (**no parameters**) | 🔴 High risk |

**Audit record fields**: `id` `type` (str, operation type such as `"ruleset"`) `usr` `ip` (client IP) `info` (operation details) `updated_at`.

### 3.6 Certificates `/certs`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| GET | `/certs` | Certificate list (**including the full PEM of `crt` and `key`**) | 🔴 High risk |
| POST / PUT | `/certs` | Create / update | 🟠 Caution |
| DELETE | `/certs` | Bulk delete (body `{keys:[id…]}`) | 🟠 Caution |

**Certificate object fields**: `id` `name` `type`(int) `email` `sni` (**JSON array string**, e.g. `"[\"example.com\",\"*.example.com\"]"`) `crt`(PEM) `key`(PEM) `dns_provider` `dns_credential` `dns_challenge`(bool) `expired_at` `uid` `usr` `updated_at`.

**`type` enum**: `0` = **apply for a free certificate** (Let's Encrypt; requires port 80 to be publicly reachable + the domain to be resolved); `1` = **upload an existing certificate** (provide `crt` + `key`). 🔴 `sni` is a **JSON array in string form**, so parsing it needs a second `json.loads`.
⚠️ When changing the certificate type the front end resets the form (fields are cleared on `change`), so before a PUT be sure to carry all the existing fields.
🔴 **`key` is the plaintext private key** and **`dns_credential` is the DNS provider's credential**: after reading them, do not write to disk, do not echo back, and do not write them into persona files or logs.

### 3.7 Plugins `/plugins`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| GET | `/plugins` | Plugin list | — |
| POST / PUT | `/plugins` | Create / update (requires `waf_nodes`) | 🟠 Caution |
| DELETE | `/plugins` | Bulk delete (body `{keys:[id…]}`) | 🟠 Caution |

**Plugin object fields**: `id` `name` (e.g. `basic_auth`, **an identifier rather than a display name**) `description` `enabled` (**bool**, on/off switch) `content` (full Lua text) `uid` `usr` `updated_at`.

> The `content` of the built-in plugins **contains example credentials** (e.g. `admin/admin123` in basic-auth). These are **example values from the official template — never copy them into production**.

### 3.8 Users `/users`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| GET | `/users` | User list | 🔴 High risk |
| POST | `/users` | Create a user | 🟠 Caution |
| POST | `/users/login` | Log in (exchange for a JWT); the body contains `usr`/`pwd`/`otp` | 🟠 Caution |
| DELETE | `/users/{id}` | Single delete (**no body**) | 🟠 Caution |

**User object fields**: `id` `usr` (username) `pwd` `role` (int) `fail` (number of failed logins) `otp_url` (**embeds the plaintext TOTP secret**) `enable_otp` (bool) `pwd_expiration` (int) `pwd_expired_at` `updated_at`.

**`role` enum**: `0` = administrator / `1` = operator / `2` = auditor.
**`pwd_expiration` enum**: `0` = unlimited / `45` / `90` / `180` (days).
🔴 `GET /users` returns `otp_url`, which **embeds the plaintext TOTP secret**; `pwd` is a password field and must be **treated as sensitive**. After reading them, do not write to disk or echo back.

### 3.9 System Settings `/setting`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| GET | `/setting` | Global configuration | 🔴 High risk |
| PUT | `/setting` | Update the global configuration | 🟠 Caution |
| GET | `/setting/waf` | Data-plane nginx parameters (8 sections, see `configuration.md` §15) | — |
| PUT | `/setting/waf` | Update the data-plane nginx parameters | 🔴 High risk |
| GET | `/setting/license` | License information `{expiration, version}` | — |
| GET | `/setting/latestVersion` | Latest version `{version}` | — |
| GET | `/setting/lang` | **Read** the current language: `{"language":"zh"}` (**changing the language is not here**; use the `language` field of `PUT /setting`) | — |
| GET | `/setting/update` | **Triggers an upgrade — a GET is the action, not a read-only call**; on success the front end auto-refreshes after 3 seconds. **Not available under a community-edition Docker deployment** (upgrades go through updating the image) | 🔴 High risk |
| GET | `/setting/backupConfig` | Download a configuration backup: `content-disposition: attachment; filename="backup.json"`, `application/json` (**contains plaintext `dsn`/`jwt_key`/`api_token`**) | 🔴 High risk |
| GET | `/setting/backupDB` | Download a database backup: `filename="backup.sql"`, `application/octet-stream` | 🔴 High risk |
| POST | `/setting/recoverConfig` | **Restore the configuration: multipart, field name `file` (single file)** ⚠️ destructive | 🔴 High risk |
| POST | `/setting/recoverDB` | **Restore the database: multipart, field name `file` (single file)** ⚠️ destructive | 🔴 High risk |

> ⚠️ **This group contains "action endpoints disguised as read-only ones"**: `GET /setting/update` **triggers an upgrade on a plain GET** (it is not a query), so do not call it casually as if it were an ordinary GET;
> `GET /setting/lang` is the truly read-only one (changing the language uses the `language` field of `PUT /setting`, exactly as the panel's settings page does) — it **only changes the UI language, not the content of the built-in rules/plugins already in the database** (the content language is fixed by the image and by the language seed used at deployment; see `deployment.md` §1 "Chinese edition / English edition").
> The output of `backupConfig` contains **plaintext credentials**, and `recoverConfig`/`recoverDB` are **destructive** restores — treat both the resulting files and the calls themselves as sensitive/dangerous.
| GET | `/setting/ipBlock/all` | All IP ban records (clicking "Export" in the front end downloads `ipblock.jsonl`; the body is **JSONL**, one object per line, and an empty list is `{}`, **not a JSON array**) | — |
| PUT | `/setting/ipBlock/{action}` | Perform an action on an IP, body `{"ip":"<IP>"}` | 🟠 Caution |

**`GET /setting` fields** (v7.2.5): `id` (node identifier, str) `addr` (admin address) `dsn` `jwt_key` `jwt_expiration` (seconds) `waf_nodes` (array, elements like `"127.0.0.1:4447"`) `ml_server` `ml_token` `api_token` `log_db` (bool) `log_level` (`error`/`info`/`debug`) `language` `version`. 🔴 Among them `dsn`/`jwt_key`/`api_token`/`ml_token` **are all sensitive values** (handling see below in §3.9 and `pitfalls.md` §2).

> 🔴 **`ipBlock` has four `{action}` values in total** (v7.2.5):
> - `check`: query a single IP, returns `{"locked":bool}`; `unlock`: release a single one, returns `"OK"`; `unlockAll`: release all of them, returns `"OK"` (an empty body is also fine). The UI button uses `PUT` with body `{"ip":"<IP>"}`.
> - `checkAll`: **not used by the UI** — the panel's "query all / export" actually downloads `GET /setting/ipBlock/all` (JSONL, see the table above) rather than calling this endpoint. Calling it with a valid ip also returns `"OK"`; the semantics are unclear, so **do not rely on it**.
> - All three PUT actions **validate the ip first**: empty or invalid → `{"err":"IP format error"}` (returned with 200, not 4xx, so do not judge success by the status code alone).
> ⚠️ **There is no action such as "toggle lock"**: `check` only queries the state; **to unban, always use `unlock`** (in bulk, `unlockAll`).

> **Data source**: the IP ban list lives in the Lua **shared memory dict `ipBlock`** (written automatically by the engine when a rule blocks), **not in the database**; there is **no Redis** inside the container.
> **TTL = 600 seconds (10 minutes)**: every rule block resets the TTL; once blocking stops being triggered it naturally decays to zero. To unban immediately, use `unlock` (in bulk, `unlockAll`).

> 🔴 **`GET /setting` returns sensitive fields**: the database connection string (including the password), `jwt_key`, `api_token` and `ml_token`.
> **Obtaining this endpoint's response is equivalent to holding panel privileges** (you can connect straight to the business database and forge tokens). Hard rules:
> - do not write to disk, do not echo back, do not write into persona files;
> - when display is needed, mask field by field;
> - only authorized clients may call it.

### 3.10 CDN Cache `/cdn`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| PUT | `/cdn` | Update/create (front end: `id===0?"POST":"PUT"`; note that the front end writes `/cdn`) | 🟠 Caution |
| DELETE | `/cdn` | Bulk delete (body `{keys:[id…]}`) | 🟠 Caution |
| DELETE | `/cdn/purge` | Purge the cache (**no parameters**) | 🟠 Caution |

**CDN object fields** (front-end defaults): `id` `host` (domain) `uri` (**regex-based URL path**, default `"/.*"`, e.g. `"/.+\\.(?:css\|js\|jpe?g\|png\|webp\|avif\|woff2?\|eot\|...)$"`) `cache_time` (str, default `"1h"`; units `s`/`m`/`h`/`d`/`M`/`y`) `enabled` (**bool**, on/off switch).

- The cache status is reflected by the response header `X-Waf-Cache: HIT / MISS`.
- The WAF's own cache purge **supports regex matching on URL paths** (better than the nginx commercial edition, which only supports `*` wildcards).

### 3.11 Machine Learning `/ml`

| Method | Path | Description | Risk |
|:---|:---|:---|:---|
| GET | `/ml` | ML model list | — |
| PUT / DELETE | `/ml` `/ml/purge` | Management | 🟠 Caution |

> On the community edition a call returns "please upgrade to the commercial edition". ML is used for anomalous-traffic identification; it can automatically learn the parameter characteristics of normal traffic and generate a whitelist rule library.

---

## 3-2. Authoritative Source for Fields and Enums (Reproducible)

The **types, enum values and defaults** in this document are not guesses — they come from the panel front-end implementation and can be re-extracted and verified at any time:

```bash
TOKEN=$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.config/waf-hosts.json')))['<instance name>']['token'])")
B=https://<panel address>:4443

# 1) index page -> the main bundle references all chunks (the business chunk names are all here)
curl -sk -H "Api-Token: $TOKEN" $B/ | grep -oE 'assets/[a-zA-Z0-9_.-]+\.js'
# 2) main bundle (contains the i18n Chinese dictionary = official field names + enum labels)
curl -sk -o /tmp/index.js $B/assets/index-<hash>.js
# 3) endpoint -> method mapping (url + method co-occur)
grep -oE 'url:\s*"[^"]+"\s*,\s*method:\s*"[A-Za-z]+"' /tmp/*.js
# 4) single-delete form (path concatenated with id)
grep -oE '"/[a-z]+/"\s*\+' /tmp/*.js
```

**Criteria and pitfalls**:

- **The front-end JS is the primary source for enum values** (`{label:…,value:"…"}`); both the official docs and the i18n key names may be **inconsistent with the live values** (e.g. the load-balancing `type` is `roundrobin`/`chash`/`swrr` live, rather than the i18n `roundRobin`/`ipHash`/`SWRR`).
- **Field types follow the real response** (`GET /sites`, etc.); do not infer a type from i18n label text (`mode` looks like an int but is actually a bool).
- Panel version: **v7.2.5** (the `version` returned by `GET /setting/license`). After a version change, re-extract and verify using the method above.

---

## 4. Error Shapes

| Symptom | Response | Troubleshooting |
|:---|:---|:---|
| Wrong token | `{"message":"missing or malformed jwt"}` | Check the token character by character |
| Used GET to query logs | `{"message":"Not Found"}` | Switch to `POST /logs` |
| Empty nodes when writing a rule/plugin | `No waf nodes` | `waf_nodes` in `config.json` must be non-empty |
| Body type mismatch | `{"err":"code=400, message=Unmarshal type error: expected=web.LogQuery, got=string, ..."}` | `query` must be an **object**, not a string |
| Query returns 0 entries and no error | `{"data":[],"total":0}` | First check whether the time format carries hours, minutes and seconds |
| Deleting the default ruleset | Rejected | The default set cannot be deleted |
| JSON parsing reports `Expecting value` | The response body carries a **UTF-8 BOM** | Endpoints such as `/setting/ipBlock/all` return `\ufeff[...]`, which must be decoded with `utf-8-sig` (the script already handles this) |

---

## 5. Script Usage

The skill ships with `scripts/waf.py` (pure standard library, no third-party dependencies, supports multiple instances). For usage see `SKILL.md`.

```bash
python3 scripts/waf.py hosts                        # list all configured instances
python3 scripts/waf.py -i <name> ping               # connectivity + auth self-check
python3 scripts/waf.py -i <name> list sites|rules|ruleset|certs|plugins|users
python3 scripts/waf.py -i <name> api GET  /ruleset
python3 scripts/waf.py -i <name> api POST /logs '{"page":1,"page_size":20,"query":{"level":5,"time_range":[]}}'
python3 scripts/waf.py -i <name> logs -q '{"level":5,"host":"example.com"}'   # log query wrapper

# write paths (no need to hand-write Python)
python3 scripts/waf.py -i <name> get rule <ID> [--field content] [--out <file>]   # fetch the body to a file (CRLF preserved)
python3 scripts/waf.py -i <name> push rule <ID|new> --file <file> [--dry-run]      # write the body back (PUT/POST)
python3 scripts/waf.py -i <name> push ruleset <ID> [--set|--add|--remove …]      # change the enablement list
python3 scripts/waf.py -i <name> ipblock [--check <IP> | --unlock <IP> | --check-all | --unlock-all]                         # ban list / unban
python3 scripts/waf.py -i <name> backup [config|db] [--out <file>]                 # pre-change backup (written as a 600-permission file)
python3 scripts/waf.py -i <name> delete rule|ruleset|cert|plugin <ID> [--dry-run] # delete (production write; obtain authorization first)
python3 scripts/waf.py -i <A> diff rule|ruleset <ID> --with <B>                   # cross-instance byte-level comparison (md5/CRLF/diff)
```

> The script automatically skips self-signed certificate verification; the token is read by the script from the config file / environment variables and **never passes through the model context**.
> The bodies for `get` / `push` are transferred via a **file** (not inlined into the shell), and writing to disk uses `newline=""` so that CRLF ↔ LF does not drift.
> Response decoding always goes through `utf-8-sig` (some endpoints carry a BOM, e.g. `GET /setting/ipBlock/all`, otherwise `json.loads` fails).
