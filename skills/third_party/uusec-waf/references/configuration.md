# Feature Configuration Guide

> Covers the two scenarios **"a user asking how to configure a feature"** and **"help me configure a feature"**.
> Every item gives: panel path -> API (scriptable) -> key fields -> caveats.
> Obtain authorization before write operations; after a change, **verify against the state that is actually in effect**, not just the API return code.

---

## 1. General Workflow

```
Confirm the target (which WAF / which site)
  -> Check the current state (read-only script: waf.py -i <instance> list ...)
  -> Present the intended change and its blast radius
  -> Obtain authorization
  -> Execute
  -> Verify (read the config back + validate with a real request)
```

**Script**: `scripts/waf.py` (usage in `SKILL.md`). Back up before changing:

```bash
python3 <skill>/scripts/waf.py -i <instance> api GET /setting/backupConfig > /tmp/waf-backup-$(date +%F).json
```

---

## 2. Onboarding a Site

**Panel**: Site management -> Add site

| Field | Description |
|:---|:---|
| Domain (`hosts`) | Supports multiple domains and the wildcard `*` (e.g. `example.com`, `*.example.com`) |
| Upstream servers (`servers`) | `{ip, port, weight}`; multiple backends are load-balanced according to `mode` |
| Load-balancing mode | `roundRobin` = weighted round robin / `ipHash` = consistent hashing / `SWRR` = smooth weighted round robin |
| **Client IP source** (`ip_source`/`ip_order`/`ip_header`) | 🔴 **Must be configured**: determines the value of `waf.ip`. Misconfigured behind multiple proxy layers -> **every IP-based protection (CC / brute force / ban) fails entirely** |
| Custom Host (`custom_host`) | Rewrites the `Host` header on origin fetch |
| Ruleset (`ruleset_id`) | Which ruleset to attach |

**API**: `GET /sites` to read, `POST /sites` to create, `PUT /sites` to update (with `id`), `DELETE /sites` to bulk-delete `{keys:[...]}`.

**Verification**: `curl -I https://<domain>` -> the `server` response header should be `uuWAF`.

> ⚠️ A domain **with no site configured** is blocked by default, returning a block page with **rule ID = -1** (to guard against the legal risk of a rogue domain pointing at the server). Seeing `-1` means "the site has not been added".

---

## 3. Configuring an SSL Certificate

**Panel**: Certificate management -> Add certificate / Request certificate

| Method | Key points |
|:---|:---|
| Upload | Fill in `crt` + `key` (PEM) |
| Let's Encrypt (HTTP-01) | Requires **port 80 reachable from the public internet**; **the number of requests per month is limited** |
| Let's Encrypt (DNS-01) | Can request **wildcard domains**; requires waiting for DNS propagation; `dns_provider` + `dns_credential` |
| Wildcard certificate | A `*` certificate can cover all domains (v6.7.0+) |

**API**: `GET /certs`, `POST /certs`, `PUT /certs` (with `id`), `DELETE /certs` for bulk delete.

🔴 `GET /certs` returns `key` (**the private key in plaintext**) and `dns_credential` (DNS credentials) -- never write them to disk, never echo them back.

---

## 4. IP / URL Allowlist (site level)

**Panel**: Site configuration -> IP address allowlist / URL path allowlist

| Item | Format |
|:---|:---|
| `ip_whitelist` | A single IP or a **CIDR range** |
| `url_whitelist` | Route expressions: `/foo/*`, `/foo/*action`, `/foo/:name` |

**API**: `PUT /sites` (with `id`).

> ⚠️ A site-level allowlist has **whole-site pass-through** semantics: once an IP or path allowlist is added to a site, **that site no longer goes through any rule** (it is not "skip just one rule"). If you only want to open a hole for individual requests, change the **rule** to make an exact exception (see `rule-authoring.md` §4.7); do not use the site allowlist.

---

## 5. Observation Mode (log only, never block)

Three levels, from smallest to largest blast radius:

| Level | How to configure | Granularity |
|:---|:---|:---|
| **Single rule** | `return waf.RULE_LOG_ONLY, "reason"` inside the rule (v7.2.0+) | Smallest |
| **Ruleset** | Disable one rule inside the ruleset (`PUT /ruleset`) | That site |
| **Whole site** | The site's `mode` field (`PUT /sites`) | Largest |

**Recommended canary path**: put a new rule into `RULE_LOG_ONLY` first -> compare the observed logs -> once you are sure there are no false positives, switch it to `RULE_BLOCK`.

> ⚠️ Under site-level observation mode, logs are still recorded even when a rule returns `RULE_ALLOW`; so when **the allowlist appears not to work**, first confirm whether the site is in observation mode.

---

## 6. Ban List Management and Unbanning

**Panel**: IP ban

| Operation | Endpoint |
|:---|:---|
| View the list | `GET /setting/ipBlock/all` |
| Query one IP's ban state | `PUT /setting/ipBlock/check`, body `{"ip":"<IP>"}` -> `{locked: bool}`; **use `unlock` to unban** |
| Export the list | The same URL downloads `ipblock.jsonl` as a blob |

**Data source**: the Lua shared memory dict `ipBlock` (**not in the database, and there is no Redis in the container**).

**Self-healing**: the **TTL of an `ipBlock` entry is 600 seconds (10 minutes)**; a rule block resets the TTL; **once you stop triggering blocks it clears by itself**.
> A ban that feels like it "will not lift" is usually because **requests that keep getting blocked are still being generated**, refreshing the TTL. Stop making requests, or unlock manually as in the table above.

---

## 7. CC / Rate Protection

**Two paths**:

| Path | Location | Characteristics |
|:---|:---|:---|
| **Built-in rule 66 "Anti-CC attack rule" / 68 "Bot attack protection" / 70 "High-frequency error protection"** | Rule management | Works out of the box, executed in ascending ID order |
| **The `cc_protection` plugin** | Plugin management | Powerful and fine-grained (site-level thresholds, path-level rate limiting, origin circuit breaking, IP global rate limiting) |

**Configuration dimensions of the plugin version** (the Lua lives in `plugins[].content`; the tunables are hoisted to the front):

| Config block | Purpose |
|:---|:---|
| `enableCCProtection` | Master switch |
| `enableOriginCircuitBreaker` / `originCircuitBreaker` | **Origin circuit breaker**: globally counts the total number of requests about to go upstream and, once exceeded, temporarily blocks all requests (protects the origin's total capacity) |
| `enableGlobalRateLimit` / `globalRateLimit` | **IP global rate limiting**: counted per IP across sites (coarse filtering) |
| `enableSiteRateLimit` / `siteDefault` / `siteConfigs` | **Site-level rate limiting**: counted independently per Host; `siteConfigs` overrides per domain |
| `enablePathRateLimit` / `pathRules` | **Precise path rate limiting**: rate-limits separately per Host + path prefix |

**Tuning notes**:

- `threshold` / `timeWindow` / `banDuration` must be understood as a set of three.
- `countStatic`: whether static assets count toward the tally (**sites with many static assets should set this to false**, otherwise ordinary browsing alone triggers it).
- **Allow search engines**: the official rules use `waf.searchEngineValid({"180.76.76.76"}, waf.ip, waf.userAgent)` to exclude real search engines so indexing is not affected -- hand-written CC rules should do the same.

**API**: `GET /plugins` to get `content` -> change the parameters -> `PUT /plugins` (with `id`; requires `waf_nodes` to be non-empty).

---

## 8. Human Verification (CAPTCHA)

| Method | Endpoint |
|:---|:---|
| Slide-and-rotate CAPTCHA (built-in) | `waf.checkRobot(waf, expireTime?, max?)`, default 600 seconds / 18000 times |
| Cloudflare Turnstile | `waf.checkTurnstile(waf, siteKey, secret, expireTime?, max?)` |
| Built-in rule 71 | "Turnstile human verification" |

🔴 **When using human verification you must allow the resources the verification page needs**: `/static/` and `/api/v1/captcha/`
-- otherwise the verification page's CSS/JS is blocked and the page cannot render (it looks like "stuck on the verification page").

**CAPTCHA image pool**: put PNGs into the container's `/uuwaf/captcha/images/`; it takes effect after **restarting the service**.

---

## 9. CDN Cache Acceleration

**Panel**: Cache acceleration

| Operation | Endpoint |
|:---|:---|
| Update the CDN configuration | `PUT /cdn` |
| Purge the cache | `DELETE /cdn/purge` |

- Cache status is visible in the response header **`X-Waf-Cache: HIT / MISS`**.
- uuWAF's self-developed cache purge **supports regex matching on URL paths** (better than nginx commercial, which only supports `*` wildcard matching).
- Cache is written to `/tmp/disk_cache_uuwaf`, `max_size=8g`, `inactive=60m`.

---

## 10. Custom Block Page

**Panel**: Site configuration -> Block page (`deny_page`).

**API**: `PUT /sites` (with `id`).

---

## 11. One-Time Password (TOTP)

**Panel**: System settings -> User management -> Enable one-time password (`users[].enable_otp`).

🔴 uuWAF's TOTP uses **HMAC-SHA256** and is **incompatible with ordinary OTP clients**.
Official recommendation: **Google Authenticator** on iOS, **FreeOTP** on Android (`https://waf.uusec.com/freeotp.apk`).

---

## 12. Cluster and Nodes

**Panel**: System settings (the `id` and `waf_nodes` of `config.json`).

- `waf_nodes`: the list of data-plane node addresses (default `["127.0.0.1:4447"]`). **Writing rules/plugins requires it to be non-empty**, otherwise it reports `No waf nodes`.
- `id`: the node ID, i.e. the value of the upstream header **`X-Waf-Id`**; **in cluster mode it distinguishes which node a request came from**.
- Upstreams obtain the real client IP from **`X-Waf-Ip`**.

> Cluster management is a **Professional / Commercial edition** capability; the Community edition is single-node only.

---

## 13. Regional Access Control

| Method | Description |
|:---|:---|
| Built-in rule 69 "Region access restriction" | Works out of the box |
| `waf.ip2loc(waf.ip, "zh-CN")` inside a rule | Returns `country, province, city, iso`; the policy is up to you |

---

## 14. Verifying and Rolling Back Configuration Changes

| Item | Practice |
|:---|:---|
| **Back up before changing** | `GET /setting/backupConfig` (configuration), `GET /setting/backupDB` (database) |
| **Verification** | Read the config back + **actually send a request that should hit / should pass**, not just check for API 200 |
| **Rollback** | Rules: restore the body with `PUT /rules`; rulesets: restore the array with `PUT /ruleset`; sites: `PUT /sites` |
| **Changes that need a restart** | Listening ports, console certificate, CAPTCHA image pool; **everything else takes effect immediately** |
| **Observation window** | After a production change, stay in `RULE_LOG_ONLY` or observation mode for a while before tightening |

> 🔴 **Forbidden**: verifying by sending crafted requests to the WAF data plane (it triggers rule 13 bans). See `pitfalls.md` §1.

---

## 15. Data-Plane nginx Parameters (`/setting/waf`, editable via API)

The panel exposes the data plane's nginx parameters as **8 text segments**, each corresponding directly to one configuration file inside the container -- **editing here is editing nginx, but without entering the container** (the measured fields map one-to-one onto the files on disk):

| Field | File on disk | Contents / commonly changed items |
|:---|:---|:---|
| `resolver` | `/uuwaf/conf/resolver.conf` | DNS resolver (default `180.76.76.76 valid=30s ipv6=off`) -- change this when the upstream is written as a domain name |
| `listen` | `/uuwaf/conf/listen.conf` | Listening ports / http2 / IPv6 (default `80 default_server` + `443 ssl http2`) |
| `ssl` | `/uuwaf/conf/ssl.conf` | Protocols and cipher suites; **HSTS is already written but commented out -- remove the `#` to enable it**; the legacy-client compatibility combination is also in the comments (note that HTTP/2 requires TLSv1.2+) |
| `gzip` | `/uuwaf/conf/gzip.conf` | Compression switch / level / type allowlist |
| `cache` | `/uuwaf/conf/cache.conf` | `proxy_cache` behavior, the `X-Waf-Cache` response header, the force-cache switch (commented out by default) |
| `proxy` | `/uuwaf/conf/proxy.conf` | Timeouts (default `proxy_read_timeout 600s`), buffers, forwarded headers, hidden headers |
| `error_page` | `/uuwaf/conf/error_page.conf` | Custom 404 / 50x error pages |
| `log` | `/uuwaf/conf/log.conf` | Data-plane `access_log` (commented out/off by default; logs mainly go to the database) |

**How to change**: `GET /setting/waf` to fetch the current full text -> edit -> `PUT /setting/waf` to write it back.
**Before you start**: `waf.py -i <instance> backup config` first. This is **global data-plane configuration; a mistake affects every site**.
**Only change it here**: do not `docker exec` into the container to edit the conf files directly -- the panel overwrites them when it writes back.

Common scenarios:

| What you want to do | Which segment to change |
|:---|:---|
| Slow upstream / large downloads that break off | `proxy`: increase `proxy_read_timeout` (default 600s) and `proxy_buffers` |
| Add HSTS | `ssl`: remove the `#` before `add_header Strict-Transport-Security …` |
| You need nginx access logs | `log`: remove the `#` from `#access_log logs/access.log proxy;` |
| Support legacy clients (TLS1.0/1.1) | `ssl`: switch to the old protocol/cipher combination in the comments (you lose HTTP/2) |
| Change DNS / use a domain name for the upstream | `resolver`: switch to your own resolver address |
| A page is stuck in cache | `cache`: tune `proxy_cache_bypass` / `proxy_cache_valid`, or enable the force-cache segment |

> ⚠️ **This is the highest-risk class of change**: a mistake in `listen` / `ssl` **takes down HTTPS for every site immediately**.
> Before changing these two segments, record the original text and confirm that the console (panel) and the data plane are **not the same layer** (the panel on 4443 is unaffected and you can still get in to change it back).
> After the panel saves `PUT /setting/waf`, the engine rewrites the conf files above and **reloads nginx automatically** -- no manual restart or container access needed.
