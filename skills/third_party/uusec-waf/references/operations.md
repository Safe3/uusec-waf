# Installation, Operations and Troubleshooting

> Official installation and FAQ source: `offline-docs/install.md`, `offline-docs/faq.md`.
> Deployment topology, the official compose and database usage: `deployment.md`.

---

## 1. Installation

### Requirements

| Item | Requirement |
|:---|:---|
| Processor | 64-bit 1 GHz or faster |
| Memory | ≥ 2 GB |
| Disk | ≥ 8 GB |
| Software dependencies | Docker CE ≥ 20.10.14, Docker Compose ≥ 2.0.0 |

> Prefer a **clean Linux x86_64** server. uuWAF runs in **cloud WAF reverse-proxy mode** and occupies ports **80 / 443** by default.

### One-line install

```bash
sudo bash -c "$(curl -fsSL https://waf.uusec.com/zh-cn/installer.sh)"
```

Installation directory `/opt/waf/`, management script `bash /opt/waf/manager.sh` (start / stop / update / uninstall).

> If Docker Engine cannot be installed automatically, install it manually. A copy of the official script is in `offline-docs/examples/manager.sh`.

### Five-step quick start

1. **Log in to the backend**: `https://<server IP>:4443`, default username `admin`, password `#Passw0rd`.
2. **Add a site**: Site management -> Add site -> fill in the site domain and the web server IP.
3. **Add an SSL certificate**: Certificate management -> Add certificate -> upload the certificate and private key; if you have none, you can request a free Let's Encrypt certificate with automatic renewal.
4. **Change the DNS target**: change the domain's A record to the uuWAF server IP.
5. **Test connectivity**: visit the site domain and confirm that the `server` field in the response headers is `uuWAF`.

> 🔴 **Harden immediately after deployment** (explicitly required by the official docs):
> 1. Create a new admin user with a **hard-to-guess username**;
> 2. **Delete the default `admin` user**;
> 3. **Enable the one-time password (TOTP)**.
>
> Note: uuWAF's TOTP uses the **HMAC-SHA256** algorithm and is **incompatible with ordinary OTP clients**. The official recommendation is Google Authenticator on iOS and FreeOTP on Android (`https://waf.uusec.com/freeotp.apk`).

---

## 2. Containers and Directory Structure

> The full official compose is in `deployment.md` §2.

```
/opt/waf/
├── manager.sh                 container management script
└── docker-compose.yml

Inside the container /uuwaf/ (the main items are listed below)
├── conf/                      data-plane nginx configuration
│   ├── uuwaf.conf             main config (listen, shared dicts, Lua phase hooks)
│   ├── listen.conf            listening ports (80 / 443; 443 uses http2)
│   ├── proxy.conf             origin proxy headers and timeouts
│   ├── ssl.conf               TLS protocols and cipher suites
│   ├── cache.conf             CDN cache
│   ├── gzip.conf              compression
│   ├── log.conf               logging
│   ├── error_page.conf        error pages
│   ├── resolver.conf          DNS
│   ├── cert/                  certificates
│   ├── geoip.mmdb             GeoIP database (60MB)
│   └── (shipped with nginx: mime.types, fastcgi/scgi/uwsgi params, etc.)
├── web/conf/
│   ├── config.json            control-plane configuration (contains sensitive fields)
│   ├── server.crt / server.key the console's own certificate
│   └── rootCA.crt / rootCA.key root CA
├── waf/plugins/*.w            built-in detection modules (plaintext Lua)
├── captcha/images/            CAPTCHA image pool
├── acme/  html/               ACME verification and error pages
├── logs/                      logs (including error.log)
├── sbin/uuwaf                 the nginx main program
├── luajit/bin/luajit-*        bundled LuaJIT (can do offline syntax validation)
├── waf-service                Go service (control plane + embedded frontend)
└── lego                       ACME client (about 70MB)
```

---

## 3. Changing Configuration

| What to change | Location | How it takes effect |
|:---|:---|:---|
| Admin backend port / SSL certificate | `addr` in `/uuwaf/web/conf/config.json`; replace `server.crt` / `server.key` in the same directory | **Restart** |
| Reverse-proxy listening port | `/uuwaf/conf/uuwaf.conf` (`listen.conf`), using nginx `listen` syntax; in the Docker edition change the compose port mapping | **Restart** |
| CAPTCHA image pool | Put PNGs into `/uuwaf/captcha/images/` | **Restart** |
| Sites / rules / rulesets / certificates / plugins | The panel (REST API) | **Takes effect immediately** |
| Cache acceleration configuration | The CDN menu in the panel | Takes effect immediately |

> **The vast majority of configuration takes effect immediately without a restart**. Only the listening ports, the console certificate and the CAPTCHA images need a restart.

### Reading the control-plane configuration (read-only reference)

Fields of `/uuwaf/web/conf/config.json` (**measured field names**):

| Field | Meaning |
|:---|:---|
| `id` | Node ID (i.e. the value of the upstream header `X-Waf-Id`), **used in cluster mode to distinguish the source** |
| `addr` | Console listening address, default `:4443` |
| `dsn` | 🔴 Database connection string (contains the password) |
| `jwt_key` | 🔴 JWT signing key |
| `jwt_expiration` | JWT lifetime |
| `waf_nodes` | List of data-plane node addresses (e.g. `["127.0.0.1:4447"]`), **must be non-empty to write rules/plugins** |
| `ml_server` | ML service address |
| `ml_token` | 🔴 ML service token |
| `api_token` | 🔴 **the Api-Token of the console REST API** |
| `log_db` | Whether logs are recorded to the database |
| `log_level` | Log level |
| `language` | UI language |
| `version` | Version number |

> 🔴 The four marked items are **sensitive data**: never write them to disk, never echo them back, never write them into persona files, never transmit them through the conversation.

### Log files

| File | Contents |
|:---|:---|
| `/uuwaf/logs/error.log` | Lua error log (the target of `waf.errLog` / `log.errLog`) |
| The rest of `/uuwaf/logs/` | Access and runtime logs |

> The data plane has `access_log off`; **logs mainly go to the database** (`log_db: true`) and are queried through the panel or the REST API. The configuration file `error.log` rotates daily (`error.log-YYYYMMDD.gz`; logrotate is measured to be configured).

---

## 4. Upgrades and Backups

- Update: `bash /opt/waf/manager.sh` (it includes an update option). ⚠️ That script **overwrites `docker-compose.yml`** -- back up any customizations yourself; and it **pulls the compose from the script's own language channel** (the Chinese channel pulls `waf.uusec.com/zh-cn/docker-compose2.yml`, the English channel pulls the root-path version) -> changing language/image means changing `manager.sh` along with it (see `deployment.md` §1 "Chinese edition / English edition").
- Backup: console "System settings -> Backup configuration / Backup database"; the APIs are `GET /setting/backupConfig`, `GET /setting/backupDB`.
- 🔴 **Before a cross-major-version upgrade you must check the version watershed** (see `internals.md` §10):
  - **v7.2.0 is incompatible with older rule versions and does not support a direct upgrade from an older version**.
  - v4.1.0 changed the plugin phase function names (old names `req_filter` etc. -> new names `req_pre_filter` etc.).
- Before upgrading, it is advisable to: export a configuration backup + record the current ruleset contents + record the body of custom rules.

---

## 5. Common Issues Quick Reference (official FAQ + additions)

### 5.1 Visiting a website shows a block page with rule ID `-1`

When a domain **is not configured in site management**, uuWAF blocks access to that domain by default -- to prevent the legal risk caused by "a rogue domain pointing at the server".

**Handling**: add the domain to a site.

### 5.2 How to obtain the real client IP after passing through uuWAF

When forwarding, the WAF injects `X-Waf-Ip` (the real client IP); `X-Forwarded-For` can also be used.

**Priority**: `X-Waf-Ip` > `X-Forwarded-For`.

**On the WAF side**: `ip_source` / `ip_order` / `ip_header` in the site configuration determine the value of `waf.ip`; **misconfiguration disables all IP-based protection**.

### 5.3 In cluster mode, how does an upstream distinguish which uuWAF the traffic came from

Read `X-Waf-Id` (the value = the `id` in each node's `config.json`).

### 5.4 How to tell whether a page is cached by the CDN

Look at the `X-Waf-Cache` response header: `HIT` = cached, `MISS` = not cached.

### 5.5 Certificate request fails

- HTTP-01 validation: requires **port 80 reachable from the public internet**.
- DNS-01 validation: no such restriction and wildcard domains are possible, but **DNS propagation takes time**.
- Let's Encrypt **has a limited number of requests per month**; too frequent and it fails.

### 5.6 Too few CAPTCHA images

Put PNGs into `/uuwaf/captcha/images/`; it takes effect after **restarting the service**.

### 5.7 A rule does not take effect

See `rule-authoring.md` §7 "Troubleshooting order".

### 5.8 A plugin makes the site error out

First check whether the plugin references **parameters that were not passed in** (such as `waf.scheme` and similar values that must be passed explicitly rather than being globally visible).

---

## 6. Diagnostic Channel Discipline

| Channel | Purpose | Safety |
|:---|:---|:---|
| **Console REST API (4443)** | Query logs, rules, sites, bans | ✅ **First choice during diagnosis**; it does not go through the data plane |
| **Panel Web** | Manual viewing and operations | ✅ |
| **Database (read-only)** | Query raw records / fields not exposed by the panel API | ✅ Read-only queries are safe; 🔴 **unauthorized write operations are strictly forbidden** (including for testing / cleanup) |
| **Shared memory dict (Lua side)** | Ban list (`ipBlock`), access counters (`ipCache`) | ✅ Read-only is safe |
| **🔴 WAF data plane (80/443)** | Reproducing issues with crafted requests | ❌ **Forbidden** -- see `pitfalls.md` |

> 🔴 **The database read-only red line**: write operations such as `INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`/`TRUNCATE` are all forbidden, and log cleanup is included in that; logs produced by testing are kept as they are and their source is annotated. Write operations require authorization first (content + blast radius + rollback).
>
> **Ban state lives in the Lua shared memory dict `ipBlock`, not in the database**. There is **no Redis** in the container.
> To check or lift bans, use "IP ban" in the panel: `GET /setting/ipBlock/all` to fetch the list, `PUT /setting/ipBlock/unlock` to unban (`check` only queries the state).

---

## 7. Rule Incident Response Plan (a broken rule -> stop the bleeding within 5 minutes)

**Symptoms**: after a new rule goes live it blocks legitimate business / a path goes down entirely / the whole site returns 403.

**Do these in order; the first two take effect immediately**:

| Step | Action | Effect | Command / location |
|:--|:---|:---|:---|
| 1 | Set the site `mode` to `false` (observation mode) | **Stops blocking immediately** (logs are still recorded, which helps with diagnosis) | `PUT /sites` (with `id`), or the site switch in the panel |
| 2 | Remove that rule ID from the ruleset used by the site | The rule stops working immediately | `waf.py -i <instance> push ruleset <ruleset ID> --remove <rule ID>` |
| 3 | Roll back the rule body | Restores the original state | `waf.py -i <instance> push rule <ID> --file <pre-change backup>` |
| 4 | Find the root cause | Prevents a repeat | Check `rule_id` + `exploit` in `waf_logs` to identify which criterion fired |

**Key facts**: changes to rules / sites / rulesets **take effect immediately, no restart needed**; only the listening ports, the console certificate and the CAPTCHA image pool need a restart.
So steps 1 and 2 stop the bleeding in seconds -- **stop the bleeding first, do not agonize over the cause first**.

> 🔴 Corollary: **put a new rule into `RULE_LOG_ONLY` before it goes live**, which saves you one incident from this playbook.
> After the post-mortem, write "why it false-positived" into the rule comments (narrow the criterion); do not just change the condition without leaving a trace.
> You can also simply wait for the `ipBlock` TTL (10 minutes) to expire -- as long as no block is triggered in the meantime.
