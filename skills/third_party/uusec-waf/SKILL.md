---
name: uusec-waf
description: "Full capabilities of UUSEC WAF (Nanqiang): deployment, operations, site/certificate/allowlist/CC protection/CDN configuration, rule and plugin authoring and debugging, and console REST API management. Trigger words: WAF, Nanqiang, uuwaf, rule, plugin, false positive, CC."
compatibility: "Requires bash and python3 (3.8+, standard library only). pcrecheck.py needs the system libpcre2; wafcheck.sh needs the container on the WAF host. The management API requires network reachability to panel port 4443."
---

# UUSEC WAF (Nanqiang)

An industrial-grade open-source WAF (WAAP), based on the **nginx + OpenResty ecosystem + LuaJIT**, using the **cloud WAF reverse proxy** model: traffic reaches Nanqiang first, is inspected by it, and is then fetched from the origin.

## Capability Scope

| Area | Content | Entry point |
|:---|:---|:---|
| **Installation and deployment** | One-click install, hardening, site onboarding, certificates | `references/operations.md` |
| **Deployment and database** | Deployment forms, official compose, DSN and database usage, startup order, upgrades | `references/deployment.md` |
| **Chinese edition / English edition** | Two language channels, two images, `UUWAF_LANGUAGE`, language fixed at deployment time, update channel binding | `references/deployment.md` §1 |
| **Daily operations** | Containers and directories, changing configuration, upgrade backups, common problems | `references/operations.md` |
| **API management** | Sites / rules / rulesets / certificates / plugins / users / logs / bans / CDN | `references/management-api.md` + `scripts/waf.py` |
| **Rule development** | Rule templates, conventions, pattern library, rollout and rollback | `references/rule-authoring.md` |
| **Pre-delivery validation** | The trio: Lua syntax / regex / **semantics (API, constants, phases, hooks, modules, DSL)** | `scripts/rulecheck.py`, `pcrecheck.py`, `wafcheck.sh` |
| **Plugin development** | 5 major phases × pre/post = 10 hook functions in total, native ngx, shared memory, pattern library | `references/plugin-authoring.md` |
| **Runtime internals** | Execution order, `RULE_ALLOW` short-circuit scope, shared memory dict, log-only mode | `references/internals.md` |
| **Data plane parameters** | nginx parameters (listen / SSL / compression / cache / proxy timeout / error pages / logs), the 8 sections of `/setting/waf` | `references/configuration.md` §15 |
| **Pitfall avoidance** | Data plane prohibitions, documentation-vs-implementation mismatches, silent-failure checklist | `references/pitfalls.md` |
| **Obtaining rules/plugins** | Official built-ins, community third-party, how to contribute | The "Rules and Plugin Resources" section of this document |
| **Configuration scenarios** | User asks "how do I configure X" / "configure it for me" | `references/configuration.md` |

> 🔴 **Read `references/pitfalls.md` before you start**, especially the two sections "Do not send crafted requests to the WAF data plane" and "Credential checklist".

---

## 🚀 Getting Started (follow along for the first onboarding)

> Step 0: **Decide the language edition first** — the Chinese edition and the English edition are two channels and two images, and the language is fixed at deployment time (switching the language in the panel only changes the UI). See `references/deployment.md` §1 "Chinese edition / English edition".

1. **Configure credentials**: Copy from the panel's "System Settings → API Access Token" → write it to `~/.config/waf-hosts.json` (permission 600, format below).
2. **Connectivity self-check**: `python3 scripts/waf.py -i <instance-name> ping`; or run the whole suite at once: `bash scripts/selfcheck.sh -i <instance-name>` (6-step read-only self-check, usage below).
3. **Look at the current state before touching anything**: `list sites` / `list ruleset` / `list rules` / `logs --size 20` — first figure out "which site has which ruleset attached".
4. **Back up before changing**: `python3 scripts/waf.py -i <instance-name> backup config` (automatically writes a file with permission 600).
5. **Write rules / plugins**: Read `references/rule-authoring.md` (or `plugin-authoring.md`) → produce according to the template → **the trio of validation** (syntax / regex / semantics) → observe with `RULE_LOG_ONLY` → then switch to blocking.
6. **Stop the bleeding when things go wrong**: `references/operations.md` §7 "Rule incident emergency response" (5 minutes).

---

## Hard Requirements Before Delivering Rules/Plugins

When writing rules or plugins you **must**:

1. **Format conventions**: An opening description block (rule name / filter phase / threat level / rule description) → `-- <--- Configuration parameters --->` (tunable items grouped up front, each with a per-item Chinese comment) → `-- <--- Utility functions --->` → `-- <--- Main logic --->`.
2. **Regex validation**: The WAF uses **PCRE (PCRE1 8.45 + JIT)** with the option `"jos"`. **Every regex must be validated before delivery.** There are two channels; pick one according to your environment:

   **① Standalone `pcrecheck.py` (choose this one by default — the agent and the WAF being on different machines is the norm)**
   Pure standard library + `ctypes` binding to the system PCRE2, runs on **any machine that has Python 3**, no container needed:
   ```bash
   python3 <skill-dir>/scripts/pcrecheck.py regex '<regex>' '<test-string-1>' '<test-string-2>'
   python3 <skill-dir>/scripts/pcrecheck.py cases '<regex>' <test-string-file>   # batch comparison line by line
   python3 <skill-dir>/scripts/pcrecheck.py extract <rule-file>   # extract + validate one by one (alias: file)
   python3 <skill-dir>/scripts/pcrecheck.py lua   <rule-file>     # Lua smoke test (heuristic, not authoritative)
   python3 <skill-dir>/scripts/pcrecheck.py engine               # self-check: PCRE version/JIT/capabilities
   python3 <skill-dir>/scripts/pcrecheck.py -h
   ```

   **② Container-based `wafcheck.sh` (usable only when the local machine is the WAF host itself; highest fidelity)**
   It uses the PCRE1 inside the container — **linked against the same library** as the runtime (`libpcre.so.1`):
   ```bash
   bash <skill-dir>/scripts/wafcheck.sh engine|regex|cases|file|lua
   ```

   🔴 **Never validate with Python `re` / `grep -E`** — they are not PCRE and will give a false "everything passes" conclusion. `pcrecheck.py` would rather report "environment unavailable" than switch to `re`.
3. **Lua syntax validation**:
   - **Authoritative** (requires the WAF host): luajit inside the container → outputs `SYNTAX_OK`:
     `bash <skill-dir>/scripts/wafcheck.sh lua <rule-file>`
   - **Heuristic smoke test when there is no container**: `python3 <skill-dir>/scripts/pcrecheck.py lua <file>`
     → `BALANCED(heuristic)` or `SYNTAX_SUSPECT`. **The wording `SYNTAX_OK` is deliberately not used**: it only checks bracket/block-keyword/string closure and **does not mean the compile passed**.
4. **Complete samples**: at least 2 that should be blocked and at least 2 that should pass (**including bypass attempts such as `..`, letter case, and suffix appending**).
5. **Deliver the validation commands, the channel used, and the results together**. When using the standalone version, state honestly that it is "**PCRE2 validation**" — the WAF runtime is PCRE1 8.45 (**there are only two real differences**: the variable-length lookbehind `(?<=a{1,3})` and the bare recursion `(?R)`, see `references/rule-authoring.md` §2.2; `\K`, `(?|…)` and the like are in fact **supported on both sides**). When the local machine is the WAF host, `pcrecheck.py engine` re-checks each item with real tests against the PCRE1 inside the container.
6. **Semantic self-check (mandatory)**: `python3 <skill-dir>/scripts/rulecheck.py all <file> [--phase 0|1|2]`. Passing both the syntax and the regex checks **does not mean the rule works** — it specifically hunts the four classes of fatal errors that the syntax layer cannot catch: **nonexistent APIs, misspelled constants, variables that do not match the phase, and misuse of `ngx`/plugin variables inside a rule**; for plugins it also checks **hook names** and **whether the modules required by `require` exist**. `all` **also runs the Lua syntax and regex checks along the way** (if container luajit / local luajit is available it uses the authoritative channel, otherwise it honestly reports that it was skipped) — one command ≈ the trio. Fix any ❌ before delivering.
7. **Re-check the symbol table after a version upgrade**: `rulecheck.py symbols` compares against the official API documentation and lists the names that are "present in the docs but absent from the script's table" — if the list is not empty, it means the symbol table of `rulecheck.py` needs updating.

> For details see `references/rule-authoring.md` §1/§2/§2.2/§5; for plugins see `references/plugin-authoring.md`.

---

## Documentation Strategy: Online First, Offline Fallback

This skill provides both an **online documentation entry point** and **offline documentation copies**.

**Priority: online first** (the most up-to-date content); use the offline copies when the network is unreachable.

| Content | Online address (GitHub raw, preferred) | Offline copy |
|:---|:---|:---|
| Rule / plugin API (**authoritative**) | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/api/README.md` | `references/offline-docs/api.zh-CN.md` |
| Installation guide | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/install.md` | `references/offline-docs/install.md` |
| Getting started | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/begin.md` | `references/offline-docs/getting-started.md` |
| FAQ | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/problems.md` | `references/offline-docs/faq.md` |
| Contribution guide | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/contribute.md` | `references/offline-docs/contribute.md` |
| Product introduction / feature comparison | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/README.md` | `references/offline-docs/product-introduction.md` |
| Changelog | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/CHANGELOG.md` | `references/offline-docs/CHANGELOG.zh-CN.md` |
| Repository description | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/README_CN.md` | `references/offline-docs/README.zh-CN.md` |
| Online documentation site | `https://waf.uusec.com/#/zh-cn/guide/install` | — |
| Source code repository | `https://github.com/Safe3/uusec-waf` | — |

> The offline copies are **snapshots of the official original text** and may lag behind upstream. For time-sensitive content (version watersheds, new features, already-fixed issues), **prefer the online source**.

---

## Rules and Plugin Resources

### Official Built-ins

| Type | Repository path | Description |
|:---|:---|:---|
| Built-in rules | `rules/*.lua` | Officially maintained, e.g. `rules/anti-cc.lua` |
| Built-in plugins | `plugins/*.lua` | Officially maintained, e.g. `plugins/kafka-logger.lua`, `plugins/ip-intelligence.lua`, `plugins/basic-auth.lua` |
| Runtime built-in rules / plugins | Panel "Rule Management" "Plugin Management" | Present in the library right after installation (rule IDs `10~499`, automatically maintained by the official team) |

### Community Third-party

| Type | Repository path | Description |
|:---|:---|:---|
| Third-party rules | `rules/third_party/*.lua` | Community-contributed, distributed with the repository but **not officially maintained** |
| Third-party plugins | `plugins/third_party/*.lua` | Community-contributed, **not officially maintained** |

🔴 **When referencing them you must distinguish built-in from third-party**:

- Criterion = the **path prefix** (whether `third_party/` is present) + the **signature in the file header**.
  - Built-in example: `plugins/ip-intelligence.lua` is signed `Created by Safe3.`
  - Community example: the file header says "Author: xxx".
- Wording convention: third-party files should be called a "**community-contributed reference implementation**" and **must not** be written as an "official implementation".

### How to Obtain Them

```bash
# List all rule and plugin paths in the repository
curl -sL "https://api.github.com/repos/Safe3/uusec-waf/git/trees/main?recursive=1" \
  | grep -o '"path": *"\(rules\|plugins\)/[^"]*"'

# Fetch a single file directly
curl -sL "https://raw.githubusercontent.com/Safe3/uusec-waf/main/rules/anti-cc.lua"
curl -sL "https://raw.githubusercontent.com/Safe3/uusec-waf/main/plugins/third_party/auth-plugin.lua"
```

**How to import into the panel**: through the console REST API `POST /rules`, `POST /plugins` (the body contains `content` = the full Lua text), or by pasting it in the panel UI. Write operations require `waf_nodes` to be non-empty (see `management-api.md`).

### Contributing

Submit a PR to `rules/` or `plugins/`. See `offline-docs/contribute.md` for details.

---

## Client Script

`scripts/waf.py` — pure standard library, no third-party dependencies, supports multiple instances.

### Instance Configuration (preferred)

`~/.config/waf-hosts.json` (permission 600):

```json
{
  "<instance-name>": {"url": "https://<server-IP>:4443", "token": "<Api-Token>"}
}
```

- **`url` takes the address at which the panel is reachable**: local `127.0.0.1`, an intranet `<server-IP>`, or a domain name all work; **the port is the panel port `4443`**
  (HTTPS; the panel uses a self-signed certificate by default → the script skips certificate verification automatically; 80/443 are the data plane and 4447 is the built-in management plane, neither of them is the panel).
- **Two steps for new users**: `waf.py init` generates a skeleton (automatically permission 600, containing a `_说明` key which the script skips) → the user fills in `url`/`token` → `-i <instance-name> ping` self-check.
- **Filling it in on the user's behalf (when the user has given you the values)**: `waf.py hosts --add <name> --url <URL> --token -` (`-` = read from **stdin**, keeping the token out of the command-line history); the script **only reports the length and never echoes the token**; if the token was given through a conversation, remind the other party to rotate it as needed.
- Adding a new WAF: just add another entry to that file, **zero changes to the script**.
- Copy the token from the panel's "System Settings → API Access Token" (**copying requires logging into the panel**; afterwards API calls only use that token and no further login is needed).

Environment variable fallback: `WAF_API_URL` + `WAF_API_TOKEN`.

### Usage

```bash
python3 <skill-dir>/scripts/waf.py hosts                              # list all instances
python3 <skill-dir>/scripts/waf.py -i <instance-name> ping                    # connectivity + authentication self-check
python3 <skill-dir>/scripts/waf.py -i <instance-name> list sites|rules|ruleset|certs|plugins|users
python3 <skill-dir>/scripts/waf.py -i <instance-name> api GET  /ruleset
python3 <skill-dir>/scripts/waf.py -i <instance-name> api GET  /rules
python3 <skill-dir>/scripts/waf.py -i <instance-name> api POST /logs \
  '{"page":1,"page_size":20,"query":{"level":5,"time_range":[]}}'
python3 <skill-dir>/scripts/waf.py -i <instance-name> logs -q '{"level":5,"host":"example.com"}'
python3 <skill-dir>/scripts/waf.py -i <instance-name> logs -q '{"level":5}' --table   # table output; the request field is hidden by default
```

### Write Path (modify rules / rulesets / bans)

**No need to hand-write Python workarounds** — `get` / `push` solve the two hard problems "there is no `GET /rules/{id}`" and "the body cannot be inlined into the shell", with **byte fidelity** (`content` is CRLF on the server side and is not normalized on round trips):

```bash
# Fetch the body into a file (default field: content; --field __meta__ shows metadata only)
python3 <skill-dir>/scripts/waf.py -i <instance-name> get rule <rule-ID> --out /tmp/rule.lua

# Write it back after editing (PUT, with id; it first GETs the current object and replaces only the body, without guessing the field shape)
python3 <skill-dir>/scripts/waf.py -i <instance-name> push rule <rule-ID> --file /tmp/rule.lua --dry-run
python3 <skill-dir>/scripts/waf.py -i <instance-name> push rule <rule-ID> --file /tmp/rule.lua

# Create a new rule (POST / id=0)
python3 <skill-dir>/scripts/waf.py -i <instance-name> push rule new --file /tmp/new.lua --name "my-rule" --level 3

# Modify a ruleset's enabled list (--add/--remove a single one, or --set the whole list; array order is meaningless)
python3 <skill-dir>/scripts/waf.py -i <instance-name> push ruleset 1 --add <rule-ID>
python3 <skill-dir>/scripts/waf.py -i <instance-name> push ruleset 1 --remove 19 --dry-run

# IP ban list: view / toggle the lock state of an IP
python3 <skill-dir>/scripts/waf.py -i <instance-name> ipblock
python3 <skill-dir>/scripts/waf.py -i <instance-name> ipblock --check <IP> | --unlock <IP>
```

> All `push` commands support `--dry-run` (it only prints the body that would be submitted and sends no request). Write operations require `waf_nodes` to be non-empty and are **production changes** — obtain authorization first; before changing, backing up with `GET /setting/backupConfig` is recommended, and provide a rollback path.

> `-i <instance-name>` must be the first argument.
> The script skips self-signed certificate verification automatically; the token is read by the script from the config file / environment variables and **never enters the conversation context**.
> The `logs` subcommand **does not print the `request` field by default** (it contains credentials); it is output only when `--raw` is explicitly added.

### Complete Self-check with One Command

```bash
# Preferred: use an instance from ~/.config/waf-hosts.json (the token stays out of the command line)
bash <skill-dir>/scripts/selfcheck.sh -i <instance-name>

# Fallback: pass url/token when there is no config file, or use environment variables
bash <skill-dir>/scripts/selfcheck.sh --url https://<panel-address>:<port> --token <Api-Token>
WAF_API_URL=https://<panel-address>:<port> WAF_API_TOKEN=<Api-Token> bash <skill-dir>/scripts/selfcheck.sh
```

> It runs a 6-step **fully read-only** self-check in order: instance list → connectivity and authentication → sites → rulesets → logs → IP ban list.
> Exit codes: `0` all passed / `1` some step failed (the failing line is marked `[FAIL]`) / `2` argument or environment error.
> The script locates the `waf.py` in the same directory automatically and **can be run from any cwd**.
> 🔴 **Prefer the config file** (`~/.config/waf-hosts.json`) — the `--token` fallback writes the Api-Token into the process arguments and the shell history, which conflicts with "the token never enters the context"; if the fallback is really needed, first `export WAF_API_TOKEN=…` in the shell and let the script read it from the environment variable.

---

## Decision Quick Reference

| What I want to do | Where to look |
|:---|:---|
| Install a Nanqiang instance / harden it | `references/operations.md` §1 |
| **Understand the deployment form / how the database is used** | `references/deployment.md` §1/§2/§3 |
| **Chinese edition or English edition / how to switch the language** | `references/deployment.md` §1 "Chinese edition / English edition" — the language is fixed at deployment time; the panel setting only changes the UI |
| **Database won't connect / version compatibility / startup order** | `references/deployment.md` §3/§4/§5 |
| **User asks "how do I configure X" / asks me to configure X** | `references/configuration.md` |
| Onboard a site / upload a certificate | `references/configuration.md` §2/§3, `references/management-api.md` §3.1/§3.6 |
| Configure CC / frequency protection | `references/configuration.md` §7 |
| Configure allowlist / log-only mode / unban | `references/configuration.md` §4/§5/§6 |
| Query logs and rules with the API | `references/management-api.md` §3.2/§3.4 |
| **Modify a rule body / modify a ruleset's enabled list / unban an IP** | `get` / `push` / `ipblock` of `scripts/waf.py` (see "Client Script → Write Path" in this document) |
| Write a rule | `references/rule-authoring.md` (**read `references/internals.md` first**) |
| **How to write a regex / how to validate it** | `references/rule-authoring.md` §2.2 (two channels: the standalone `pcrecheck.py` / the container-based `wafcheck.sh`) |
| Write a visual (DSL) rule | `references/rule-authoring.md` §3.2 |
| Write a plugin | `references/plugin-authoring.md` |
| Decide whether to use a rule or a plugin | `references/rule-authoring.md` §6 |
| A built-in rule has a bug and I cannot change it | `references/internals.md` §5 — built-in rules are maintained by the panel, **direct edits get rolled back**, do not modify them |
| **Validate rules/plugins before delivery (semantic layer)** | `python3 scripts/rulecheck.py all <file> [--phase N]` (or `bash scripts/wafcheck.sh semantics <file>` on the WAF host) |
| **Which modules can a plugin use** | `references/plugin-authoring.md` §10 (tested list + verification command) |
| What exactly is the difference between a rule and a plugin | `references/internals.md` §3.2 (scope / ngx / cross-phase) |
| A rule I wrote has no effect | `references/rule-authoring.md` §7 troubleshooting order |
| How to handle a false positive | `references/internals.md` §3 (the cost of `RULE_ALLOW`) + `references/rule-authoring.md` §4.7 |
| Find out why a request was blocked | `references/pitfalls.md` §7 (read the built-in detection module signature table) + `references/management-api.md` §3.4 |
| What to watch out for before upgrading | `references/internals.md` §10 version watershed + `references/operations.md` §4 |
| How to lift a ban | `references/pitfalls.md` §1/§5 (TTL and removal), `references/configuration.md` §6 |

---

## Security and Compliance Requirements

### Credentials and Sensitive Data

| Source | Sensitive content | Handling |
|:---|:---|:---|
| `GET /setting` | `dsn` (contains the password), `jwt_key`, `api_token`, `ml_token` | **Never written to disk / never echoed / never written into persona files** |
| `GET /users` | `otp_url` (the TOTP secret in plaintext), `pwd` | Same as above |
| `GET /certs` | `key` (the private key PEM), `dns_credential` (DNS credentials) | Same as above |
| The `request` of `POST /logs` | `Authorization`, `Cookie` and the like are **stored verbatim** | **Not printed by default**; when really needed, take only the necessary fragments |
| `config.json` | All of the above | Same as above |
| Panel default credentials | `admin` / `#Passw0rd` | **This user must be deleted after deployment** |

**Where to keep the Api-Token**: a config file with permission **600** (`~/.config/waf-hosts.json`) or an environment variable, read by **the script**, never through the model context.

### Operating Discipline

1. **Do not send crafted requests to the WAF data plane (80/443)** — it triggers a rule 13 ban and also bans the IPs on the same link. For diagnosis use only: the control plane API (4443), read-only database access, read-only shared memory, and the source code of the built-in detection modules. See `references/pitfalls.md` §1.
2. **Obtain authorization before production write operations** — changing rules, changing rulesets, unbanning IPs, and changing site/certificate configuration are all production changes. First list the questions to be confirmed and explain the scope of impact, execute after confirmation, **and provide a rollback path**.
3. **Everything is read-only during diagnosis**; obtain explicit authorization first if end-to-end verification is really needed.
4. **🔴 Unauthorized write operations on the database are strictly forbidden** — the database (the WAF's `wafdb` and any instance database) is **read-only**. `INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`/`TRUNCATE` and the like are all forbidden, **including for testing, verification, and log cleanup**; logs are original records, and logs produced by tests **are kept faithfully with their source noted**, not deleted, not cleared, not modified. If a write operation is really needed, first explain the content, the scope of impact, and the rollback path, then execute it after obtaining authorization. Priority of diagnostic channels: console API > read-only queries > panel.
5. **Back up before changing** — `GET /setting/backupConfig` / `GET /setting/backupDB`.
6. **Acceptance is based on the actual effective state** — do not only look at the API returning 200; verify with requests that should be blocked and requests that should pass.
7. **Do not modify external systems on the user's behalf** — if you can provide something that can be pasted directly, hand it to the user to execute.

### Deliverable Conventions

- **Rules/plugins must be validated before delivery** (Lua syntax + every regex + samples that should be blocked and should pass), together with the validation commands and results. See "Hard Requirements Before Delivering Rules/Plugins" in this document.
- **When referencing third-party files you must distinguish their provenance**: `rules/*.lua`, `plugins/*.lua` = official; `rules/third_party/*`, `plugins/third_party/*` = **community-contributed** (worded as "community-contributed reference implementation", never as "official implementation").

---

## File List

```
SKILL.md                        Entry point: capability scope, documentation strategy, decision quick reference, script usage
references/
├── management-api.md           Console REST API (with tested corrections and field semantics)
├── internals.md                Runtime internals: execution order, ID partitioning, RULE_ALLOW, shared memory, log-only mode
├── rule-authoring.md           Rule authoring: templates, conventions, **regex (PCRE) and validation**, **DSL rules**, pattern library, troubleshooting
├── plugin-authoring.md         Plugin authoring: phases, native ngx, pattern library, pitfalls
├── operations.md               Installation, directories, changing configuration, upgrades, common problems
├── deployment.md               Deployment and database: deployment forms, official compose, DSN and database usage, startup order, upgrades
├── configuration.md            **Feature configuration guide**: site/certificate/allowlist/log-only mode/CC/captcha/CDN/ban
├── pitfalls.md                 🔴 Prohibitions, credentials, documentation-vs-implementation mismatches, silent-failure checklist
└── offline-docs/               Offline copies of the official docs and examples
    ├── api.zh-CN.md            Official rule/plugin API (authoritative full text)
    ├── install.md / getting-started.md / faq.md / contribute.md
    ├── product-introduction.md / CHANGELOG.zh-CN.md / README.zh-CN.md / README.md / LICENSE.txt
    └── examples/               Source copies of official built-in and community rules/plugins
        ├── rule-*.lua          anti-CC, brute force, dynamic rate limiting, high-frequency blocking, high-frequency errors
        ├── plugin-*.lua        kafka-logger, ip-intelligence, basic-auth, auth-session
        ├── manager.sh          Official container management script
        ├── docker-compose.yml  Official compose (uuwaf + wafdb, authoritative)
        └── low-memory-my.cnf   Official low-memory MySQL tuning (commented out by default in compose)
scripts/
├── pcrecheck.py                **Standalone** validator (ctypes + system PCRE2, no container needed; recommended)
├── wafcheck.sh                 Container-based validator (same-origin PCRE1 + authoritative luajit, WAF host only)
├── regex-extract.awk           Regex extractor for wafcheck.sh (used by the file subcommand)
├── rulecheck.py                **Semantic validator** (pure standard library, runs on any machine): API/constants/phases/hooks/modules/DSL
├── waf.py                      REST API client (multi-instance, pure standard library; get/push/ipblock/backup/delete/diff)
└── selfcheck.sh                One-command self-check of connectivity + authentication + common read-only endpoints
```

---

## Sources and License

| Item | Description |
|:---|:---|
| Subject | [Safe3/uusec-waf](https://github.com/Safe3/uusec-waf) (UUSEC WAF, Nanqiang) |
| Upstream license | **BSD 2-Clause**, Copyright (c) 2025 UUSEC Technology — full text in `references/offline-docs/LICENSE.txt` |
| Offline copies | The documents and examples under `references/offline-docs/` are all **snapshots of the official original text**; the license and copyright follow upstream; keep `LICENSE.txt` when redistributing |
| Timeliness | The copies may lag behind upstream; for time-sensitive content (version watersheds, new features, fixed issues) **prefer the online original**, see "Documentation Strategy" |

> This skill is a **usage guide** compiled by a third party and has no affiliation with UUSEC Technology;
> the "runtime internals / implementation-level research / pitfall checklist" in it were summarized from this skill's own testing and are not official documentation content.
> The final interpretation of the rules/file contents rests with the upstream official documentation.
