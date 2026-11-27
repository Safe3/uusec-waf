# uusec-waf Skill

An **Agent Skill** for UUSEC WAF (Nanqiang) (WAAP): installation and deployment, daily operations, sites and certificates, rule and plugin authoring and debugging, and console REST API management.

> **This repository is the generic open-source edition.** It uses the [Agent Skills](https://agentskills.io/specification) standard format, so any runtime that supports the specification (Claude Code, Codex, QwenPaw, etc.) can use it directly; it does not depend on any proprietary tool of a specific agent platform.
>
> This skill is a **usage guide and toolset** compiled by a third party and has **no affiliation** with UUSEC Technology.

---

## What It Can Do

| Area | Content |
|:---|:---|
| **Installation and deployment** | One-click install, hardening, site onboarding, certificates, Chinese edition / English edition channel selection |
| **Deployment and database** | Deployment forms, official compose, DSN and database usage, startup order, upgrades |
| **Daily operations** | Containers and directories, changing configuration, upgrade backups, common problems |
| **API management** | Sites / rules / rulesets / certificates / plugins / users / logs / bans / CDN |
| **Rule development** | Rule templates, conventions, PCRE pattern library, rollout and rollback |
| **Plugin development** | 5 major phases × pre/post = 10 hooks, native ngx, shared memory |
| **Pre-delivery validation** | The trio: Lua syntax / regex / **semantics** (API, constants, phases, hooks, modules, DSL) |
| **Runtime internals** | Execution order, `RULE_ALLOW` short-circuit, shared memory dict, log-only mode |
| **Pitfall avoidance** | Data plane prohibitions, documentation-vs-implementation mismatches, silent-failure checklist |

> 🔴 **Read `references/pitfalls.md` before you start**, especially the two sections "Do not send crafted requests to the WAF data plane" and "Credential checklist".

---

## Directory Structure

```
SKILL.md                        Entry point: capability scope, documentation strategy, decision quick reference, script usage
references/
├── management-api.md           Console REST API (with tested corrections and field semantics)
├── internals.md                Runtime internals: execution order, ID partitioning, RULE_ALLOW, shared memory, log-only mode
├── rule-authoring.md           Rule authoring: templates, conventions, PCRE regex and validation, DSL rules, pattern library, troubleshooting
├── plugin-authoring.md         Plugin authoring: phases, native ngx, pattern library, pitfalls
├── operations.md               Installation, directories, changing configuration, upgrades, common problems
├── deployment.md               Deployment and database: deployment forms, official compose, DSN, startup order, upgrades
├── configuration.md            Feature configuration guide: site/certificate/allowlist/log-only mode/CC/captcha/CDN/ban
├── pitfalls.md                 🔴 Prohibitions, credentials, documentation-vs-implementation mismatches, silent-failure checklist
└── offline-docs/               Offline copies of the official docs and examples (BSD-2-Clause, see "License")
scripts/
├── waf.py                      REST API client (multi-instance, pure standard library)
├── selfcheck.sh                Complete self-check with one command (6 read-only steps)
├── rulecheck.py                Semantic validator (API/constants/phases/hooks/modules/DSL)
├── pcrecheck.py                Standalone regex validator (ctypes + system PCRE2, no container needed)
├── wafcheck.sh                 Container-based validator (same-origin PCRE1 + authoritative luajit, WAF host only)
└── regex-extract.awk           Regex extractor for wafcheck.sh
```

---

## Installation

Just put this directory into your runtime's skills directory (the path differs per runtime; commonly `<workspace>/skills/uusec-waf/`):

```bash
git clone <this-repository-url> uusec-waf
```

**Dependencies**: `bash`, `python3` (3.8+).
All Python scripts **use the standard library only** and have no third-party dependencies; `pcrecheck.py` additionally needs the system `libpcre2` (bundled with most distributions; the script prints a hint when it is missing).

---

## Configuring Credentials

Copy from the panel's "System Settings → API Access Token" and write it to `~/.config/waf-hosts.json` (permission 600):

```json
{
  "<instance-name>": {"url": "https://<server-IP>:4443", "token": "<Api-Token>"}
}
```

- **`url` takes the address at which the panel is reachable**: the port is the panel port `4443` (HTTPS; self-signed certificates are skipped automatically by the script).
  Note that `80/443` are the data plane and `4447` is the built-in management plane, neither of which is the panel.
- **Generate a skeleton**: `python3 scripts/waf.py init` (automatically permission 600) → fill in `url`/`token`.
- **Fill it in on the user's behalf**: `python3 scripts/waf.py hosts --add <name> --url <URL> --token -` (`-` = read from stdin, keeping the token out of the command-line history; the script only reports the length and never echoes it).
- **Environment variable fallback**: `WAF_API_URL` + `WAF_API_TOKEN`.
- Multiple instances: just add another entry to that file; zero changes to the script.

> 🔴 Do not put the token on the command line, do not paste it into a conversation, and do not commit it to a repository.

---

## Usage

### Connectivity Self-check

```bash
python3 scripts/waf.py -i <instance-name> ping          # single step: connectivity + authentication
bash    scripts/selfcheck.sh -i <instance-name>          # full suite: 6-step read-only self-check
```

`selfcheck.sh` runs "instance list → connectivity and authentication → sites → rulesets → logs → IP ban list" in order, sending only GET requests throughout.
Exit codes: `0` all passed / `1` some step failed / `2` argument or environment error. The script locates the `waf.py` in the same directory automatically and can be run from any cwd.

### Common Queries

```bash
python3 scripts/waf.py -i <instance-name> list sites|rules|ruleset|certs|plugins|users
python3 scripts/waf.py -i <instance-name> api GET /ruleset
python3 scripts/waf.py -i <instance-name> logs -q '{"level":5}' --table    # the request field (containing credentials) is hidden by default
```

### Write Path (modify rules / rulesets / bans)

```bash
python3 scripts/waf.py -i <instance-name> get  rule <rule-ID> --out /tmp/rule.lua
python3 scripts/waf.py -i <instance-name> push rule <rule-ID> --file /tmp/rule.lua --dry-run
python3 scripts/waf.py -i <instance-name> push ruleset 1 --add <rule-ID>
python3 scripts/waf.py -i <instance-name> ipblock --check <IP> | --unlock <IP>
```

> All `push` commands support `--dry-run` (it only prints the body that would be submitted and sends no request). Write operations are **production changes** — obtain authorization first, back up before changing, and have a rollback path ready.

### Pre-delivery Validation

```bash
python3 scripts/rulecheck.py all <file> [--phase 0|1|2]   # semantics (mandatory)
python3 scripts/pcrecheck.py regex '<regex>' '<should-match>' '<should-pass>'
bash    scripts/wafcheck.sh lua <file>                    # authoritative Lua (WAF host only)
```

---

## License and Acknowledgements

| Item | Description |
|:---|:---|
| **Subject** | [Safe3/uusec-waf](https://github.com/Safe3/uusec-waf) (UUSEC WAF, Nanqiang) |
| **Upstream license** | **BSD 2-Clause**, Copyright (c) 2025 UUSEC Technology |
| **Offline copies** | The documents and examples under `references/offline-docs/` are snapshots of the official original text; the copyright follows upstream; keep `LICENSE.txt` when redistributing |
| **Timeliness** | The copies may lag behind upstream; for version watersheds, new features, and fixed issues **prefer the online original** |

Content outside `references/offline-docs/` (SKILL.md, the other references, scripts) was compiled and summarized from testing by this project,
and the "runtime internals / implementation-level research / pitfall checklist" in it is **not official documentation content**; the final interpretation of the rules and file contents rests with the upstream official documentation.

> ⚠️ Timeliness note: WAF versions iterate quickly; when specific version behavior is involved, please refer to the online official documentation.

---

## Contributing

Issues and PRs are both welcome. Before submitting changes related to rules/plugins, please first get `rulecheck.py` and `pcrecheck.py` to pass.
