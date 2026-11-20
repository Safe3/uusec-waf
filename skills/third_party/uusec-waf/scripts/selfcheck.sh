#!/usr/bin/env bash
# UUSEC WAF -- complete self-check in one command (6 steps, all read-only)
#
# Purpose
# ----
#   Runs through "instance list → connectivity + auth → sites → rulesets → logs → IP ban list" in order,
#   for first-time onboarding confirmation, initial troubleshooting, and post-change regression. Only GET requests are sent; no write requests at all.
#
# Usage
# ----
#   bash selfcheck.sh -i <instance name>                            # instance from ~/.config/waf-hosts.json (recommended)
#   bash selfcheck.sh --url https://<IP>:4443 --token <Api-Token>   # fallback when there is no config file
#   WAF_API_URL=... WAF_API_TOKEN=... bash selfcheck.sh             # environment-variable fallback
#   bash selfcheck.sh -h
#
#   The script locates waf.py in its own directory automatically, so **it can be run from any cwd**, with no need to cd first.
#
# Exit codes
# ----
#   0 = all six steps passed; 1 = some step failed (the failing step line is marked [FAIL]); 2 = argument or environment error.
#
# Dependencies: bash + python3 (waf.py is pure standard library, no third-party dependencies).

set -u

INSTANCE=""; URL=""; TOKEN=""
while [ $# -gt 0 ]; do
    case "$1" in
        -i|--instance) INSTANCE="${2:-}"; shift 2 ;;
        --url)         URL="${2:-}";      shift 2 ;;
        --token)       TOKEN="${2:-}";    shift 2 ;;
        -h|--help)     sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf '[ERROR] unknown argument: %s (use -h for usage)\n' "$1" >&2; exit 2 ;;
    esac
done

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF="$SKILL_DIR/waf.py"
[ -f "$WAF" ] || { printf '[ERROR] cannot find %s\n' "$WAF" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf '[ERROR] python3 is required\n' >&2; exit 2; }

# Invocation prefix: -i <instance name> first, then --url/--token, and finally the environment variables
if [ -n "$INSTANCE" ]; then
    PREFIX=(python3 "$WAF" -i "$INSTANCE")
elif [ -n "$URL" ] || [ -n "$TOKEN" ]; then
    export WAF_API_URL="$URL" WAF_API_TOKEN="$TOKEN"
    PREFIX=(python3 "$WAF")
    printf '[NOTE] using the --url/--token fallback: the token will end up in process arguments and shell history.\n'
    printf '       consider using ~/.config/waf-hosts.json instead, or export WAF_API_TOKEN=… first\n'
else
    PREFIX=(python3 "$WAF")
fi

N=0; FAIL=0
step() {
    local desc="$1"; shift
    N=$((N + 1))
    printf '\n===== [%s/6] %s =====\n' "$N" "$desc"
    if "$@"; then :; else printf '  [FAIL] step %s did not pass\n' "$N"; FAIL=1; fi
}

step "instance list (~/.config/waf-hosts.json)" python3 "$WAF" hosts
step "connectivity + auth (GET /setting/license)"  "${PREFIX[@]}" ping
step "site list"                            "${PREFIX[@]}" list sites
step "ruleset list"                          "${PREFIX[@]}" list ruleset
step "recent logs (5 entries)"                    "${PREFIX[@]}" logs --size 5 --table
step "IP ban list"                         "${PREFIX[@]}" ipblock

printf '\n==============================\n'
if [ "$FAIL" -eq 0 ]; then
    printf '[OK] all six self-check steps passed\n'
    exit 0
fi
printf '[FAIL] some steps did not pass -- check the [FAIL] lines above\n'
printf '       for auth / connectivity errors see the "Notes and troubleshooting" section of SKILL.md\n'
exit 1
