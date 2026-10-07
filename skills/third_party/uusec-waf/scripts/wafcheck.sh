#!/usr/bin/env bash
# UUSEC WAF rules/plugins -- in-container "same-source" checker (PCRE1 + LuaJIT)
#
# Purpose
# ----
#   When this machine is **exactly the WAF host** (running the UUWAF container locally), use the PCRE1
#   library and LuaJIT inside the container for checks **from the same source as the runtime**. This is
#   the highest-fidelity channel, and the only one that can do **authoritative Lua syntax checks**.
#
#   ⚠️ Only meaningful on the WAF host. When the agent and the WAF are on different machines,
#      switch to **scripts/pcrecheck.py** instead (standalone, binds the system PCRE2, no container needed):
#        python3 pcrecheck.py regex '<regex>' '<sample>'
#        python3 pcrecheck.py file  <rule file>
#      pcrecheck.py can validate regexes, but **cannot do authoritative Lua validation** (that needs luajit).
#
# Usage
# ----
#   wafcheck.sh engine                       environment self-check: PCRE1 / LuaJIT versions and capabilities
#   wafcheck.sh regex   <regex> [test string ...]   regex syntax + item-by-item matching (exit code 2 = invalid)
#   wafcheck.sh cases   <regex> <test-string file>  line-by-line batch comparison
#   wafcheck.sh lua     <file>               **authoritative** Lua syntax check → SYNTAX_OK
#   wafcheck.sh file    <file>               Lua syntax + extract every regex in the file and check them one by one
#   wafcheck.sh semantics <file> [--phase N] semantic checks (API/constants/phase/hooks/modules) → delegates to rulecheck.py
#                                            ⚠️ this subcommand needs python3 (the other subcommands do not)
#
# Container detection: the WAF_CONTAINER environment variable, or an image name containing uusec/waf / a container name containing uuwaf,
#           or /uuwaf/sbin/uuwaf existing inside the container.
#
# Safety: regexes and test strings are always passed via files/standard input, never spliced into a shell command string;
#       no HTTP request is sent at all, and WAF protection is never triggered.
#
# Compatibility: bash + awk + sed + grep (all present in the container), no python/perl dependency.

set -u

WAF_C=""
while [ $# -gt 0 ]; do
    case "$1" in
    --container) WAF_C="${2:-}"; shift 2 ;;
    -h|--help)   WAF_C="__help__"; shift ;;
    *) break ;;
    esac
done

CMD="${1:-}"; [ $# -gt 0 ] && shift
ARGS=(); for a in "$@"; do ARGS+=("$a"); done

usage() { sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; }

# --------------------------------------------------------------------------- #
# Container detection
# --------------------------------------------------------------------------- #
detect_container() {
    if [ -n "${WAF_CONTAINER:-}" ]; then printf '%s' "$WAF_CONTAINER"; return; fi
    local c
    c=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null \
        | awk 'tolower($0) ~ /uusec\/waf|uuwaf/ {print $1; exit}')
    if [ -n "$c" ]; then printf '%s' "$c"; return; fi
    for c in $(docker ps --format '{{.Names}}' 2>/dev/null); do
        if docker exec "$c" sh -c 'test -x /uuwaf/sbin/uuwaf' 2>/dev/null; then
            printf '%s' "$c"; return
        fi
    done
    printf ''
}

[ "$WAF_C" = "__help__" ] && { usage; exit 0; }
[ -n "$WAF_C" ] || WAF_C=$(detect_container)

if [ -z "$WAF_C" ] || ! docker exec "$WAF_C" sh -c 'test -x /uuwaf/sbin/uuwaf' 2>/dev/null; then
    cat >&2 <<'EOF'
[ERROR] No usable UUWAF container found on this machine.

This script is the "in-container same-source validation" channel, and it is only meaningful on the WAF host.
If the agent and the WAF are on different machines (the common case), switch to the standalone version (no container needed):

    python3 <skill dir>/scripts/pcrecheck.py regex '<regex>' '<sample>'
    python3 <skill dir>/scripts/pcrecheck.py file  <rule file>
    python3 <skill dir>/scripts/pcrecheck.py engine

Note: pcrecheck.py binds the system PCRE2 and can validate regexes; but the **authoritative** Lua syntax
    check can only be done by luajit inside the container, and must be run on the WAF host.
EOF
    exit 3
fi

tmpd=$(mktemp -d 2>/dev/null || echo "/tmp/wafcheck.$$")
mkdir -p "$tmpd" 2>/dev/null
trap 'rm -rf "$tmpd"' EXIT
PF="$tmpd/pat"; SF="$tmpd/subj"

# Feed the pattern/sample into the container, then match; echo the result code 0=hit 1=miss 2=invalid
do_check() {
    docker exec -i "$WAF_C" sh -c 'cat > /tmp/.wc.p' < "$1" 2>/dev/null
    docker exec -i "$WAF_C" sh -c 'cat > /tmp/.wc.s' < "$2" 2>/dev/null
    docker exec "$WAF_C" sh -c 'grep -qP -f /tmp/.wc.p /tmp/.wc.s 2>/dev/null'
    printf '%s' "$?"
}
do_reason() {
    docker exec -i "$WAF_C" sh -c 'cat > /tmp/.wc.p' < "$1" 2>/dev/null
    docker exec -i "$WAF_C" sh -c 'cat > /tmp/.wc.s' < "$2" 2>/dev/null
    docker exec "$WAF_C" sh -c 'grep -qP -f /tmp/.wc.p /tmp/.wc.s' 2>&1 | head -1
}
check_rc() { printf '%s' "$1" > "$PF"; printf 'x' > "$SF"; do_check "$PF" "$SF"; }
subj_rc()  { printf '%s' "$1" > "$SF"; do_check "$PF" "$SF"; }

case "$CMD" in

engine)
    echo "container: $WAF_C"
    docker exec "$WAF_C" sh -c '
      echo "--- grep version (the PCRE carrier) ---"
      grep --version 2>/dev/null | head -1
      echo "--- pcre library that grep depends on ---"
      ldd "$(command -v grep)" 2>/dev/null | grep -i pcre || echo "(statically linked)"
      echo "--- PCRE library ---"
      ls -l /lib64/libpcre.so* /usr/lib64/libpcre.so* /usr/lib/libpcre.so* 2>/dev/null | head -3
      echo "--- LuaJIT ---"
      /uuwaf/luajit/bin/luajit -v 2>&1 | head -1
    '
    echo "--- capability self-check ---"
    printf 'x' > "$SF"
    printf '(?<=x)' > "$PF";  [ "$(do_check "$PF" "$SF")" = 0 ] && echo "  ✅ lookbehind"
    printf '(?:x)'  > "$PF";  [ "$(do_check "$PF" "$SF")" = 0 ] && echo "  ✅ non-capturing group"
    printf 'aaa' > "$SF"; printf 'a{2,}?' > "$PF"; [ "$(do_check "$PF" "$SF")" = 0 ] && echo "  ✅ non-greedy"
    printf 'x' > "$SF";  printf 'abc('  > "$PF"; [ "$(do_check "$PF" "$SF")" = 2 ] && echo "  ✅ invalid regex detected (exit code 2)"
    ;;

regex)
    PAT="${ARGS[0]:-}"
    [ -n "$PAT" ] || { echo "[ERROR] usage: wafcheck.sh regex <regex> [test string ...]" >&2; exit 3; }
    echo "[CHANNEL] PCRE1 inside container $WAF_C (same source as the runtime)"
    rc=$(check_rc "$PAT")
    if [ "$rc" = 2 ]; then
        echo "[INVALID] $PAT"; printf '        %s\n' "$(do_reason "$PF" "$SF")"; exit 2
    fi
    echo "[VALID] $PAT"
    [ "${#ARGS[@]}" -le 1 ] && exit 0
    fail=0
    for i in $(seq 1 $((${#ARGS[@]} - 1))); do
        s="${ARGS[$i]}"
        if [ "$(subj_rc "$s")" = 0 ]; then printf '  hit     | %s\n' "$s"
        else printf '  miss    | %s\n' "$s"; fail=1; fi
    done
    exit $fail
    ;;

cases)
    PAT="${ARGS[0]:-}"; F="${ARGS[1]:-}"
    [ -n "$PAT" ] || { echo "[ERROR] usage: wafcheck.sh cases <regex> <test-string file>" >&2; exit 3; }
    [ -f "$F" ] || { echo "[ERROR] test-string file not found: $F" >&2; exit 3; }
    echo "[CHANNEL] PCRE1 inside container $WAF_C (same source as the runtime)"
    rc=$(check_rc "$PAT")
    if [ "$rc" = 2 ]; then echo "[INVALID] $PAT"; exit 2; fi
    echo "[VALID] $PAT"
    while IFS= read -r s || [ -n "$s" ]; do
        case "$s" in ''|'#'*) continue ;; esac
        if [ "$(subj_rc "$s")" = 0 ]; then printf '  hit     | %s\n' "$s"
        else printf '  miss    | %s\n' "$s"; fi
    done < "$F"
    ;;

lua)
    F="${ARGS[0]:-}"
    [ -f "$F" ] || { echo "[ERROR] usage: wafcheck.sh lua <file>" >&2; exit 3; }
    docker exec -i "$WAF_C" sh -c 'cat > /tmp/.wc.lua' < "$F"
    docker exec "$WAF_C" sh -c \
      '/uuwaf/luajit/bin/luajit -e '\''local f,e=loadfile("/tmp/.wc.lua"); print(f and "SYNTAX_OK" or ("ERR: "..tostring(e)))'\'''
    ;;

semantics)
    F="${ARGS[0]:-}"
    [ -n "$F" ] || { echo "[ERROR] usage: wafcheck.sh semantics <file> [--phase 0|1|2] [--plugin]" >&2; exit 3; }
    command -v python3 >/dev/null 2>&1 || { echo "[ERROR] the semantics subcommand needs python3 (the other subcommands do not)" >&2; exit 3; }
    exec python3 "$(dirname "$0")/rulecheck.py" all "$F" "${ARGS[@]:1}"
    ;;

file)
    F="${ARGS[0]:-}"
    [ -f "$F" ] || { echo "[ERROR] usage: wafcheck.sh file <file>" >&2; exit 3; }
    echo "[CHANNEL] PCRE1 inside container $WAF_C (same source as the runtime)"
    echo "=== Lua syntax (authoritative, luajit) ==="
    docker exec -i "$WAF_C" sh -c 'cat > /tmp/.wc.lua' < "$F"
    docker exec "$WAF_C" sh -c \
      '/uuwaf/luajit/bin/luajit -e '\''local f,e=loadfile("/tmp/.wc.lua"); print(f and "SYNTAX_OK" or ("ERR: "..tostring(e)))'\'''
    echo
    echo "=== extracted regexes ==="
    awk -f "$(dirname "$0")/regex-extract.awk" "$F" 2>/dev/null | sort -u > "$tmpd/pairs"
    total=0; bad=0; susp=0
    while IFS="$(printf '\t')" read -r kind pat; do
        [ -z "${pat:-}" ] && continue
        total=$((total+1))
        rc=$(check_rc "$pat")
        if [ "$rc" = 2 ]; then
            if [ "$kind" = "DEFINITE" ]; then
                bad=$((bad+1)); printf '  [DEFINITE-INVALID] %s\n' "$pat"
            else
                susp=$((susp+1)); printf '  [SUSPECT-INVALID] %s   <- not certain whether it is used as a regex; please confirm manually\n' "$pat"
            fi
            printf '                %s\n' "$(do_reason "$PF" "$SF")"
        else
            printf '  [%s] %s\n' "$kind" "$pat"
        fi
    done < "$tmpd/pairs"
    [ "$total" -eq 0 ] && echo "  (no regex extracted -- waf.rgx* may be unused and waf.startWith/pmMatch etc. used instead)"
    echo "total $total: definite-invalid $bad, suspect-invalid $susp"
    echo
    echo "Note: multi-line calls and [=[ level long strings need pcrecheck.py file (stronger extraction)"
    [ "$bad" -eq 0 ] || exit 2
    ;;

*)
    usage; exit 1 ;;
esac
