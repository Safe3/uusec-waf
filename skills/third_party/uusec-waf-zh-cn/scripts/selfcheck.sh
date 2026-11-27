#!/usr/bin/env bash
# UUSEC WAF（南墙）—— 一条命令做完备自检（6 步，全部只读）
#
# 用途
# ----
#   依次跑完「实例列表 → 连通认证 → 站点 → 规则集 → 日志 → IP 封禁名单」，
#   用于首次接入确认、故障初判、变更后回归。全程只发 GET，不发任何写请求。
#
# 用法
# ----
#   bash selfcheck.sh -i <实例名>                                   # 用 ~/.config/waf-hosts.json 的实例（推荐）
#   bash selfcheck.sh --url https://<IP>:4443 --token <Api-Token>   # 无配置文件时兜底
#   WAF_API_URL=... WAF_API_TOKEN=... bash selfcheck.sh             # 环境变量兜底
#   bash selfcheck.sh -h
#
#   脚本自动定位同目录的 waf.py，**在任意 cwd 都能执行**，无需先 cd。
#
# 退出码
# ----
#   0 = 六步全部通过；1 = 有步骤失败（失败步骤行标 [FAIL]）；2 = 参数或环境错误。
#
# 依赖：bash + python3（waf.py 为纯标准库，无第三方依赖）。

set -u

INSTANCE=""; URL=""; TOKEN=""
while [ $# -gt 0 ]; do
    case "$1" in
        -i|--instance) INSTANCE="${2:-}"; shift 2 ;;
        --url)         URL="${2:-}";      shift 2 ;;
        --token)       TOKEN="${2:-}";    shift 2 ;;
        -h|--help)     sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf '[错误] 未知参数: %s（用 -h 看用法）\n' "$1" >&2; exit 2 ;;
    esac
done

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF="$SKILL_DIR/waf.py"
[ -f "$WAF" ] || { printf '[错误] 找不到 %s\n' "$WAF" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf '[错误] 需要 python3\n' >&2; exit 2; }

# 调用前缀：优先 -i <实例名>，其次 --url/--token，最后交给环境变量
if [ -n "$INSTANCE" ]; then
    PREFIX=(python3 "$WAF" -i "$INSTANCE")
elif [ -n "$URL" ] || [ -n "$TOKEN" ]; then
    export WAF_API_URL="$URL" WAF_API_TOKEN="$TOKEN"
    PREFIX=(python3 "$WAF")
    printf '[提示] 使用 --url/--token 兜底：token 会进入进程参数与命令历史。\n'
    printf '       建议改用 ~/.config/waf-hosts.json，或先 export WAF_API_TOKEN=…\n'
else
    PREFIX=(python3 "$WAF")
fi

N=0; FAIL=0
step() {
    local desc="$1"; shift
    N=$((N + 1))
    printf '\n===== [%s/6] %s =====\n' "$N" "$desc"
    if "$@"; then :; else printf '  [FAIL] 第 %s 步未通过\n' "$N"; FAIL=1; fi
}

step "实例列表（~/.config/waf-hosts.json）" python3 "$WAF" hosts
step "连通 + 认证（GET /setting/license）"  "${PREFIX[@]}" ping
step "站点列表"                            "${PREFIX[@]}" list sites
step "规则集列表"                          "${PREFIX[@]}" list ruleset
step "最近日志（5 条）"                    "${PREFIX[@]}" logs --size 5 --table
step "IP 封禁名单"                         "${PREFIX[@]}" ipblock

printf '\n==============================\n'
if [ "$FAIL" -eq 0 ]; then
    printf '[OK] 六步自检全部通过\n'
    exit 0
fi
printf '[FAIL] 有步骤未通过 —— 对照上方 [FAIL] 行排查\n'
printf '       认证 / 连通类错误见 SKILL.md「注意事项与排查」一节\n'
exit 1
