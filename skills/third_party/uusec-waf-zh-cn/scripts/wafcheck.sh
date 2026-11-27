#!/usr/bin/env bash
# UUSEC WAF 规则/插件 —— 容器内「同源」校验器（PCRE1 + LuaJIT）
#
# 用途
# ----
#   在**恰好是 WAF 主机**（本机跑着 UUWAF 容器）时，用容器内的 PCRE1 库
#   与 LuaJIT 做**与运行时同源**的校验。这是保真度最高的通道，也是唯一能
#   做**权威 Lua 语法校验**的通道。
#
#   ⚠️ 只在 WAF 主机上有意义。agent 与 WAF 不同机时，本机没有容器，
#      请改用 **scripts/pcrecheck.py**（独立版，绑定系统 PCRE2，无需容器）：
#        python3 pcrecheck.py regex '<正则>' '<样例>'
#        python3 pcrecheck.py file  <规则文件>
#      pcrecheck.py 能做正则校验，但**做不了权威 Lua 校验**（须 luajit）。
#
# 用法
# ----
#   wafcheck.sh engine                      环境自检：PCRE1 / LuaJIT 版本与能力
#   wafcheck.sh regex   <正则> [测试串 ...]   正则语法 + 逐条匹配（退出码 2 = 非法）
#   wafcheck.sh cases   <正则> <测试串文件>   按行批量比对
#   wafcheck.sh lua     <文件>               **权威** Lua 语法校验 → SYNTAX_OK
#   wafcheck.sh file    <文件>               Lua 语法 + 提取文件内正则逐个校验
#   wafcheck.sh semantics <文件> [--phase N] 语义检查（API/常量/阶段/钩子/模块）→ 转 rulecheck.py
#                                            ⚠️ 该子命令需要 python3（其余子命令不需要）
#
# 容器定位：环境变量 WAF_CONTAINER，或镜像名含 uusec/waf / 容器名含 uuwaf，
#           或容器内存在 /uuwaf/sbin/uuwaf。
#
# 安全：正则与测试串一律经文件/标准输入传递，不拼进 shell 命令串；
#       全程不发任何 HTTP 请求，不会触发 WAF 防护。
#
# 兼容性：bash + awk + sed + grep（容器内均有），不依赖 python/perl。

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
# 容器定位
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
[错误] 本机找不到可用的 UUWAF 容器。

本脚本是「容器内同源校验」通道，只在 WAF 主机上有意义。
若 agent 与 WAF 不同机（常见情况），请改用独立版（无需容器）：

    python3 <skill目录>/scripts/pcrecheck.py regex '<正则>' '<样例>'
    python3 <skill目录>/scripts/pcrecheck.py file  <规则文件>
    python3 <skill目录>/scripts/pcrecheck.py engine

注：pcrecheck.py 绑定系统 PCRE2，可做正则校验；但 Lua 的**权威**语法
    校验只有容器内 luajit 能做，须在 WAF 主机执行。
EOF
    exit 3
fi

tmpd=$(mktemp -d 2>/dev/null || echo "/tmp/wafcheck.$$")
mkdir -p "$tmpd" 2>/dev/null
trap 'rm -rf "$tmpd"' EXIT
PF="$tmpd/pat"; SF="$tmpd/subj"

# 把模式/样例送进容器后匹配；回显结果码 0=命中 1=未命中 2=非法
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
    echo "容器: $WAF_C"
    docker exec "$WAF_C" sh -c '
      echo "--- grep 版本（PCRE 载体）---"
      grep --version 2>/dev/null | head -1
      echo "--- grep 依赖的 pcre 库 ---"
      ldd "$(command -v grep)" 2>/dev/null | grep -i pcre || echo "(静态链接)"
      echo "--- PCRE 库 ---"
      ls -l /lib64/libpcre.so* /usr/lib64/libpcre.so* /usr/lib/libpcre.so* 2>/dev/null | head -3
      echo "--- LuaJIT ---"
      /uuwaf/luajit/bin/luajit -v 2>&1 | head -1
    '
    echo "--- 能力自检 ---"
    printf 'x' > "$SF"
    printf '(?<=x)' > "$PF";  [ "$(do_check "$PF" "$SF")" = 0 ] && echo "  ✅ lookbehind 后顾"
    printf '(?:x)'  > "$PF";  [ "$(do_check "$PF" "$SF")" = 0 ] && echo "  ✅ 非捕获组"
    printf 'aaa' > "$SF"; printf 'a{2,}?' > "$PF"; [ "$(do_check "$PF" "$SF")" = 0 ] && echo "  ✅ 非贪婪"
    printf 'x' > "$SF";  printf 'abc('  > "$PF"; [ "$(do_check "$PF" "$SF")" = 2 ] && echo "  ✅ 非法正则可识别（退出码 2）"
    ;;

regex)
    PAT="${ARGS[0]:-}"
    [ -n "$PAT" ] || { echo "[错误] 用法: wafcheck.sh regex <正则> [测试串 ...]" >&2; exit 3; }
    echo "[通道] 容器 $WAF_C 内 PCRE1（与运行时同源）"
    rc=$(check_rc "$PAT")
    if [ "$rc" = 2 ]; then
        echo "[非法] $PAT"; printf '        %s\n' "$(do_reason "$PF" "$SF")"; exit 2
    fi
    echo "[合法] $PAT"
    [ "${#ARGS[@]}" -le 1 ] && exit 0
    fail=0
    for i in $(seq 1 $((${#ARGS[@]} - 1))); do
        s="${ARGS[$i]}"
        if [ "$(subj_rc "$s")" = 0 ]; then printf '  命中    | %s\n' "$s"
        else printf '  不命中  | %s\n' "$s"; fail=1; fi
    done
    exit $fail
    ;;

cases)
    PAT="${ARGS[0]:-}"; F="${ARGS[1]:-}"
    [ -n "$PAT" ] || { echo "[错误] 用法: wafcheck.sh cases <正则> <测试串文件>" >&2; exit 3; }
    [ -f "$F" ] || { echo "[错误] 测试串文件不存在: $F" >&2; exit 3; }
    echo "[通道] 容器 $WAF_C 内 PCRE1（与运行时同源）"
    rc=$(check_rc "$PAT")
    if [ "$rc" = 2 ]; then echo "[非法] $PAT"; exit 2; fi
    echo "[合法] $PAT"
    while IFS= read -r s || [ -n "$s" ]; do
        case "$s" in ''|'#'*) continue ;; esac
        if [ "$(subj_rc "$s")" = 0 ]; then printf '  命中    | %s\n' "$s"
        else printf '  不命中  | %s\n' "$s"; fi
    done < "$F"
    ;;

lua)
    F="${ARGS[0]:-}"
    [ -f "$F" ] || { echo "[错误] 用法: wafcheck.sh lua <文件>" >&2; exit 3; }
    docker exec -i "$WAF_C" sh -c 'cat > /tmp/.wc.lua' < "$F"
    docker exec "$WAF_C" sh -c \
      '/uuwaf/luajit/bin/luajit -e '\''local f,e=loadfile("/tmp/.wc.lua"); print(f and "SYNTAX_OK" or ("ERR: "..tostring(e)))'\'''
    ;;

semantics)
    F="${ARGS[0]:-}"
    [ -n "$F" ] || { echo "[错误] 用法: wafcheck.sh semantics <文件> [--phase 0|1|2] [--plugin]" >&2; exit 3; }
    command -v python3 >/dev/null 2>&1 || { echo "[错误] semantics 子命令需要 python3（其余子命令不需要）" >&2; exit 3; }
    exec python3 "$(dirname "$0")/rulecheck.py" all "$F" "${ARGS[@]:1}"
    ;;

file)
    F="${ARGS[0]:-}"
    [ -f "$F" ] || { echo "[错误] 用法: wafcheck.sh file <文件>" >&2; exit 3; }
    echo "[通道] 容器 $WAF_C 内 PCRE1（与运行时同源）"
    echo "=== Lua 语法（权威，luajit）==="
    docker exec -i "$WAF_C" sh -c 'cat > /tmp/.wc.lua' < "$F"
    docker exec "$WAF_C" sh -c \
      '/uuwaf/luajit/bin/luajit -e '\''local f,e=loadfile("/tmp/.wc.lua"); print(f and "SYNTAX_OK" or ("ERR: "..tostring(e)))'\'''
    echo
    echo "=== 提取到的正则 ==="
    awk -f "$(dirname "$0")/regex-extract.awk" "$F" 2>/dev/null | sort -u > "$tmpd/pairs"
    total=0; bad=0; susp=0
    while IFS="$(printf '\t')" read -r kind pat; do
        [ -z "${pat:-}" ] && continue
        total=$((total+1))
        rc=$(check_rc "$pat")
        if [ "$rc" = 2 ]; then
            if [ "$kind" = "确定" ]; then
                bad=$((bad+1)); printf '  [确定-非法] %s\n' "$pat"
            else
                susp=$((susp+1)); printf '  [疑似-非法] %s   <- 不确定是否作正则用，请人工确认\n' "$pat"
            fi
            printf '                %s\n' "$(do_reason "$PF" "$SF")"
        else
            printf '  [%s] %s\n' "$kind" "$pat"
        fi
    done < "$tmpd/pairs"
    [ "$total" -eq 0 ] && echo "  （未提取到正则——可能未用 waf.rgx*，而用 waf.startWith/pmMatch 等）"
    echo "共 $total 条：确定非法 $bad 条，疑似非法 $susp 条"
    echo
    echo "提示：跨行调用与 [=[ 层级长字符串需用 pcrecheck.py file（提取能力更强）"
    [ "$bad" -eq 0 ] || exit 2
    ;;

*)
    usage; exit 1 ;;
esac
