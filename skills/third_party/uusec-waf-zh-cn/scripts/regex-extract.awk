# 从南墙 Lua 规则/插件源码中提取正则字面量
#
# 输出 TAB 分隔的两列：置信度 \t 正则
#   确定  内联在 waf.rgx*(...) 第 2 参数位的字面量，
#         或「被 waf.rgx* 用作第 2 参数」的变量所赋的字面量
#   疑似  其余可能作正则使用的字面量：
#           - 长字符串 [[...]]（未被 rgx* 直接使用）
#           - 名字含 pat / rgx / regex / re / pattern 的变量所赋的字面量
#
# 短字符串按 Lua 语义反转义（\\ \" \' → \\ " '，其余 \X 原样保留）；
# 长字符串 [[...]] 原样保留。纯文本字面量（如 "jos"、域名、提示语）不输出，避免噪声。
#
# 字符串扫描为手工逐字符进行，**能正确处理转义引号**（"x\"y"）与内嵌双引号，
# 不依赖正则匹配引号边界。
#
# 用法: awk -f regex-extract.awk <规则文件>
#
# 已知局限（提取为静态字面量分析，非 Lua 解析器）
# ------------------------------------------------------------
#   * 只识别**同一行内**的 `waf.rgx*(…, 第2参数)`；调用跨行则漏检。
#     （官方仓库现有规则/插件无跨行写法；`wafcheck.sh file` 会报「未提取到正则」，
#      此时请人工确认，或改用 `wafcheck.sh regex` 直接校验该正则。）
#   * 长字符串只支持 `[[…]]`，不支持 `[=[ … ]=]` 层级形式。
#   * 第 2 参数为函数调用/拼接（如 `waf.rgxMatch(uri, makePat())`）时无法静态求值，漏检。
#   * 变量赋值只识别单行 `name = "字面量"` / `name = [[字面量]]`。
#   * 「疑似」类靠变量名启发式（含 pat/rgx/regex/re…），可能误报或漏报，
#     故 file 子命令对「疑似-非法」只提示人工确认、不计入失败。
# 上述局限都不影响「确定」类命中的正确性。

# 反转义：只认 \\ \" \' 三种，其余 \X（\n \t \d \. 等）原样保留 ——
# 它们在 PCRE 里同样有意义，还原会破坏模式。
function unesc(s,   i, n, c, nx, out) {
    n = length(s); out = ""; i = 1
    while (i <= n) {
        c = substr(s, i, 1)
        if (c == "\\" && i < n) {
            nx = substr(s, i + 1, 1)
            if (nx == "\\" || nx == "\"" || nx == "'") { out = out nx; i += 2; continue }
        }
        out = out c
        i++
    }
    return out
}

# s 以 " 开头时解析短字符串字面量。
# 返回消耗的字符数（含首尾引号）；内层原始内容（仍含转义）写入全局 OUT。失败返回 0。
function short_lit(s,   i, n, c) {
    n = length(s)
    OUT = ""
    if (substr(s, 1, 1) != "\"") return 0
    i = 2
    while (i <= n) {
        c = substr(s, i, 1)
        if (c == "\\") {                      # 转义对：原样收下两个字符
            OUT = OUT c
            i++
            if (i <= n) { OUT = OUT substr(s, i, 1); i++ }
            continue
        }
        if (c == "\"") return i               # 未转义的收尾引号
        OUT = OUT c
        i++
    }
    return 0                                   # 未闭合
}

# s 以 [[ 开头时解析长字符串字面量（不支持 [=[ 层级）。
# 返回消耗的字符数；内容（原样）写入全局 OUT。失败返回 0。
function long_lit(s,   j) {
    OUT = ""
    if (substr(s, 1, 2) != "[[") return 0
    j = index(substr(s, 3), "]]")
    if (j == 0) return 0
    OUT = substr(s, 3, j - 1)
    return j + 3
}

# ---- 1) 变量赋值：local? name = "..." 或 [[...]] ----
{
    line = $0
    sub(/^[ \t]*/, "", line)
    sub(/^local[ \t]+/, "", line)
    if (match(line, /^[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*/)) {
        name = substr(line, 1, RSTART + RLENGTH)
        sub(/[ \t]*=.*$/, "", name)
        rest = substr(line, RSTART + RLENGTH)
        val = ""; isLong = 0
        if (substr(rest, 1, 1) == "\"") {
            if (short_lit(rest) > 0) val = unesc(OUT)
        } else if (substr(rest, 1, 2) == "[[") {
            if (long_lit(rest) > 0) { val = OUT; isLong = 1 }
        }
        if (val != "") {
            lit[name] = val
            if (isLong) longv[name] = 1
            if (tolower(name) ~ /pat|rgx|regex|re$|re[0-9]|pattern/) likev[name] = 1
        }
    }
}

# ---- 2) waf.rgx*(...) 第 2 参数 → 字面量记「确定」，变量名记入 rgxv ----
{
    l = $0
    while (match(l, /rgx[A-Za-z]*[ \t]*\([ \t]*[^,]*,[ \t]*/)) {
        after = substr(l, RSTART + RLENGTH)
        if (substr(after, 1, 1) == "\"") {
            if (short_lit(after) > 0) { p = unesc(OUT); def[p] = 1; seen[p] = 1 }
        } else if (substr(after, 1, 2) == "[[") {
            if (long_lit(after) > 0) { p = OUT; def[p] = 1; seen[p] = 1 }
        } else if (match(after, /^[A-Za-z_][A-Za-z0-9_]*/)) {
            rgxv[substr(after, 1, RLENGTH)] = 1
        }
        if (length(after) == 0) break
        l = after
    }
}

END {
    # 被 rgx* 使用的变量 → 其字面量升为「确定」
    for (v in rgxv) if (v in lit) def[lit[v]] = 1
    # 收集「疑似」：长字符串变量 + 名字像正则的变量
    for (v in longv) seen[lit[v]] = 1
    for (v in likev) seen[lit[v]] = 1
    for (p in seen) if (p != "") printf "%s\t%s\n", (p in def ? "确定" : "疑似"), p
}
