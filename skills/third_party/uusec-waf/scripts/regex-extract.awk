# Extract regex literals from UUSEC WAF Lua rule/plugin source code
#
# Outputs two TAB-separated columns: confidence \t regex
#   DEFINITE  a literal inlined as the 2nd argument of waf.rgx*(...),
#         or a literal assigned to a variable that is "used by waf.rgx* as the 2nd argument"
#   SUSPECT  the remaining literals that might be used as regexes:
#           - long strings [[...]] (not used directly by rgx*)
#           - literals assigned to variables whose names contain pat / rgx / regex / re / pattern
#
# Short strings are unescaped per Lua semantics (\\ \" \' → \\ " ', any other \X is kept as-is);
# long strings [[...]] are kept as-is. Plain-text literals (such as "jos", domain names, message strings) are not output, to avoid noise.
#
# String scanning is done manually, character by character, **handling escaped quotes correctly** ("x\"y") and embedded double quotes,
# without relying on regex matching of quote boundaries.
#
# Usage: awk -f regex-extract.awk <rule file>
#
# Known limitations (extraction is static literal analysis, not a Lua parser)
# ------------------------------------------------------------
#   * Only recognizes `waf.rgx*(…, 2nd argument)` **on the same line**; a call split across lines is missed.
#     (the existing rules/plugins in the official repo have no multi-line forms; `wafcheck.sh file` will report "no regex extracted",
#      in which case confirm manually, or use `wafcheck.sh regex` to check that regex directly.)
#   * Long strings: only `[[…]]` is supported; the `[=[ … ]=]` level form is not.
#   * When the 2nd argument is a function call/concatenation (e.g. `waf.rgxMatch(uri, makePat())`), it cannot be evaluated statically and is missed.
#   * Variable assignment: only the single-line form `name = "literal"` / `name = [[literal]]` is recognized.
#   * The "SUSPECT" class relies on a variable-name heuristic (containing pat/rgx/regex/re…), so it may over- or under-report,
#     which is why the file subcommand only asks for manual confirmation on "SUSPECT-INVALID" and does not count it as a failure.
# None of these limitations affect the correctness of the "DEFINITE" hits.

# Unescape: only \\ \" \' are recognized, any other \X (\n \t \d \. etc.) is kept as-is --
# they are equally meaningful in PCRE, and unescaping them would break the pattern.
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

# Parses a short string literal when s starts with ".
# Returns the number of characters consumed (including both quotes); the raw inner content (escapes still included) is written to the global OUT. Returns 0 on failure.
function short_lit(s,   i, n, c) {
    n = length(s)
    OUT = ""
    if (substr(s, 1, 1) != "\"") return 0
    i = 2
    while (i <= n) {
        c = substr(s, i, 1)
        if (c == "\\") {                      # escape pair: take both characters as-is
            OUT = OUT c
            i++
            if (i <= n) { OUT = OUT substr(s, i, 1); i++ }
            continue
        }
        if (c == "\"") return i               # unescaped closing quote
        OUT = OUT c
        i++
    }
    return 0                                   # not closed
}

# Parses a long string literal when s starts with [[ (the [=[ level form is not supported).
# Returns the number of characters consumed; the content (as-is) is written to the global OUT. Returns 0 on failure.
function long_lit(s,   j) {
    OUT = ""
    if (substr(s, 1, 2) != "[[") return 0
    j = index(substr(s, 3), "]]")
    if (j == 0) return 0
    OUT = substr(s, 3, j - 1)
    return j + 3
}

# ---- 1) variable assignment: local? name = "..." or [[...]] ----
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

# ---- 2) waf.rgx*(...) 2nd argument → the literal is recorded as "DEFINITE", the variable name is recorded in rgxv ----
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
    # variables used by rgx* -> their literals are promoted to "DEFINITE"
    for (v in rgxv) if (v in lit) def[lit[v]] = 1
    # collect "SUSPECT": long-string variables + variables whose names look like regexes
    for (v in longv) seen[lit[v]] = 1
    for (v in likev) seen[lit[v]] = 1
    for (p in seen) if (p != "") printf "%s\t%s\n", (p in def ? "DEFINITE" : "SUSPECT"), p
}
