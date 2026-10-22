# 规则编写

> **先读 `internals.md`**：执行顺序（ID 升序）、`RULE_ALLOW` 短路整链、规则库与规则集分离、内置规则不可改 —— 这四件事直接决定规则能不能生效。
> API 变量与函数全量清单见 `offline-docs/api.zh-CN.md`（官方原文）。本文只讲**怎么写对**。

---

## 一、规则模板

```lua
--[[
规则名称: <名称>
过滤阶段: <请求阶段 / 返回HTTP头阶段 / 返回页面阶段>
危险等级: <低危 / 中危 / 高危 / 严重>
规则描述: <功能概述，不写具体阈值参数，避免修改参数后描述失真>
--]]

-- <--- 配置参数 --->
-- 所有可调项集中在此，命名自解释，逐项中文注释
local enableXXX      = true        -- 总开关
local threshold      = 100         -- 时间窗口内允许的最大请求数
local timeWindow     = 60          -- 统计时间窗口，单位为秒
local banDuration    = 300         -- 超限后的封禁时间，单位为秒
local countStatic    = false       -- 是否统计静态资源请求

-- <--- 工具函数 --->
-- 复杂逻辑拆成局部函数，命名动词开头
local function isDynamic(waf)
    return waf.isQueryString or ((waf.reqContentLength or 0) > 0)
end

-- <--- 主逻辑 --->
local uri = waf.uri or ""          -- nil 安全

if not enableXXX then return false end

-- ...检测逻辑...

return false                    -- 放行（不拦截）
-- return waf.RULE_BLOCK, "原因" -- 拦截
-- return waf.RULE_ALLOW, "原因" -- 白名单（⚠️ 跳过后续整条规则链）
-- return waf.RULE_LOG_ONLY, "原因" -- 仅记录（v7.2.0+）
```

三个返回值常量：

| 常量 | 值 | 含义 |
|:---|:---|:---|
| `waf.RULE_BLOCK` | 1 | 拦截 |
| `waf.RULE_ALLOW` | 2 | 允许（**跳过后续全部规则**） |
| `waf.RULE_LOG_ONLY` | 3 | 仅记录（单规则观察模式，v7.2.0+） |

**分段骨架**：用 `-- <--- 名称 --->` 分节，推荐顺序 = 配置参数 → 工具函数 → 主逻辑。
配置参数一律**前置集中**（便于修改与交付）。
> 价值：**可调项集中在开头并逐项中文注释**，一眼看清这条规则能调什么、怎么调 —— 调整规则功能时不必通读主体逻辑，交付与评审也快。

---

## 二、编写规范

| 规范 | 说明 |
|:---|:---|
| **开头说明块必填** | 规则名称 / 过滤阶段 / 危险等级 / 规则描述 |
| **参数集中前置** | 阈值、时间窗口、封禁时长、开关用局部变量集中在开头，**逐项中文注释** |
| **分段骨架** | `-- <--- 配置参数 --->` / `-- <--- 工具函数 --->` / `-- <--- 主逻辑 --->` |
| **命名自解释** | 变量名带单位与语义（`banDuration` 而非 `t`），布尔用 `enable*` / `is*` / `count*` |
| **描述不写参数** | 规则描述写功能概述（如"累计攻击超过10次，则在10分钟内拦截该 ip 访问"），阈值变化时不失真 |
| **注释克制** | 必要说明放开头与参数区，主体少写注释 |
| **阶段意识** | 请求阶段只用请求变量；返回头阶段才有 `waf.status`；返回页面阶段才有 `waf.respBody` |
| **nil 安全** | `(waf.host or "")`、`(waf.uri or "")` 防护 |
| **`waf.ipBlock` 慎写** | 官方未标只读，但内置规则 13 用"只读 + 续期"写法（`set` 的值取自 `get`）；**规则自行 `incr` 会与引擎拦截写入造成双计数**。状态存储优先用 `waf.ipCache` |
| **规则里没有 `ngx`** | 规则跑在**受限沙箱**（全局名白名单已实测，`ngx` 不在其中）→ 用 `ngx` 会直接报错，`require` 也不可用。需要 `ngx` 就写成插件（见 `internals.md` §五之二） |
| **局部别名** | 顶部 `local rgx, kv = waf.rgxMatch, waf.kvFilter` —— 避免每次请求重复查表（官方内置惯用） |
| **廉价判据先行** | 先用 `startWith` / `contains` / 头字段判空早退，再进正则或语义引擎 |
| **扫全输入面** | `form["FORM"]`(+`valOnly`) → `form["FILES"]`(`knFilter`) → `queryString` → `cookies` → `reqHeaders` → `uri` → `referer`/`userAgent`；少一个面就是绕过通道 |
| **多重解码** | `htmlEntityDecode` / `urlDecode` / `base64Decode` 后再匹配（官方内置的常规做法） |
| **语义引擎优先** | `checkSQLI` / `checkRCE` / `checkXSS` / `checkPT`，**不要手搓正则做语义检测**；特征正则只用来补语义漏掉的特定家族 |
| **畸形即拦** | `hErr` / `qErr` / `cErr` / `fErr` 非 `unknown` 即判恶意构造 |
| **类型防御** | `waf.reqHeaders.cookie` 可能是 table（多 Cookie 头）—— 用前 `type()` 判断并 `table.concat` |
| **正则必须先验证** | 见「§二之二、正则：引擎、选项与验证」；用 PCRE 语法、`"jos"` 选项 |
| **字符类含 `.` 要补 `..` 检查** | `[A-Za-z0-9._:-]+` 能匹配 `..`，必须另加 `not waf.contains(uri, "..")` |
| **交付前自检** | 语法校验 + 正则校验 + 应拦/应放样例（见「§五、规则输出规范」） |

---

## 二之二、正则：引擎、选项与验证

### 引擎是 PCRE（PCRE1 8.45 + JIT）

实测（`sbin/uuwaf` 二进制）：

| 证据 | 结论 |
|:---|:---|
| 版本串 **`8.45 2021-06-15`** | **PCRE1 8.45**（非 PCRE2、非 RE2） |
| `pcre_exec` / `pcre_compile` / `pcre_study` / `pcre_fullinfo` 符号存在 | 动态链接 **PCRE1** |
| **`pcre_jit_exec` 存在** | **启用 JIT** |
| `pcre2_compile_8` 出现 **0 次** | **不是 PCRE2** |
| 容器 `lib64/libpcre.so.1.2.10`、`grep -P` 依赖 `libpcre.so.1` | 运行时同源 |

`waf.rgxMatch` / `rgxGmatch` / `rgxSub` / `rgxGsub` 的官方说明是**「用法同 `ngx.re.*`」**，因此**语法 = PCRE1 8.45**。

**PCRE 支持但 Lua 模式串不支持**（写规则时的关键差别）：

- 字符类、量词、分组、锚点、`\d\w\s\b` 等转义
- 前瞻/后顾 `(?=)` `(?<=)`
- 非贪婪 `*?` `+?`
- 命名分组 `(?<name>…)`
- 动词 `(*FAIL)` `(*SKIP)`

**PCRE1 8.45 与 PCRE2 的关系**（实测；WAF 主机上跑 `pcrecheck.py engine` 会用容器内 PCRE1 逐项复核）：

- ✅ **两边都支持**（放心用）：字符类、量词、分组、锚点、`\d\w\s\b`、前瞻/后顾（**定长**）、非贪婪 `*?`、命名分组 `(?<n>…)`、子程序 `(?&n)` / `(?(DEFINE)…)`、条件组、**`\K` 环视复位**、**分支重置 `(?|…)`**、占有量词、`(*SKIP)(*F)`、`\p{…}`。
- ❌ **仅 PCRE2 合法、PCRE1 8.45 拒绝**（写规则时避免）：
  - **变长后顾** `(?<=a{1,3})` `(?<=ab+)` —— PCRE1 要求后顾**定长**（报 `lookbehind assertion is not fixed length`）。
  - **裸整串递归** `(?R)` —— PCRE1 报 `recursive call could loop indefinitely`。

### 选项：用 `"jos"`

| 选项 | 含义 | 建议 |
|:---|:---|:---|
| `j` | JIT 编译 | ✅ 必开（引擎带 JIT） |
| `o` | 只编译一次并缓存 | ✅ 必开（规则在同一 worker 内复用） |
| `s` | 单行模式（`.` 匹配换行） | ✅ 建议（匹配 `\r\n` 注入类载荷时必需） |
| `i` | 忽略大小写 | 按需 |
| `u` | UTF-8 模式 | 内容含多字节字符且用到 `.`/字符类时考虑 |
| `m` | 多行 | 按需 |

### 必须验证（**两个通道，按环境择一**）

**判断依据很简单：本机是不是 WAF 主机（有没有 UUWAF 容器）。**

| 场景 | 用哪个 | 为什么 |
|:---|:---|:---|
| agent 与 WAF **不同机**（**常态**） | `scripts/pcrecheck.py` | ctypes 绑定系统 PCRE2，无需容器，任何有 Python3 的机器都能跑 |
| 本机**就是** WAF 主机 | `scripts/wafcheck.sh` | 容器内 PCRE1，与运行时**链接同一个库**，保真度最高 |
| 需要**权威 Lua 语法校验** | 只能在 WAF 主机用 `wafcheck.sh lua`（luajit） | Python 标准库没有 Lua 解析器 |

> **手上既没有 WAF 容器、也没装 lua/luajit 时**（很常见）：`pcrecheck.py lua` 只是启发式冒烟。按优先级三选一：
> ① 让 WAF 主机代校验（`wafcheck.sh lua`，权威）；② 宿主机装一个 luajit（`apt install luajit` / 包管理器，同为 Lua 5.1 语法）自校；
> ③ 都没有时**必须在交付说明里写明"未做权威 Lua 语法校验"**，不能默默当成通过。

> 🔴 **不要用 Python 的 `re` 模块或 `grep -E` 校验**：它们不是 PCRE —— `\d`、变长后顾、占有量词、`(?(DEFINE))` 等行为都不同，会给出"全部通过"的假结论。
> 🔴 **不要用 `grep -P` 的返回值当作唯一依据并省略样例**：宿主 `grep -P` 可能链接 PCRE2，与运行时 PCRE1 不是同一库。
> ℹ️ **PCRE2 与 PCRE1 的差异**：`pcrecheck.py` 是 PCRE2，WAF 运行时是 PCRE1 8.45。**实测**两边一致支持 `\K`、分支重置 `(?|…)`、子程序 `(?&n)`、`(?(DEFINE)…)`、占有量词、`(*SKIP)(*F)`、`\p{…}`。**真差异只有两处**：**变长后顾**（`(?<=a{1,3})`）与**裸递归**（`(?R)`）—— PCRE2 合法、PCRE1 拒绝，写规则时避免。本机即 WAF 主机时，`pcrecheck.py engine` 会用容器内 PCRE1 逐项实测复核（不靠静态清单）。

**① 独立版 `pcrecheck.py`（默认选它）**

```bash
python3 <skill目录>/scripts/pcrecheck.py engine                      # 自检：PCRE 版本/JIT/能力
python3 <skill目录>/scripts/pcrecheck.py regex '<正则>' '<应命中>' '<应放过>'
python3 <skill目录>/scripts/pcrecheck.py cases '<正则>' <测试串文件>  # 按行批量，忽略空行与 # 注释
python3 <skill目录>/scripts/pcrecheck.py extract <规则文件>          # 提取全部正则逐个校验（别名 file）
python3 <skill目录>/scripts/pcrecheck.py lua <规则文件>              # 启发式冒烟（非权威）

# 通用选项
-o OPTS              选项字母，对齐 `"jos"`，默认 "s"：s=i=m=u=x=j=o=（j/o 在校验中无副作用）
--pattern-file F     从文件读正则（避开 shell 转义）
--subject-file F     从文件读测试串（整份文件作为一个测试串）
```

> 正则与样例一律经**文件/参数**传入，不拼 shell 串 —— 含反斜杠、`$( )`、引号的模式与样例都保真，也不会被命令替换执行。
> `extract` 的提取器比 awk 版强：**支持跨行 `rgx*()` 调用**、**支持 `[=[ ]=]` 层级长字符串**、**正确跳过注释**（不会把注释里的假调用当正则）。

**② 容器版 `wafcheck.sh`（仅 WAF 主机）**

```bash
bash <skill目录>/scripts/wafcheck.sh engine
bash <skill目录>/scripts/wafcheck.sh regex '<正则>' '<应命中>' '<应放过>'
bash <skill目录>/scripts/wafcheck.sh cases '<正则>' <测试串文件>
bash <skill目录>/scripts/wafcheck.sh lua   <规则文件>    # 权威 Lua 校验 → SYNTAX_OK
bash <skill目录>/scripts/wafcheck.sh file  <规则文件>    # Lua + 正则（awk 提取器）
```

脚本自动定位 WAF 容器（镜像名含 `uusec/waf`、或容器内存在 `/uuwaf/sbin/uuwaf`），也可用 `WAF_CONTAINER=<名>` 或 `--container <名>` 指定。

**③ 手工最小命令（仅用于肉眼快速确认，不作为交付校验）**

```bash
# 语法：退出码 0=匹配 / 1=不匹配 / 2=正则非法（stderr 给出原因）
docker exec <waf容器> sh -c 'printf "%s" "<测试串>" | grep -qP "<正则>"'
```

> ⚠️ 该命令把正则与测试串拼进了 shell 串 —— **含反斜杠、`$`、引号时会失真甚至被 shell 执行**。**交付校验必须用上面两个脚本。**
> 实测：`grep -qP "abc("` → **exit 2**（非法）。
> 实测容器内：`grep (GNU grep) 3.1` 动态链接 `libpcre.so.1 → libpcre.so.1.2.10`（PCRE1），`LuaJIT 2.1`。

**④ 同时校验 Lua 语法与字符串转义**

权威 Lua 校验只存在于容器版（`wafcheck.sh lua`，走 luajit）：

```bash
docker exec -i <waf容器> sh -c 'cat > /tmp/rule.lua' < <规则文件>
docker exec <waf容器> sh -c '/uuwaf/luajit/bin/luajit -e \
  "local f,e=loadfile(\"/tmp/rule.lua\"); print(f and \"SYNTAX_OK\" or (\"ERR: \"..tostring(e)))"'
```

> ⚠️ 实测：Lua 短字符串里 `"\d"` 会报 `invalid escape sequence` —— **正则里的 `\d` 在 `"…"` 中必须写成 `\\d`**；用 `[[ ]]` 长字符串则**原样保留**（`[[\d]]` 就是 `\d`）。这是写含正则规则时最常踩的坑。
> 无容器时用 `pcrecheck.py extract`：它会**按 Lua 语义反转义**短字符串（`\\-` → `\-`）再校验、区分短/长字符串、并正确跳过注释。

### 验证后交付

**任何含正则的规则/插件，交付前必须先跑通校验**，并给出：
- 应命中的样例（≥2 条）
- 不应命中的样例（≥2 条，含边界与绕过尝试）

> 实测示例：`^/file/[A-Za-z0-9._:-]+$` 会命中 `/file/..`（因为字符类含 `.`）→ 证明"字符类含 `.` 必须另加 `..` 检查"。
> 实测示例：`^/api/v1/` 这类前缀匹配**会同时命中 `/api/v1/../../etc/passwd`** → 证明前缀写法不安全。

---

## 二之三、语义自检：rulecheck.py（补语法 / 正则的盲区）

Lua 语法过了、正则也合法，**不等于规则能用**。下面这些错只有语义层能抓：

| 会犯的错 | 例子 | 运行期表现 |
|:---|:---|:---|
| 不存在的 API | `waf.getHeader(...)`、`waf.checkSQLI2(...)` | 运行报错、规则失效 |
| 常量拼错 | `waf.RULE_BLOK` | 条件永假 / 永真 |
| 阶段不匹配 | 请求阶段用 `waf.status`、`waf.respBody` | 永远拿不到值（面板也禁用） |
| 规则里误用插件能力 | `waf.msg`、`waf.ctx`、`ngx.*`、`require(...)` | 报错 —— 规则沙箱里没有 `ngx`/`require`，`msg`/`ctx` 只在插件里有 |
| 插件钩子写错 | `_M.req_filter`（v4.1.0 前的旧名） | 插件**静默不执行** |
| require 了没有的模块 | `require("resty.redis")` | 插件运行报错（清单见 `plugin-authoring.md` §十） |

```bash
python3 <skill目录>/scripts/rulecheck.py all <文件> [--phase 0|1|2] [--plugin]
python3 <skill目录>/scripts/rulecheck.py dsl '<content JSON>'        # DSL(type=0) 结构（含正则合法性）
python3 <skill目录>/scripts/rulecheck.py symbols                     # 版本升级后：符号表 vs 官方文档是否同步
bash    <skill目录>/scripts/wafcheck.sh semantics <文件>             # WAF 主机上的同一入口
```

`all` **会连带跑 Lua 语法与正则**（有 WAF 容器或本机 luajit 时用权威通道，否则如实提示"未做权威校验"）——
所以**一条命令 ≈ 三件套**；`--no-lua` / `--no-regex` 可单独关掉。

- `--phase` 不传时**从头注释「过滤阶段:」自动识别**；认不出会提示（官方内置规则多无头注释，属正常）。
- 退出码：`0` = 通过（含仅提示）/ `1` = 有错误 / `2` = 用法错误。
- 它只管**名字与阶段**：能否编译仍须 `wafcheck.sh lua`，正则仍须 `pcrecheck.py`。**三件套一起跑才算完整校验。**

---

## 三、阶段与可用变量

| 阶段（`phase`） | 可用变量 |
|:---|:---|
| **请求阶段**（0） | `waf.ip` `waf.scheme` `waf.httpVersion` `waf.host` `waf.uri` `waf.method` `waf.reqUri` `waf.userAgent` `waf.referer` `waf.reqContentType` `waf.XFF` `waf.origin` `waf.reqHeaders` `waf.hErr` `waf.isQueryString` `waf.reqContentLength` `waf.queryString` `waf.qErr` `waf.form` `waf.form["RAW"]` `waf.form["FORM"]` `waf.form["FILES"]` `waf.fErr` `waf.cookies` `waf.cErr` `waf.requestLine` `waf.ipBlock` `waf.ipCache` |
| **返回 HTTP 头阶段**（1） | 上述 + `waf.status` `waf.respHeaders` `waf.respContentLength` `waf.respContentType` |
| **返回页面阶段**（2） | 上述 + `waf.respBody` `waf.replaceFilter` |

**面板的硬性约束（实测前端逻辑）**：**请求阶段下 `waf.status` 与返回头/返回内容相关参数被禁用**，切到返回头或返回页面阶段才放开。
（前端表现：`phase===0` 禁用第 13~17 项参数；`phase===1` 放开 13~16、仍禁用第 17 项；`phase===2` 全放开。）

> 对应到变量：**请求阶段拿不到 `waf.status`、`waf.respHeaders`、`waf.respBody`**。
> **按响应状态计数（如 404 爆破防护）必须用返回 HTTP 头阶段** —— 这正是内置规则 70 处于 `phase=1` 的原因。

关键细节：

- `waf.uri` 是**解码后、不带参数**的 URI → `==` 全等与锚定正则不会被 query 干扰。
- `waf.reqUri` 是**原始 URI，带参数**。
- `waf.isQueryString` 是 **bool**（是否存在请求参数），`waf.queryString` 是 **table**。
- `waf.form["FILES"]` 结构：`{name={[1]="filename",[2]="file content"}}`；`waf.form["FORM"]` 结构：`{uid="12", vid={[1]="select",[2]="a from b"}}`。
- 返回头阶段的 `waf.status` 是整数。
- 返回页面阶段改内容需**同时**赋值 `waf.respBody = newstr` 和 `waf.replaceFilter = true`；且只在 `respContentType` 为 text/html、text/plain、json、xml 时可用。

---

## 三之二、可视化规则（DSL）

面板除 Lua 规则外还提供**可视化规则构造器**，产出的规则 `type=0`、`content` 为 JSON。**官方文档未收录**，下列结构取自面板前端实现（v7.2.5 —— 就是序列化这段 JSON 的代码本身）。

### 数据格式

```js
// 面板真实序列化逻辑（RuleMgr）
e = []                       // 收集条件
for each 条件: e[i] = [key, op, val]
if (#e > 1) then table.insert(e, 1, dslLogic) end     // 多条件：逻辑符插到数组首位
content = JSON.stringify([dsl_action, e])
```

| 位置 | 含义 | **存库取值** |
|:---|:---|:---|
| `[0]` | 动作 `dsl_action` | **`1`** 拦截 / **`2`** 允许 / **`3`** 只记录 |
| `[1][0]` | 逻辑 `dsl_logic`（**仅多条件时存在**） | **`"&"`** 与 / **`"\|"`** 或 / **`"~&"`** 非与 / **`"~\|"`** 非或 |
| `[1][i]` | 条件 | `[ key, op, val ]` 三元组 |

**示例**：

```json
[1, [["uri", "*", "/.env"]]]
[1, ["&", ["ip", "=", "203.0.113.9"], ["uri", "*", "/.env"]]]
[2, ["|", ["uri", "^", "/static/"], ["uri", "^", "/assets/"]]]
```

🔴 **两个高频踩坑**：

1. **存的是数字与符号，不是英文名**。面板 i18n 里存在 `include` / `ipMatch` / `startsWith` / `block` 这类**显示用 key**，它们**不是存库值** —— 照 i18n 写 JSON 会产出无效规则。
2. **取反 = 前缀 `~`**（`~*` `~.` `~-` `~=`）；逻辑非与/非或是 `"~&"` / `"~\|"`。

**参数（key）与操作符（op）的完整取值表见 `management-api.md` §3.2**（含请求侧与响应侧全部字段、操作符符号表）。

### 面板内置校验（照抄其逻辑 = 官方认可的自查标准）

```js
// 操作以 "." 结尾（即 regex / notRegex）→ 校验正则是否合法
if (op.endsWith("."))   { try { new RegExp(val, "") } catch(e) { 报错并中止 } }
// 操作是 > 或 < → 值必须是数字
else if (op === ">" || op === "<") {
    if (!/^[+-]?\d+(\.\d+)?$/.test(val)) { 报错 "The value must be number" }
}
```

> **要点**：面板用 JS `RegExp` 校验，**运行时是 PCRE**。两者高度兼容但不完全等价 —— 用到有差异的语法（变长后顾、裸递归）时用校验脚本再验一次（`pcrecheck.py regex`；WAF 主机上可用 `wafcheck.sh regex` 走 PCRE1）。
> 面板按 `phase` 动态禁用响应侧参数：**请求阶段禁用 `status` / `resp*`**，切到返回头或返回页面阶段才放开。

### 何时用 DSL、何时用 Lua

| 场景 | 选择 |
|:---|:---|
| 简单的 IP / 路径 / 头部条件组合 | **DSL**（免写代码，面板可视化维护） |
| 需要计数、频率、共享内存、多步判断、响应改写 | **Lua** |

> 两者在同一个规则库共存，ID 分配规则相同。

---

## 四、模式库

每个模式都标注了**是否来自官方内置规则**（内置规则的写法最可靠）。

### 4.1 CC / 频率防护（官方内置规则 66 原文风格）

```lua
if not waf.startWith(waf.toLower(waf.uri), "/api/") then
    return false
end

-- 排除真实搜索引擎，避免影响收录
local se, ok = waf.searchEngineValid({"180.76.76.76"}, waf.ip, waf.userAgent)
if se and ok then
    return false
end

local sh = waf.ipCache
local ccIp = 'cc-' .. waf.ip
local c, f = sh:get(ccIp)
if not c then
    sh:set(ccIp, 1, 60, 1)                 -- 60 秒计数窗口，flag=1 计数中
else
    if f == 2 then
        return waf.block(true)             -- 封禁中：重置 TCP（不记日志）
    end
    sh:incr(ccIp, 1)
    if c + 1 >= 100 then
        sh:set(ccIp, c + 1, 300, 2)        -- 封禁 300 秒，flag=2 封禁中
        return waf.RULE_BLOCK, ccIp
    end
end
return false
```

要点：`get` 返回 `值, flag`；`set(key, 值, exptime, flag)` 第 4 参数是**自定义状态位**。

> `flag` 是官方示例里的一个**约定**（官方未定义取值范围），用 `1` / `2` 区分「计数中」与「已封禁/验证中」两种状态，使同一个 key 能承载"计数 + 状态"两重语义。
> 官方 anti-cc 示例注释同样标注 `-- 设置1分钟也就是60秒访问计数时间` / `-- 设置5分钟也就是300秒拦截时间`。

### 4.2 机器人攻击防护（官方内置规则 68 原文风格）

与 4.1 同构，但**跨过阈值时启动人机验证**，而不是直接返回拦截：

```lua
local sh = waf.ipCache
local robotIp = 'rb:' .. waf.ip
local c, f = sh:get(robotIp)

if not c then
    sh:set(robotIp, 1, 60, 1)            -- 60 秒计数窗口，flag=1 计数中
else
    if f == 2 then
        return waf.checkRobot(waf)       -- 已进入验证态：弹出滑动旋转验证码
    end
    sh:incr(robotIp, 1)
    if c + 1 >= 360 then
        sh:set(robotIp, c + 1, 1800, 2)  -- 进入验证态，30 分钟验证窗口
        return waf.RULE_BLOCK, robotIp   -- 首次跨阈值仍返回拦截
    end
end
return false
```

> **注意区分两个分支**：
> - **首次跨阈值** → `sh:set(..., 2)` 置为验证态 + **返回 `RULE_BLOCK`**；
> - **此后 `flag == 2`** → 才走 `waf.checkRobot(waf)` 弹出验证码。
>
> 所以是"先拦一次，随后改为要求验证"，不是直接起验证码。

- `waf.checkRobot(waf, expireTime?, max?)`：默认 600 秒 / 18000 次后重新验证。
- `waf.checkTurnstile(waf, siteKey, secret, expireTime?, max?)`：用 Cloudflare Turnstile。
- 🔴 用人机验证时**必须同时放行 `/static/` 和 `/api/v1/captcha/`**，否则验证页的 CSS/JS 被拦截、页面无法渲染。

### 4.3 响应状态类防护（官方内置规则 70，返回 HTTP 头阶段）

```lua
local sh = waf.ipCache
local ccIp = '404-' .. waf.ip
local c, f = sh:get(ccIp)
if f == 2 then
    return waf.block(true)
end
if waf.status ~= 404 then
    return false
end
if not c then
    sh:set(ccIp, 1, 60, 1)
else
    sh:incr(ccIp, 1)
    if c + 1 >= 10 then
        sh:set(ccIp, c + 1, 300, 2)
        return waf.RULE_BLOCK, ccIp
    end
end
return false
```

> **按响应状态计失败，必须用返回 HTTP 头阶段 + `waf.status`**。请求阶段的"按请求数计数"只是近似防护。

### 4.4 读取「已拦截 IP 的攻击次数」（官方内置规则 13，`waf.ipBlock` 用法）

```lua
local ib = waf.ipBlock
local c = ib:get(waf.ip)
if c and c >= 10 then
    ib:set(waf.ip, c, 600, 1)          -- 第3参 600 = TTL，续期 10 分钟，不改计数
    return waf.RULE_BLOCK, "ip blocked for continue attack: " .. waf.ip
end
return false
```

> `waf.ipBlock` 是**「被拦截 IP」的记录**：键 = IP，值 = **累计拦截次数**。**规则拦截时由 WAF 引擎自动写入**（插件拦截**不自动**，需手动 `ngx_kv.ipBlock:incr(waf.ip, 1, 0, 600)`）。
> 用途正是**判断某 IP 的攻击次数** —— 官方内置规则 13「高频攻击防护」就是这么做的；你也可以在自己的规则里读它做分级处置。
> 🔴 **TTL = 600 秒（10 分钟）**：规则 13 的 `ib:set(waf.ip, c, 600, 1)` 把 TTL **重置为 10 分钟**（不递增计数）。**停止触发拦截后计数会自然清零**，封禁自行解除 —— 官方描述为「累计攻击超过 10 次，则在 **10 分钟内**拦截该 ip 访问」。
> 🔴 规则侧**只读**：可以 `get`、可做续期式 `set`，**不可覆盖计数**；状态存储用 `waf.ipCache`。
> 🔴 依赖 `waf.ipBlock` 的规则**对 ID 位置有要求**（见 `internals.md` §二）。

### 4.5 上传文件检测（`waf.knFilter`）

```lua
local function fileContentMatch(v)
    local m = waf.rgxMatch(v, "<\\?php|<jsp:|<%(?i:!|\\s*@)", "jos")
    if m then
        return m, v
    end
    return false
end
if waf.form then
    local m, d = waf.knFilter(waf.form["FILES"], fileContentMatch, 0)   -- p=0 匹配文件内容，p=1 匹配文件名
    if m then return waf.RULE_BLOCK, d end
end
```

### 4.6 键值对检测（`waf.kvFilter` / `waf.jsonFilter`）

```lua
local function rceMatch(v)
    if waf.checkRCE(v) then
        return true, v
    end
    return false
end

-- 匹配 queryString / cookies 等键值对（valOnly=true 只匹配 value）
local m, d = waf.kvFilter(waf.queryString, rceMatch, true)

-- 遍历 JSON body（parsed=false 表示 v 是字符串）
local m, d = waf.jsonFilter(waf.form["RAW"], rceMatch, false, true)
```

### 4.7 白名单（⚠️ 高风险，务必窄）

> **代价再强调一次**：命中后**后续规则与 ML 校验都不再执行**（返回头阶段的插件钩子也会被跳过，精确清单见 `internals.md` §三之三）—— 放行范围必须窄到"即使此后不做任何检测也安全"的程度。

> **执行前提**：规则按 ID 升序执行，"命中即跳过后继全部规则"的语义**只在 ID 小于所有拦截类规则时成立**。要把自定义规则放到最前，用官方预留的 **ID 9**（种子数据描述：「留下备用，用于自定义最高优先级规则」）—— 该槽位用途不限，放行只是其中一种用法。

```lua
if waf.host == "app.example.com"
   and waf.method == "POST"
   and (waf.uri or "") == "/api/v1/task/submit"           -- 精确匹配优先
   and not waf.contains((waf.uri or ""), "..")            -- 防路径遍历
   and waf.reqContentType
   and waf.startWith(waf.toLower(waf.reqContentType), "application/json")
then
    return waf.RULE_ALLOW, "已放行：<业务说明>（<误报根因>）"
end
```

**放行条目自查表**（交付白名单时必须逐条验证）：

| 用例 | 期望 |
|:---|:---|
| 同路径、改 User-Agent | 不放行 |
| 同路径、改 method | 不放行 |
| 同路径、加后缀 `/x` | 不放行 |
| 同路径、插 `../` | 不放行 |
| 同路径、换 content-type | 不放行 |
| 不同 host 同路径 | 不放行 |

### 4.8 数据脱敏（返回页面阶段）

```lua
if waf.respContentLength == 0 or waf.respContentLength >= 2097152 then
    return
end

local newstr, n, err = waf.rgxGsub(waf.respBody, [[\b1[3-9]\d{9}\b]], function(m)
    return m[0]:sub(1, 3) .. "****" .. m[0]:sub(-4)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
if n > 0 then
    waf.respBody = newstr
    waf.replaceFilter = true          -- 通知南墙执行替换
end
```

> **数据脱敏属商业版能力**（社区版不可用）。但**规则里改 `respBody` 的机制本身是通用的** —— 这段代码示范的是 `waf.rgxGsub` + `waf.respBody` + `waf.replaceFilter` 的协同用法，可用于敏感词替换、URL 重写等任何返回内容改写场景。
> 大响应体先按 `respContentLength` 短路，避免无谓开销。

### 4.9 地区访问控制

```lua
local country, province, city, iso = waf.ip2loc(waf.ip, "zh-CN")
if country == "中国" then
    return false
end
return waf.RULE_BLOCK, "地区限制"
```

### 4.10 官方内置惯用法（从 50 条内置规则提炼，可直接复用）

| 惯用法 | 写法 | 为什么 |
|:---|:---|:---|
| **局部别名** | `local rgx, kv = waf.rgxMatch, waf.kvFilter` | 避免每次请求重复查表 |
| **最便宜的判据先行** | `if not waf.startWith(waf.toLower(waf.uri), "/api/") then return false end` | 非目标流量零成本早退 |
| **长度 / 头字段短路** | `if waf.reqHeaders.next_action == nil then return false end`；`if waf.reqContentLength >= 131072 then …` | 不解析 body 就能排掉大部分请求 |
| **扫全输入面** | FORM → FILES → queryString → cookies → reqHeaders → uri → requestLine → referer → userAgent | 漏一个面就是绕过通道 |
| **多重解码** | `htmlEntityDecode` / `urlDecode` / `base64Decode` 后再匹配 | 对抗编码绕过 |
| **语义引擎 + 特征互补** | `checkXSS(v) or rgx(v, "<窄特征家族>", "jos")` | 语义引擎覆盖广，窄正则补特定家族 |
| **语义 level 按输入面取值** | 官方内置对不同面取不同 level（SQLi 规则：表单/query/cookie=3、请求头=默认；命令注入规则：表单=1、query=2、cookie=0、请求头=1） | **没有统一口径**：level 越高越严、误报越多；拿不准就照抄对应的那条内置规则 |
| **畸形即拦** | `hErr` / `qErr` / `cErr` / `fErr` 非 `unknown` 直接拦 | 解析失败多是恶意构造 |
| **类型防御** | `waf.reqHeaders.cookie` 可能是 table → 先 `type()` 判断再 `table.concat` | 官方规则 72 实测存在该分支 |
| **证据入日志** | `return waf.RULE_BLOCK, <命中的值或 RAW>` | 事后回溯与收敛误报的唯一线索 |
| **封禁期断连** | `return waf.block(true)` | 二次命中直接重置 TCP，省带宽 |

> ⚠️ **别照抄内置样本的写法**：官方内置里存在不规范返回（如规则 65 返回 `true, RAW, false` 而非 `waf.RULE_BLOCK` 常量）。**返回值一律用三常量，结构以本模板为准。**

### 4.11 检测原语与匹配 API 速查（选型表）

| 需求 | 用它 | 说明 |
|:---|:---|:---|
| SQL 注入 | `waf.checkSQLI(str[, level])` | 语义引擎；`level` 0~3，越大越严 |
| 命令注入 | `waf.checkRCE(str[, level])` | 同上 |
| XSS | `waf.checkXSS(str)` | 同上 |
| 路径遍历 | `waf.checkPT(str)` | 同上 |
| 内置特征模块 | `waf.plugins.<模块>.check()` | **无参**，返回 `true, 证据` / `false, nil`；模块：`scannerDetection` / `fileLeakDetection` / `weakPwdDetection` / `sqlErrorDetection` / `phpErrorDetection` / `javaErrorDetection` / `javaClassDetection`；**未收录于官方文档，但内置规则自身在用**（模块清单见 `pitfalls.md` §七） |
| 多串快速匹配 | `waf.pmMatch(sstr, {"a","b","c"})` | 多模匹配、命中即返回；优于 `for` + `inArray` |
| 简单包含 / 前后缀 | `waf.contains` / `startWith` / `endWith` | 最便宜，优先用 |
| 正则 | `waf.rgxMatch` / `rgxGmatch` / `rgxSub` / `rgxGsub` | 能不用就不用；必带 `"jo"` |
| 编解码 | `base64Decode` / `urlDecode` / `htmlEntityDecode` / `hexDecode` | 解码后再匹配 |
| 键值对 / 上传 / JSON 遍历 | `kvFilter` / `knFilter` / `jsonFilter` | 见 §4.5、§4.6 |
| 地理位置 | `waf.ip2loc(ip[, lang])` | 返回 `country, province, city, iso_code` |
| 根域名 | `waf.getRootDomain(host)` | **未收录于官方文档**，内置 RFI 规则在用；用时注意版本依赖 |
| 重定向 / 人机验证 / 拦截 | `waf.redirect(uri[, status])` / `checkRobot` / `checkTurnstile` / `waf.block(reset)` | 均**与 `return` 搭配** |

> 全量签名、参数与返回值以 `offline-docs/api.zh-CN.md`（官方原文）为准；本表只做选型。

> ⚠️ **引擎里还有 6 个官方文档未收录的名字**（从 `sbin/uuwaf` 的字符串表读出，v7.2.5）：
>
> | 名字 | 是什么 | 能不能用 |
> |:---|:---|:---|
> | `waf.getRootDomain(host)` | 取该 host 的**根域名**（用于判断跳转目标是否自家域） | 内置 RFI 规则在用 |
> | `waf.plugins.<模块>.check()` | 调用引擎内置检测模块（见本节上一行） | 内置规则在用 |
> | `waf.jsonDecode(str)` | JSON 解析（`util` 模块函数，基于 `cjson.safe`，返回 `值[, err]` 不抛异常） | 官方未收录、内置未用 |
> | `waf.checkJson(v)` | **JSON 攻击语义检测**（与 `checkSQLI`/`checkXSS`/`checkPT`/`checkRCE` 并列） | 同上 |
> | `waf.split(str, sep)` | 字符串分割（`util` 工具函数，与 `trim`/`inArray` 同组） | 同上 |
> | `waf.respContentEncoding` | 返回阶段的 `Content-Encoding`（gzip 等）状态 | 同上 |
>
> ⚠️ 这一组属内部实现，跨版本随时会变 —— 要用先在目标实例实测，**别写进交付规则**；官方文档收录的 API 足够覆盖常规需求。
>
> **两个机制事实**（解释了为什么本表的建议是对的）：
> - `checkSQLI` 底层是 **`resty.libinjection`**（引擎里以 `purify_sql` 封装）→ token 化 + 指纹式语义引擎，所以 `level` 越高越严、误报也越多。
> - `pmMatch` 底层是 **`ahocorasick`**（AC 自动机 C 扩展 `libac.so`）→ 多模匹配一遍扫描，这就是"别用 `for` + `inArray` 逐串比"的原因。
>
> 复核方法见 `internals.md` §三之三。

---

## 五、规则输出规范

当用户要求写规则时，按以下结构输出：

1. **需求分析** → 判断用基础规则、高级规则还是插件
2. **方案摘要** → 拦什么、怎么拦、适用范围
3. **威胁模型** → 攻击类型、关键特征、绕过方式
4. **规则代码** → 可直接复制（配置参数前置、分段骨架）
5. **测试样例** → 应拦截 + 应放行 + 边界（**含绕过尝试**）
6. **误报分析** → 可能误杀的业务场景
7. **部署建议** → ID/排序、灰度（`RULE_LOG_ONLY` 观察）、回滚方式
8. **校验结果** → **实际跑过的语法与正则校验输出**（不是"应该没问题"）

### 🔴 交付前必须验证（硬要求）

**未经校验的规则/插件不得交付**。至少完成：

| 校验 | 命令 | 通过标准 |
|:---|:---|:---|
| Lua 语法 | WAF 主机：`wafcheck.sh lua <文件>`（权威）／其他机：`pcrecheck.py lua <文件>`（启发式） | `SYNTAX_OK` ／ `BALANCED(heuristic)` |
| 每条正则 | `pcrecheck.py regex`（PCRE2）或 `wafcheck.sh regex`（PCRE1，WAF 主机） | 退出码 0/1（**2 = 正则非法，必须修**） |
| 应拦样例 | `pcrecheck.py cases` | 全部命中 |
| 应放样例 | 同上 | 全部不命中（含 `..`、大小写、后缀追加等绕过尝试） |
| **语义检查** | `rulecheck.py all <文件> [--phase N]` | 无 ❌ 项：API/常量/阶段/ngx/require/钩子 |
| **模块检查**（插件） | `rulecheck.py modules <插件文件>` | `require` 的模块都在实测清单内 |

### 交付前自查表（机器查不到，逐项过一遍）

| 项 | 自问 |
|:---|:---|
| 判据性质 | 写的是**可判定事实**还是**枚举症状**？换个文件名 / 端点 / 参数名还拦得到吗（枚举必漏） |
| 放行面 | 若用 `RULE_ALLOW`：host + method + 精确路径 + content-type 都限定了吗？`..` 检查加了吗？知道它会连插件一起跳过吗？ |
| 绕过样例 | `..`、大小写、后缀追加（`.bak`/`.old`）、URL 编码、多重编码、空字节、超长参数 —— 各想过一次吗？ |
| 性能 | 有没有 `for` 遍历大表（该用 `pmMatch`/`inArray`）？正则带 `jo` 吗？有没有把重活（解析大 body）放在每个请求上？ |
| 日志安全 | 会不会把 `Authorization` / `Cookie` / 口令写进 `error_log`？ |
| 灰度 | 首次上线是否 `RULE_LOG_ONLY`？观察期怎么比对（新规则拦下的集合 vs 原规则）？ |
| 回滚 | 改前备份做了吗？出事能按 `operations.md` §七 五分钟止血吗？ |

**交付时把校验命令、所用通道与结果一并给出**，让使用者可复现。
> 通道按环境择一：**agent 与 WAF 不同机是常态 → 用 `pcrecheck.py`（PCRE2）**；本机就是 WAF 主机 → 用 `wafcheck.sh`（PCRE1 同源）。用 PCRE2 校验时**如实注明**，并避免**真差异**语法：变长后顾 `(?<=a{1,3})`、裸递归 `(?R)`（`\K`、`(?|…)` 其实两边都支持）。**不用 Python `re`。**

---

## 六、规则 vs 插件：选择原则

| 方案 | 适用场景 | 复杂度 |
|:---|:---|:---|
| **DSL 可视化规则** | IP / 路径 / 头部条件的简单组合 | 最低 |
| **Lua 高级规则** | CC 防护、语义检测、速率限制、响应改写 | 中等 |
| **插件** | 多阶段处理、原生 `ngx` 对象、外部库/网络请求、跨阶段共享数据、Cookie 续期 | 最高 |

**关键差别**：

| 维度 | 规则 | 插件 |
|:---|:---|:---|
| 阶段 | 请求 / 返回头 / 返回页面（整段） | 每阶段再分 pre / post（10 个函数） |
| 与规则链关系 | **在规则链内**，`RULE_ALLOW` 会跳过后续规则与 ML 校验 | 在规则链**之外**；放行后**返回头阶段整段跳过**（含钩子），其余阶段仍执行 |
| 执行顺序 | 按规则 ID 升序 | 按 `priority` 降序（越大越先） |
| 原生 `ngx` | 不应依赖 | 正当用法 |
| 数据共享 | 共享内存字典 | `waf.ctx`（阶段间）+ 共享内存字典 |

> **能用高级规则解决就用高级规则**，不要升级为插件。插件开发与维护成本更高。

---

## 七、排障顺序

规则不生效时，按此顺序查：

1. **站点是否观察模式**（`mode`）—— 观察模式下不拦截。
2. **规则是否在该站点所用规则集里** —— 建好没挂进规则集 = 死规则。
3. **是否被更小 ID 的规则抢先处理** —— 尤其白名单类（`RULE_ALLOW` 短路整链）。
4. **规则 ID 位置是否满足要求** —— 依赖 `waf.ipBlock` 计数的后置类规则有硬性位置要求。
5. **规则是否被面板回滚** —— 内置自动维护条目改动会被回滚（判据是 ID 区段，不是 `type`/`uid`）。
6. **写操作是否因 `waf_nodes` 为空失败** —— 报 `No waf nodes`。
