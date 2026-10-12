# 运行时机制与特性

> 这些内容**官方 API 文档未收录或语焉不详**，来自对运行实例的实现层研究（nginx 配置、内置检测模块源码、内置规则 Lua 源码、Go 二进制内的前端实现）与实测。
> 规则编写与排障时**必须先读本文**，否则会写出「看起来对但不生效」的规则。

---

## 一、请求处理流水线

```
客户端
  │
  ├─ 80 / 443  ← nginx 直接监听（listen.conf）；443 走 http2
  │
  ▼
ssl_certificate_by_lua_block  → waf.http_ssl_phase()     [SSL 阶段，插件 ssl_pre/post]
  │
  ▼
rewrite_by_lua_block          → waf.req_filter()         [请求阶段：规则链 + 插件 req_pre/post]
  │
  ▼
upstream waf_backend          → waf.http_balancer_phase() [按站点配置选后端]
  │
  ▼
header_filter_by_lua_block    → waf.resp_header_filter() [返回头阶段：规则 + 插件]
  │
  ▼
body_filter_by_lua_block      → waf.resp_body_filter()   [返回页面阶段：规则 + 插件]
  │
  ▼
log_by_lua_block              → waf.http_log_phase()     [日志阶段：插件 log_pre/post]
```

要点：

- **规则链在 `req_filter` / `resp_header_filter` / `resp_body_filter` 三个位置执行**，与 `rule-authoring.md` 的「过滤阶段」一一对应。
- **插件在规则链之外**：插件钩子**成对包裹**规则链 —— `req_pre_filter`（官方命名：**请求阶段前过滤**）→ 规则链 → `req_post_filter`（**请求阶段后过滤**）。
  **规则没有"阶段前/阶段后"这种相位**：规则只属于阶段本体（`phase` 0/1/2），"阶段前/后"是插件独有的钩子位置，规则链本身才是该阶段的主流程。
  （可复核：`req_filter` 的字节码地址序 = `req_pre_filter` 0325 → 规则链 0391/0570 → `req_post_filter` 0818；返回头/返回内容阶段同构。）
- 🔴 **但"之外"≠"不受影响"**：`RULE_ALLOW` 命中后会置 `waf_ctx.in_whitelist` 标记，**不同阶段受影响程度不同** —— 精确清单见 §三之三。只记结论：**返回头阶段会被整段跳过（含该阶段的插件钩子），请求/返回页面/日志阶段的插件钩子仍会执行**。
- **管理后台独立**：控制台在 `4443`，其配置在 `/uuwaf/web/conf/config.json`（`addr` 字段）；**不经数据面**。
- **数据面自己读数据库**（不靠控制面推送）：`sbin/uuwaf` 内有一组 SQL 直查 —— `select \`id\`,\`phase\`,\`type\`,\`content\` from waf_rules`、`select \`id\`,\`content\` from waf_ruleset`、`select \`id\`,\`name\`,\`content\` from waf_plugins where \`enabled\`=1`、站点与证书各一条；控制面用 `set_purge` 失效缓存。这解释了"改完规则几秒内生效、且无需重启"。
- **插件执行优先级**：引擎侧对 `priority` 做 `table.sort`（降序），与 `waf_plugins` 查询的**无 `order by`** 配合使用（顺序由 Lua 排，不由 SQL 排）。
- **内置管理面**：`4447` 端口提供服务，`config.json` 的 `waf_nodes` 即指向它（`["127.0.0.1:4447"]`）。这正是**写规则/插件要求 `waf_nodes` 非空**的原因。

---

## 二、执行顺序：规则按 ID 升序

- 规则**按规则 ID 从小到大**依次执行，**命中拦截后不再匹配后续规则**。
- **规则集数组的顺序不影响执行顺序**（数组只表达"启用哪些"，见 `management-api.md` §3.3）。
- **ID 分区是硬约定**（依据官方种子数据与 CHANGELOG v6.7.0）：

| 区段 | 归属 |
|:---|:---|
| **`9`** | **官方预留位**。官方种子 SQL 原文（控制面二进制内 `INSERT INTO waf_rules`）：`(9, 1, 3, 'Custom', 0, 1, 'Reserved for defining custom highest-priority rules', 'return false', ...)` —— 名称 `Custom`、描述「**保留用于定义自定义最高优先级规则**」、内容仅 `return false`（面板中文是该字段的 i18n 显示） |
| `10 ~ 499` | **官方内置规则** |
| **`500 ~`** | **自定义规则**（自增分配） |

> **开发者口径**（与官方种子、官方仓库一致）：**同一阶段内规则按规则 ID 从小到大执行**。
>
> **为什么可以断定"顺序由 ID 决定"而不是"由规则集数组决定"**（四条互相独立）：
> 1. **官方种子的 `Default` 规则集 `content` 是 ID 降序**（`[75,74,73,…,19,…]`，见同一份种子 SQL）。若执行顺序 = 数组顺序，那 ID 9 这个"最高优先级预留位"就永远排在最后，官方不必特意留它。
> 2. 上游社区规则注释（见下）明确要求**与第一个内置规则交换位置**，而自定义规则 ID 从 500 起 —— 不可能靠数组位置实现"先执行"。
> 3. 面板保存规则集**不排序**（`filter` + `JSON.stringify`，只保留勾选项）→ `content` 只是"启用清单"，不具备顺序语义。
> 4. 引擎**按 ID 升序**执行；`内容` 里的数组顺序、以及面板里的显示顺序（本机默认集是 ID 降序）都不决定执行先后。
>
> 官方 CHANGELOG（v6.7.0）原文：「**防止默认规则覆盖自定义规则，自定义规则id范围调整起始值到500**」。
> 这就是为什么**自定义规则默认排在所有官方内置规则之后**，也因此**无法直接承担"前置总闸"角色** —— 除非用官方特意留出的 **ID 9** 槽位。
>
> ⚠️ **不要从 ID 大小反推"这条是不是自建的"**：ID 9 是官方预留的**最高优先级自定义位**，任何自建功能都可能放在那里。判据是**内容与来源**，不是 ID 落在哪一段。

- 官方 CHANGELOG 明确记载：「**新增白名单规则功能，匹配成功后不再匹配剩余规则**」—— 这就是 `RULE_ALLOW` 短路的官方依据（见下节）。
- 推论：**需要"前置总闸"语义的规则（放行、前置准入校验、统一拦截、限速…），ID 必须小于所有拦截类规则 ID**；官方为此预留了 **ID 9**（见上表）。它不限定用途——凡是要求"先于所有内置规则执行"的功能都放这里，具体实现由使用者决定。

> 上游社区规则 `rules/third_party/frequent-block-detection.lua` 的文件头注释原文（作者 MCQSJ）印证了这一点：
> 「！！！注意: 因为南墙WAF特性，此规则生效对**规则ID**有要求，需要将此规则与南墙自带规则的**第一个规则交换位置**才能生效！！！」
> 即**依赖 `waf.ipBlock` 累计计数的后置类规则**，必须落在"计数已产生、但拦截尚未发生"的位置上。

> 面板保存规则集时**不做排序**（`filter` + `JSON.stringify`，只保留勾选项），所以 `content` 的顺序是**勾选历史**
> —— 官方种子的 `Default` 集就是 ID 降序存放。**不要**从数组顺序或面板显示顺序推断执行先后。

---

## 三、`RULE_ALLOW` 跳过整条规则链（最高代价的认知）

白名单规则的注释原文：

> 「注意：此规则ID必须小于所有拦截类规则ID，否则白名单将失效。」

官方 CHANGELOG（v6.x 白名单功能条目）原文：

> 「新增白名单规则功能，**匹配成功后不再匹配剩余规则**」

这两句合起来才是完整语义：**`RULE_ALLOW` 不是"这一条不拦"，而是"跳过后续全部规则"** —— 而且**短路的不只是规则**（对插件的影响按阶段不同，见 §三之三）。

对照 `RULE_ALLOW` 的机制语义：

| 项目 | 结论 |
|:---|:---|
| 触发条件 | `host` / `method` / `uri` / `content-type` 等 —— 只是**触发条件** |
| 生效范围 | **命中后的整条规则链** —— 不是条件本身限定的范围 |
| 一并跳过 | 同路径上的 SQLi / RCE / XSS / webshell / 路径遍历 / 敏感文件 / RFI 检测，**以及频率与 CC 防护（13 / 66 / 70）** |
| 净效果 | 等于给该路径开一条**规则真空隧道** |

**设计自问**：用 `RULE_ALLOW` 前，先问一句「绕过之后这条路径还剩什么防护」——答案往往是「没有」：**后续规则与 ML 校验都不再跑**，只有日志类插件还会记录。

**因此放行条件必须尽量窄**：

1. **精确匹配优先于前缀**：`(waf.uri or "") == "/api/v1/task/submit"` 优于 `waf.startWith(waf.uri, "/api/v1/")`。
2. **路径含变量时用锚定正则** `^…$`：前缀写法会让 `/upload/<uuid>/../../etc/passwd` 也命中。
3. **多重锁定**：`host` + `method` + 路径 + `content-type`（必要时再叠 UA 或自定义头）。
4. **叠加 `..` 检查**：字符类里含 `.` 的正则（如 `[A-Za-z0-9._:-]+`）能匹配 `/a/../b`，**必须**另加 `not waf.contains((waf.uri or ""), "..")`。
5. **敏感文件类不整条放行**：放行一次等于永久关掉该路径的告警（例：私钥预览只放 `.pub`，不放整个路径）。

`waf.uri` 的官方定义是**解码后、不带参数的 URI**，所以 `==` 全等与锚定正则不会被 query 干扰（`?offset=…&token=…` 无效）。

---

## 三之二、规则 vs 插件：作用域与可用能力（最易混的一组概念）

| 维度 | 规则 | 插件 |
|:---|:---|:---|
| **作用域** | **站点级**：站点 → 一套规则集 → 规则；换站点就换集 | **全局**：插件库一份、对所有站点生效；要站点差异化，把站点配置写在插件内部（如 `site_auth_config`） |
| **执行位置** | 规则链**内**（`phase` 固定，一条规则只在一个阶段） | 规则链**外**，每阶段 pre/post 共 10 个钩子 |
| **会被放行绕过吗** | 会 —— `RULE_ALLOW` 命中即跳过后继全部规则与 ML 校验 | **部分会** —— 返回头阶段的插件钩子会被整段跳过，其余阶段仍执行（精确清单见 §三之三） |
| **可用 API** | 只有 `waf.*` | `waf.*` **＋ 原生 `ngx`**（`ngx.req` / `ngx.header` / `ngx.exit` / `ngx.shared` …） |
| **`ngx` 可用性** | ❌ **不要用**：官方 API 只提供 `waf.*`，内置 50 条规则 0 处使用 `ngx`，跨版本不保证 | ✅ 正当用法，官方插件均直接使用 |
| **跨阶段传状态** | ❌ 不可能（一条规则只跑一个阶段）；跨请求状态用 `waf.ipCache` | ✅ `waf.ctx` 在 pre/post 与各阶段间共享 |
| **`require`** | ❌ 不支持 | ✅ 支持（模块清单见 `plugin-authoring.md` §十） |
| **写在哪** | 面板「规则管理」（`type=1` Lua / `type=0` DSL） | 面板「插件管理」 |
| **灰度手段** | `RULE_LOG_ONLY` + 规则集启停 | `enabled` 开关 + 插件内总开关 + `priority` |

> 一句话：**规则 = 站点级、链内、只有 `waf.*`；插件 = 全局、链外、可跨阶段、可用 `ngx`。**
> **别把插件当成"白名单绕不过的强制层"** —— 放行会跳过一部分插件处理（§三之三）；要真正强制，只能**不写放行规则**，或在 WAF 之外再做一层。

---

## 三之三、`RULE_ALLOW` 命中后到底跳过了什么（代码级取证）

取证方法：`sbin/uuwaf` 里嵌了 12 段 **LuaJIT 字节码**，其中 17.9 KB 的那段就是 `waf.req_filter` / `resp_header_filter` / `resp_body_filter` / `http_log_phase` 的实现。导出后用容器内 `luajit -bl` 反汇编读控制流（无行号，靠字符串常量与跳转判定）。

`RULE_ALLOW` 命中（站点 `ip_whitelist` / `url_whitelist` 命中同理）后，引擎在 `waf_ctx.in_whitelist` 打标，后续行为**逐阶段不同**：

| 位置 | 白名单命中后的行为 | 反汇编依据 |
|:---|:---|:---|
| 请求阶段 · 剩余规则 | ❌ 跳过（规则循环 break） | 规则返回 `2` 后 `in_whitelist = true` → 跳出循环 |
| 请求阶段 · ML 校验 | ❌ 跳过 | 循环后 `if in_whitelist then goto 尾部` |
| 请求阶段 · `req_post_filter` | ✅ **仍执行** | 该调用点无条件执行（在尾部） |
| 请求阶段 · `req_pre_filter` | ✅ 必然已执行（在规则链之前） | 调用点在规则链之前 |
| 返回头阶段 `resp_header` | 先跑 `resp_header_pre_filter` → 随后 ❌ **整段提前返回**（**`resp_header_post_filter` 被跳过**，状态/头处理也跳过） | 入口先调 pre；`if in_whitelist then return` |
| 返回页面阶段 `resp_body` | 🔸 跳过解压/替换等主体处理，**`resp_body_post_filter` 仍执行** | `if in_whitelist then goto <post 调用点>` |
| 日志阶段 `log` | ✅ **完全不检查该标记** → `log_pre_filter` / `log_post_filter` 照常 | 该函数内无 `in_whitelist` 引用 |

> **一句话**："放行后插件也不跑"**只对返回头阶段成立**；请求阶段与日志阶段的插件照常执行 —— 所以**放行不会导致审计/日志丢失**，但也**不能靠插件补检测**。

**换版本后自己复核**（升级后引擎逻辑可能变）：

```bash
docker exec <容器> cat /uuwaf/sbin/uuwaf > /tmp/uuwaf.bin
python3 - <<'P'
import re
d = open('/tmp/uuwaf.bin','rb').read()
offs = [m.start() for m in re.finditer(rb'\x1bLJ', d)]        # LuaJIT 字节码魔数
for i, o in enumerate(offs):
    end = offs[i+1] if i+1 < len(offs) else len(d)
    open('/tmp/lj_%02d.ljbc' % i, 'wb').write(d[o:end])
P
docker cp /tmp/lj_04.ljbc <容器>:/tmp/   # 含 RULE_ALLOW / *_filter / in_whitelist 的那段
docker exec <容器> /uuwaf/luajit/bin/luajit -bl /tmp/lj_04.ljbc | grep -n 'in_whitelist\|pre_filter\|post_filter'
```

---

## 三之四、`rule_id = -1` 是什么（官方 FAQ）

拦截页面/日志里出现 `rule_id = -1`，**不是某条规则命中**，而是**该域名没有在站点管理里配置**：
南墙默认拦截未配置域名的访问（防黑域名解析指向引起的法律风险）。排查这类"莫名拦截"先看站点列表。

---

## 四、规则库与规则集分离

| 概念 | 载体 | 关键结论 |
|:---|:---|:---|
| 规则库 | `waf_rules` / `GET /rules` | 规则定义。**建好不挂进规则集 = 死规则，不生效** |
| 规则集 | `waf_ruleset.content`（JSON 数组） | 启用清单。一个站点挂一个集，一个集可被多站点引用 |

- 判断某规则是否生效：**先看它是否在站点所用规则集的数组里**（而不是看它是否存在）。
- 默认规则集 `Default` 不可删除。
- **低风险处置顺序**：① 改规则集（停用某条） → ② 加自定义规则并挂进集 → ③ 改规则正文（谨慎，见下节）。

---

## 五、内置自动规则不可改

- 内置拦截规则由面板**自动维护**，**改动会被回滚**（官方 CHANGELOG：「防止默认规则覆盖自定义规则」即该机制的由来）。
- ⚠️ **不要用「二进制里的种子 SQL」比对线上规则来判断有没有被改过**：种子有**中/英两份**（同一 id 两条 `INSERT`），且线上库可能是**旧版本**初始化后一路升级上来的，两者本就会不一致（实测 50 条内置里 46 条与某一份种子逐字吻合，`20`/`24`/`75` 对不上也不代表被改过）。判据是**改动是否被回滚**，不是与种子比文本。
- 📌 **ID `9` 不属于"改内置"**：官方种子把它定义成**预留的自定义位**（内容仅 `return false`，引用见 §二），就是留给使用者自建的位（改它不会被回滚）。真正的内置是 `10~499`。
- ⚠️ **`type` 与「是不是内置」无关**：`type` 是**规则编辑类型**（`0`=DSL 可视化规则 / `1`=Lua 规则）。判据是 **ID 区段**（`9`=预留位、`10~499`=内置、`≥500`=自定义）、**固定名称**与**改动是否被回滚**。
- 这意味着：即使内置规则的判据存在明显缺陷，也**不能直接修改它**。

已知的内置规则判据缺陷（实测复现）：

| 规则 | 缺陷 |
|:---|:---|
| 22 Boundary异常拦截 | `waf.strCounter(ct, "boundary")` 把 `boundary` 的**值**里的字样也计入，导致值里自带该字样的 boundary（如 `--abc-boundary-123`）被数成 2 次，误判为异常 |
| 11 Invalid protocol | 检测逻辑在内核（非 Lua），含 `checkContentDisposition` 类判定，无法从 Lua 侧修改 |

**处理方式**：内置规则的判据改不了（面板自动维护），**不要直接改它** —— 能做的只有：在**规则集**里停用该条，或对已确认的误报用规则 9 精确放行（`rule-authoring.md` §4.7）。

1. 新建**自定义规则**，复现内置规则的检测逻辑；
2. 在自定义规则内对**已确认的业务误报**做精确放行（`return false` 前短路）；
3. 在**规则集**里关掉原内置规则；
4. 把自定义规则挂进规则集。

> 顺序不可颠倒：**必须先有自定义规则接管、再关内置规则**，否则出现防护空窗。

---

## 五之二、规则运行在**受限沙箱**里（`ngx` 用不了，不是"不推荐"）

`sbin/uuwaf` 的初始化模块里会为规则构造一个受限环境的 `_G` 替身（`env._G = env`），
并**按白名单**注入全局名。v7.2.5 实测白名单原文（字节码字符串表）：

```
_VERSION error ipairs next pairs select tonumber tostring type unpack
os.clock os.difftime os.time
string.byte string.char string.find string.format string.gmatch string.gsub
string.len string.lower string.match string.reverse string.sub string.upper
table.insert table.maxn table.remove table.sort table.concat
```

**`ngx` 不在白名单里** → 规则里访问 `ngx`（或 `ngx.xxx`）会直接报错；`require` 同样不可用。
这解释了为什么官方 50 条内置规则**零次**使用 `ngx` —— 不是风格问题，是**环境里没有**。

> **插件不受此沙箱限制**：官方插件都直接用 `ngx` / `resty.*` / `require`。
> 要"用 ngx 做检测"→ 写成插件（见 `plugin-authoring.md`）。
> 复核方法同 §三之三（导出字节码搜 `_VERSION error ipairs`）。

---

## 六、可用的存储：共享内存字典

nginx 配置中声明了 **9 个共享内存字典**（`lua_shared_dict` 实测原文）：

| 字典 | 容量 | 用途 |
|:---|:---|:---|
| `ipCache` | 16m | 访问 IP 计数 / 状态（读写） |
| `ipBlock` | 8m | 已拦截 IP 记录（键=IP，值=累计拦截次数；规则拦截时引擎自动写入） |
| `stats` | 2m | 统计 |
| **`db`** | **32m** | **通用键值存储（容量最大）** |
| `robot` | 16m | 人机验证状态 |
| `purge` | 4m | CDN 缓存清理 |
| `lock` | 2m | 锁 |
| `live` | 2m | 实时状态 |
| `search_engines` | 8m | 搜索引擎验证 |

### 规则侧可用

| 变量 | 语义 | 约束 |
|:---|:---|:---|
| `waf.ipBlock` | **「被拦截 IP」的记录**：键=IP，值=累计拦截次数 | 官方标注「用法见 `ngx.shared.DICT`」，**读写 API 均可用** |
| `waf.ipCache` | 访问 IP 计数 / 状态的键值库 | 官方标注「用法见 `ngx.shared.DICT`」 |

**`waf.ipBlock` 的写入者（关键）**：

| 拦截方 | 是否自动写入 |
|:---|:---|
| **规则拦截** | ✅ **自动** —— 引擎在 `resp_header_post_filter` / `resp_body_post_filter` 阶段执行 `ip.incr.ipBlock` |
| **插件拦截** | ❌ **不自动** —— 插件须自行 `ngx_kv.ipBlock:incr(waf.ip, 1, 0, 600)` |

> **它的用途就是「记录被拦截的 IP」，可据此判断该 IP 的攻击次数** —— 官方内置规则 13 的实现基础。
> **TTL = 600 秒（10 分钟）**：每次规则拦截把 TTL **重置为 10 分钟**，**不递增计数**；停止触发拦截后计数自然清零，封禁自行解除。
> ⚠️ 官方没有把 `waf.ipBlock` 标为"只读"——它与其他 `ngx.shared.DICT` 一样可读写。
> 但**内置规则 13 的写法是刻意的「只读 + 续期」**（`set` 的值取自 `get` 结果，等于不动计数），
> 因为计数应由引擎的拦截动作负责递增；规则若自行 `incr` 会造成双计数。

内置规则 13（高频攻击防护）示范了 `waf.ipBlock` 的正确用法 —— **只读累计计数 + 续期，不自增**（代码见 `rule-authoring.md` §4.4）。

内置规则 66 / 68 / 70 示范了 `waf.ipCache` 的读写（`get` / `set` / `incr`，带 `exptime` 与 `flag`）：

```lua
local sh = waf.ipCache
local key = 'cc-' .. waf.ip
local c, f = sh:get(key)
if not c then
    sh:set(key, 1, 60, 1)        -- 60 秒计数窗口，flag=1 计数中
elseif f == 2 then
    return waf.block(true)       -- 封禁中：重置 TCP
else
    sh:incr(key, 1)
    if c + 1 >= 100 then
        sh:set(key, c + 1, 300, 2)  -- 5 分钟封禁，flag=2 封禁中
        return waf.RULE_BLOCK, key
    end
end
```

`flag` 是**自定义状态位**（官方未定义取值范围）：`1` = 计数中，`2` = 封禁中。它使同一 key 能承载"计数 + 状态"两重语义。

### 插件侧可用：原生 `ngx.shared`

插件里**可以用原生 `ngx` 对象**（`local ngx = ngx`），因此可直接访问全部共享字典：

```lua
local ngx_kv = ngx.shared
ngx_kv.db:set(session_key, expire_time, duration)   -- 用 32m 的 db 存会话
ngx_kv.ipCache:get(key)                              -- 与规则侧同一存储
ngx_kv.ipBlock:incr(waf.ip, 1, 0, 600)               -- 手动累加拦截计数
```

> 🔴 **写规则时不要依赖原生 `ngx`**。实测：**51 条内置规则中，`ngx.` 出现次数为 0** —— 内置规则一律使用 `waf.*` 封装 API。
> 原因：规则可能运行在与插件不同的受限环境中，原生 `ngx` 未必可用。**跨环境的可靠做法是坚持 `waf.*`**：`waf.ipCache` / `waf.ipBlock` / `waf.errLog` / `waf.rgx*` / `waf.block`。
> 插件则相反 —— 插件模板本身就要求直接操作 `ngx`（`ngx.req.get_headers()`、`ngx.header`、`ngx.exit()`），是原生上下文的正当用法。

### 选哪个存储

| 需求 | 选择 |
|:---|:---|
| 访问频率 / 状态计数 | `waf.ipCache` |
| 读已有拦截计数 | `waf.ipBlock`（只读） |
| 需要较大空间的通用键值（会话、映射、缓存） | 插件用 `ngx.shared.db`（32m） |
| 写日志 | `waf.errLog(...)`（规则）/ `require("waf.log").errLog(...)`（插件） |

---

## 七、内置检测模块的位置

内置检测逻辑分为两层：

| 层 | 位置 | 形态 | 可否修改 |
|:---|:---|:---|:---|
| **纯 Lua 检测模块** | `/uuwaf/waf/plugins/*.w` | 明文 Lua（AC 自动机 + 特征串表） | 文件系统层面可改，**但容器更新会覆盖，不应改动** |
| **内核 / 二进制判定** | nginx 模块 + Go 服务 | 不可读 | 不可修改 |

**明文可读的模块清单与误报排查流程见 `pitfalls.md` §七。**

---

## 八、上游请求头

WAF 转发给上游时注入的头部（官方 FAQ）：

| 头 | 含义 |
|:---|:---|
| `X-Waf-Ip` | 真实客户端 IP |
| `X-Waf-Id` | 该请求来自哪台 WAF 节点（值 = `config.json` 的 `id`），**集群模式下用于区分来源** |
| `X-Waf-Cache` | `HIT` = 已缓存，`MISS` = 未缓存 |

上游应用需要真实 IP 时，**优先读 `X-Waf-Ip`**，其次 `X-Forwarded-For`。

---

## 九、观察模式

三个层次的"只记录不拦截"：

| 层次 | 位置 | 粒度 |
|:---|:---|:---|
| **站点级** | 站点 `mode` 字段 | 整个站点 |
| **规则级** | 规则 `return waf.RULE_LOG_ONLY, …` | 单条规则 |
| **规则集级** | 规则集内容（停用某条） | 该站点 |

- `waf.RULE_LOG_ONLY`（值 `3`）自 **v7.2.0** 起提供，用于**单条规则的观察模式**。
- **v7.2.0 声明与旧版本规则不兼容**，不支持从旧版本直接升级 —— 升级前需核对版本分水岭。
- 站点级观察模式即使规则返回 `RULE_ALLOW` 也仍记录日志，因此**白名单不生效时**先确认站点是否为观察模式。

---

## 十、版本分水岭（升级前必查）

| 版本 | 变化 |
|:---|:---|
| **v7.2.0** | 新增 `RULE_BLOCK` / `RULE_ALLOW` / `RULE_LOG_ONLY` 三常量；**与旧版规则不兼容，不支持直接升级** |
| **v7.1.0** | 插件支持 `priority`，阶段函数返回两个 bool 控制流程 |
| **v4.1.0** | 插件引入 pre/post 小阶段（此前用 `req_filter` / `resp_header_filter` / `resp_body_filter` / `log`） |
| **v7.2.5** | 社区版最大站点数 10 → **16** |

### 特性 → 最低版本（写规则前先确认目标实例版本）

| 特性 | 最低版本 |
|:---|:---|
| `waf.RULE_BLOCK` / `RULE_ALLOW` / `RULE_LOG_ONLY` 三常量、单规则观察模式 | **v7.2.0**（且该版本与旧版规则不兼容、不支持直接升级） |
| 插件 `priority`、阶段函数返回两个 bool | v7.1.0 |
| 插件 pre/post 小阶段（旧名 `req_filter` 等作废） | v4.1.0 |
| 社区版站点数上限 16 | v7.2.5 |
| 数据库结构自动创建 | v6.8.0 |
| `UUWAF_DB_DSN`（自定义数据库）、证书通配所有域名 | v6.7.0 |

> 读目标实例版本：`GET /setting/license` 的 `version`（或 `waf.py -i <实例> ping`）。

完整变更见 `offline-docs/CHANGELOG.zh-CN.md` 与在线 `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/CHANGELOG.md`。

---

## 十一、社区版能力边界

| 项目 | 社区版 |
|:---|:---|
| 价格 | 完全免费 |
| 站点数量 | 最大 **16** |
| 漏洞防护 / CC 防护 / 后门检测 / 业务安全 / CDN 加速 / 高级规则 / 插件扩展 / 合规审计 / 日志报表 / 地区限制 / 负载均衡 / 拦截页面 / 免费证书 | ✅ 支持 |
| 机器学习 / 集群管理 / 主机防御 / RASP / 数据脱敏 / 增强规则 / 多租户 / 定制开发 / 技术支持 | ❌ 需专业版或商业版 |

官方效果评估（社区版）：检出率 74.77%，误报率 0.09%，准确率 99.42%（样本 33669）。
完整对比表见 `offline-docs/product-introduction.md`。
