# 控制台 REST API（管理面）

> **权威源**：面板前端实现（`/uuwaf/waf-service` 内嵌 JS）+ 官方 FAQ「如何调用南墙控制台的 REST API」。
> 每条路径都标注**风险等级**（按破坏性与敏感性分级），动手前先看这一列。

风险图例：

| 标记 | 含义 |
|:---|:---|
| 🔴 高危 | 破坏或不可逆、中断服务、或返回明文凭据（私钥 / 口令 / token）——**先备份、先确认目标实例** |
| 🟠 谨慎 | 有副作用的写操作（增删改站点 / 规则 / 规则集 / 证书 / 插件 / 用户 / CDN / IP 名单），可重建但会改变线上防护状态 |
| — | 只读查询，不改变服务状态 |

---

## 一、认证

每个请求带 HTTP 头：

```
Api-Token: <token>
```

- Token 在面板「系统设置 → API 接口访问 Token」复制（**复制需登录面板**；之后调用只用该 token）。
- `Api-Token` 对所有读写路径均有效（`GET /setting/license`、`GET /ruleset`、`POST /logs` 等），**不需要 JWT**。
- 认证失败返回 `{"message":"missing or malformed jwt"}`（HTTP 400/401）。token 抄错一位即触发此错误 —— 排障时优先怀疑 token 逐字正确性。

### 基址

```
https://<面板地址>:<默认 4443>/api/v1
```

- 默认端口 **4443**，由 `/uuwaf/web/conf/config.json` 的 `addr` 字段决定（默认 `:4443`）。
- 面板通常用**自签证书**，客户端需跳过证书校验。
- **4443 是控制面入口**：不经 WAF 数据面、不消耗攻击计数，是诊断期唯一安全的通道。

---

## 二、通用规律（重要）

| 规律 | 说明 |
|:---|:---|
| **POST = 新建，PUT = 更新** | 前端逻辑 `id === 0 ? "POST" : "PUT"`。更新时 body 必须带 `id`。 |
| **日志与审计查询用 POST** | `GET /logs` 返回 `{"message":"Not Found"}`；必须 `POST /logs` 带 body。 |
| **DELETE 的三种形态** | ① body 批量 `{keys:[1,2]}`（`/sites`、`/certs`、`/plugins`、`/ml`、`/cdn`）；② 路径单删 `/rules/{id}`、`/ruleset/{id}`、`/users/{id}`（**无 body**）；③ 无参数批量清理 `/cdn/purge`、`/logs/purge`、`/audits/purge`、`/ml/purge` |
| **规则/插件写操作需 `waf_nodes` 非空** | 空数组报 `No waf nodes`。节点地址配好即可，节点无需真实在线。 |
| **默认规则集不可删** | `DELETE /ruleset/{id}` 对 `Default` 集会被拒绝。 |
| **改配置立即生效** | 规则、站点、证书等经面板保存后即时生效，**无需重启**。例外：监听端口、管理后台证书、验证码图片池需重启（见 `operations.md`）。 |

---

## 三、接口清单

### 3.1 站点 `/sites`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| GET | `/sites` | 站点列表 + 规则集下拉选项 | — |
| POST | `/sites` | 新建站点 | 🟠 谨慎 |
| PUT | `/sites` | 更新站点（带 `id`） | 🟠 谨慎 |
| DELETE | `/sites` | 批量删 `{"keys":[id,...]}` | 🟠 谨慎 |

**`GET /sites` 返回结构**：

```json
{
  "options": [ {"label":"<规则集名>","value":2}, {"label":"Default","value":1} ],
  "sites":   [ { ...站点对象... } ]
}
```

- `options` 是**规则集下拉项**（`label` 名称 / `value` = `ruleset_id`），前端新建站点时用它渲染选择框。
- **`hosts` 是字符串数组**（如 `["example.com","*.example.com"]`），不是字符串。

**站点对象字段语义**（`GET /sites` 返回；**类型与默认值以 v7.2.5 为准**）：

| 字段 | 类型 | 默认 | 语义 |
|:---|:---|:---|:---|
| `id` `usr` `updated_at` | int/str/str | — | 标识与审计 |
| `hosts` | array[str] | `[]` | 该站点接管的域名列表，支持 `*` 通配（如 `["example.com","*.example.com"]`） |
| `description` | str | `""` | 站点备注 |
| **`mode`** | **bool** | `true` | 🔴 **防护开关**：`true`=**拦截模式**（阻断），`false`=**观察模式**（只记录不拦）。**是 `bool` 不是 int** |
| `ruleset_id` | int | `1` | 挂载的规则集 ID（对应 `options[].value`） |
| `scheme` | str | `"http"` | **上游连接协议**（回源协议，`http`/`https`） |
| **`servers`** | array[obj] | `[{"ip":"127.0.0.1","port":8080,"weight":1}]` | **上游主机列表**。每项 `{ip, port, weight}`；`weight`=权重（配合下面的 `type` 做负载均衡） |
| **`type`** | str | `"roundrobin"` | **负载均衡算法**（见下方枚举，注意**与 i18n 键名不同**） |
| `ip_whitelist` `url_whitelist` | array[str] | `[]` | 站点级白名单。IP 支持单个 IP 或 CIDR；URL 支持 `/foo/*`、`/foo/:name` 等路由表达式 |
| `custom_host` | str | `""` | **代理时改写请求的 Host 头**（空 = 不改） |
| `deny_page` | str | 默认拦截页 HTML | 自定义拦截页内容 |
| `is_websocket` `is_ml` `is_cache` `force_ssl` | **bool** | `false`/`false`/`false`/`false` | WebSocket 支持 / 机器学习 / 缓存加速 / 强制 HTTPS。**均为 bool** |
| `ip_source` | int | `0` | **客户端真实 IP 来源**：`0`=网络连接(socket) / `1`=X-Forwarded-For / `2`=HTTP 请求头（见下） |
| `ip_order` | int | `2` | **倒数第 n 个 IP**（仅 `ip_source` 为 1 或 2 时生效） |
| `ip_header` | str | `"X-Real-IP"` | **头名称**（仅 `ip_source=2` 时生效） |

**`type`（负载均衡）枚举** —— 🔴 i18n 键名与线上取值**不一致**，以线上值为准：

| 线上取值 | 面板显示 | 含义 |
|:---|:---|:---|
| `roundrobin` | 带权轮询 | 加权轮询（默认） |
| `chash` | 一致性哈希 | 按客户端 IP 一致性哈希（**不是** `iphash`） |
| `swrr` | 平滑加权轮询 | Smooth Weighted Round-Robin（**不是** `SWRR`） |

**`ip_source` 枚举**：

| 值 | 含义 | 配套字段 |
|:---|:---|:---|
| `0` | 网络连接（socket 对端 IP） | — |
| `1` | `X-Forwarded-For` | `ip_order`（倒数第 n 个） |
| `2` | 自定义 HTTP 请求头 | `ip_order` + `ip_header`（头名称，默认 `X-Real-IP`） |

> `ip_source` / `ip_order` / `ip_header` 决定 `waf.ip` 的值。上游若有多层代理，这里配错会导致**所有基于 IP 的防护（CC、爆破、封禁）整体失效**，是排障高频盲点。

### 3.2 规则 `/rules`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| GET | `/rules` | 规则列表（**含 `content` 全文**） | — |
| POST | `/rules` | 新建规则（需 `waf_nodes`） | 🟠 谨慎 |
| PUT | `/rules` | 更新规则（带 `id`）（需 `waf_nodes`） | 🟠 谨慎 |
| DELETE | `/rules/{id}` | 单条删除 | 🟠 谨慎 |

> ⚠️ **没有 `GET /rules/{id}`**：`/rules/13` 返回 `{"message":"Not Found"}`。
> 取单条规则正文只能：`GET /rules` 后本地筛选，或用 `/rules` 的列表结果按 `id` 取。
> （`/rules/{id}` 仅在前端删除逻辑中出现，method 为 `delete`。）

**规则对象字段**：`id` `uid` `level` `name` `phase` `type` `description` `content` `updated_at` `usr`

| 字段 | 取值 | 说明 |
|:---|:---|:---|
| `id` | int | 规则 ID（`9`=官方预留 / `10~499`=内置 / `500~`=自定义，见下） |
| `level` | 0 ~ 4 | 危险等级：0=提示 1=低危 2=中危 3=高危 4=严重 |
| `phase` | 0 ~ 2 | 过滤阶段：`0`=请求阶段，`1`=返回 HTTP 头阶段，`2`=返回页面阶段 |
| **`type`** | **0 / 1** | **规则编辑类型**：**`0` = DSL 可视化规则，`1` = Lua 规则**（面板 `typeOption:{dsl:"DSL规则", lua:"LUA规则"}`） |
| `content` | str | 规则正文，**格式由 `type` 决定**（见下）。可能是 **CRLF 或 LF**（51 条中 CRLF 4 / LF 47） |
| **`name`** | str | 🔴 **仅在 `type=1`（Lua）时是真实规则名**；`type=0`（DSL）时 `name` 是**空串**，规则内容全在 `content`（JSON）里 |
| `uid` | int | 面板写入的规则均为 `1`（**不是"内置/自定义"判据**——判据见 ID 区段） |
| `usr` | str | 创建者用户名 |

**`content` 的两种格式（由 `type` 决定）**：

| `type` | 格式 | 示例 |
|:---|:---|:---|
| **1（Lua）** | Lua 源码全文 | `local ib = waf.ipBlock\nlocal c = ib:get(waf.ip)\n...` |
| **0（DSL）** | JSON：`[动作, [条件…]]` | `[1,["&",["ip","=","203.0.113.9"],["uri","*","/.env"]]]` |

DSL 结构细节见 `rule-authoring.md` §二「可视化规则（DSL）」。

**DSL 规则的完整语法**（取自面板前端 v7.2.5 的实现，官方文档未收录）：

`content` = JSON 数组 `[动作, [条件…]]`；动作是**数字**，条件是 `[字段, 操作符, 值]`：

| 动作 | 值 | 逻辑 | 值 |
|:---|:---|:---|:---|
| 拦截 `block` | `1` | 逻辑与 AND | `"&"` |
| 允许 `allow` | `2` | 逻辑或 OR | `"\|"` |
| 只记录 `logOnly` | `3` | 逻辑非与 NOT AND | `"~&"` |
| — | — | 逻辑非或 NOT OR | `"~\|"` |

**条件字段（key）** —— 请求侧：`ip` `method` `reqUri` `uri` `queryString` `reqHeaders` `userAgent` `referer` `reqContentType` `XFF` `origin` `reqContentLength` `form`；响应侧：`status` `respHeaders` `respContentType` `respContentLength` `respBody`。

**条件操作符（op）** —— 🔴 **是符号不是英文名**，且**取反=前缀 `~`**：

| 操作 | 符号 | 操作 | 符号 |
|:---|:---|:---|:---|
| 字符串包含 | `*` | 字符串不包含 | `~*` |
| 正则匹配 | `.` | 正则不匹配 | `~.` |
| IP 匹配 | `-` | IP 不匹配 | `~-` |
| 以字符串开始 | `^` | 以字符串结尾 | `$` |
| 等于 | `=` | 不等于 | `~=` |
| 大于 | `>` | 小于 | `<` |

> 🔴 **`type` 不是"内置 / 自定义"的判据**。判定内置与否要看 **ID 区段**与**改动是否被回滚**（见下）。

**「内置 vs 自定义」的实际判据**：

| 判据 | 说明 |
|:---|:---|
| **ID 区段** | **`9`** = **官方预留位**（种子数据：名称「自定义」、描述「留下备用，用于自定义最高优先级规则」、内容仅 `return false`）；**`10 ~ 499`** = 官方内置规则；**`500 ~`** = 自定义规则（自增分配） |
| **名称** | 内置规则有固定名称（如 `SQL报错检测`、`防CC攻击规则`） |
| **改动是否被回滚** | 内置规则由面板**自动维护**，**改动会被回滚** —— 这是不可直接修改内置规则的真正原因 |

> 官方 CHANGELOG（v6.7.0）：「防止默认规则覆盖自定义规则，自定义规则id范围调整起始值到500」。
> **ID 9 是官方留出的"自定义最高优先级"槽位**：任何需要"先于全部内置规则执行"的自建功能都可以放这里（用途不限）。因此**不要用"ID 大小"反推是不是自建**，要看内容与来源。
> **直接改内置条目会被面板自动维护回滚**（官方 CHANGELOG：「防止默认规则覆盖自定义规则」）；要停某条内置检测，改的是**规则集**的启用清单，不是规则本身。

### 3.3 规则集 `/ruleset`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| GET | `/ruleset` | 规则集列表（`id` `uid` `name` `content` `updated_at` `usr`） | — |
| POST | `/ruleset` | 新建规则集 | 🟠 谨慎 |
| PUT | `/ruleset` | 更新规则集 | 🟠 谨慎 |
| DELETE | `/ruleset/{id}` | 单删（默认集禁删） | 🟠 谨慎 |
| GET | `/ruleset/rules` | 规则集内规则**摘要** | — |
| GET | `/ruleset/rules?id=N` | 同上（`id` 参数**不影响结果**） | — |

**`content` 是 JSON 数组字符串**，元素是规则 ID：

```json
"[66,68,70,50,49,47,45,43,29,19,17,16,15,13,10,9]"
```

> ⚠️ **数组顺序无实际意义**：规则执行按**规则 ID 升序**，不按数组顺序。数组只表达「启用哪些」——
> 面板保存时就是 `filter(仍存在的规则)` + `JSON.stringify`，不排序；官方种子的 `Default` 集也是 ID 降序存放（依据见 `internals.md` §二）。

> ⚠️ **`GET /ruleset/rules` 的坑**：它返回的是**摘要**——`content` 恒为空字符串 `""`，`level` / `type` / `uid` 归零，`updated_at` 为空。
> - 取规则正文**必须**走 `GET /rules`（列表已含全文；无 `GET /rules/{id}`）。
> - **`id` 查询参数不生效**：`?id=1`、`?id=2`、不传参均返回**全部 51 条**（规则库全量摘要）。**它不按规则集过滤**，不要用它来"读某个规则集的成员"。
> - 要拿规则集成员，用 `GET /ruleset` 取 `content` 数组。

**规则集 ≠ 规则**（最高频的认知错误）：

| 概念 | 载体 | 作用 |
|:---|:---|:---|
| **规则** | `GET /rules`（`waf_rules`） | 规则的**定义**，存在**规则库**里 |
| **规则集** | `GET /ruleset`（`waf_ruleset.content`） | 规则的**启用清单**，决定哪些规则对外生效 |

- 一条规则可以放在多个规则集里，也可以**建好却完全不挂进任何规则集**（此时它是死的，不生效）。
- 一个站点挂**一个**规则集（`ruleset_id`）；一个规则集可被**多个**站点引用。
- **误报处置的多数场景只需改规则集**（启用/停用某条），不用碰规则正文 —— 这是最低风险的处置手段。

### 3.4 日志 `/logs`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| POST | `/logs` | 日志查询 | — |
| GET | `/logs/total` | 总量统计 `[总, 今, 7天, 拦]` | — |
| GET | `/logs/top` | Top 数据 `{attackers, sites, types}` | — |
| GET | `/logs/live` | 实时状态 `{usage:{cpu,mem,disk}, req, atk, geo}` | — |
| POST | `/logs/report` | 日志报表，body `{}` | — |
| POST | `/logs/download` | 导出日志 CSV：body **直接传查询对象** `{"level":5,"host":"","url":"","ip":"","time_range":[]}`（**无** `page`/`page_size`）；返回 `text/csv`，文件名取自 `Content-Disposition`（如 `attack_log.csv`） | — |
| GET | `/logs/newVersion` | 是否有新版本 `{newer: bool}` | — |
| DELETE | `/logs/purge` | 清空日志 | 🔴 高危 |

> **返回结构速记**：`/logs/total` → `[总请求, 今日, 7天, 拦截数]`；`/logs/top` → `{attackers, sites, types}`（今日 TOP 10）；`/logs/live` → `{usage:{cpu,mem,disk}, req, atk, geo}`（`atk`/`geo` 是 **JSON 字符串**，需二次解析）。

**查询 body**：

```json
{
  "page": 1,
  "page_size": 20,
  "query": {
    "level": 5,
    "host": "",
    "url": "",
    "ip": "",
    "time_range": []
  }
}
```

`query` 精确字段（**官方 API 文档未收录，来自前端实现**）：

| 字段 | 类型 | 说明 |
|:---|:---|:---|
| `level` | int | **`5` = 全部**；0=提示 1=低危 2=中危 3=高危 4=严重 |
| `host` | string | 按域名过滤，空串=不过滤 |
| `url` | string | 按 URL 过滤（子串） |
| `ip` | string | 按来源 IP 过滤 |
| `time_range` | array | 时间范围 |

> 🔴 **`time_range` 两个易踩点**：
> 1. **必须带时分秒**。`["YYYY-MM-DD HH:MM:SS","YYYY-MM-DD HH:MM:SS"]` 生效；纯日期 `["YYYY-MM-DD","YYYY-MM-DD"]` 返回 **0 条但不报错**——**静默返回空结果**，极易误判为「无攻击」。
> 2. `[]` 表示不限制时间。

**查询用 `POST` 而非 `GET`**：

```
GET /logs → {"message":"Not Found"}
```

**返回结构**：`{"data":[...], "total":N}`。`data` 中每条记录字段：

| 字段 | 说明 |
|:---|:---|
| `id` `uid` `updated_at` | 标识与时间 |
| `name` | **命中规则的名称**（如「高频攻击防护」） |
| `level` | 该条日志等级 |
| `ip` `country` `province` `city` `latitude` `longitude` | 来源与地理位置 |
| `host` `url` | 被访问域名与路径 |
| `exploit` | 判定依据摘要 |
| `request` | 🔴 **原始 HTTP 请求报文全文** |

> 🔴 **`request` 字段含凭据**：常见 `Authorization`、`Cookie`、`X-Api-Token` 等敏感头**原样保存**。
> **硬规则：默认不打印、不落盘、不回显 `request` 字段**；确需排查时只提取必要片段，且不在对话/文件中复现凭据。

> **`updated_at` 是时间列**：数据库表中没有 `time` 列，误用即查不出数据。

### 3.5 审计 `/audits`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| POST | `/audits` | 审计查询 `{page, page_size}` | — |
| POST | `/audits/download` | 导出 CSV（当前筛选结果前 10000 条） | — |
| DELETE | `/audits/purge` | 清空审计（**无参数**） | 🔴 高危 |

**审计记录字段**：`id` `type`(str，操作类型如「规则集」) `usr` `ip`(客户端 IP) `info`(操作详情) `updated_at`。

### 3.6 证书 `/certs`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| GET | `/certs` | 证书列表（**含 `crt` 与 `key` 全文 PEM**） | 🔴 高危 |
| POST / PUT | `/certs` | 新建 / 更新 | 🟠 谨慎 |
| DELETE | `/certs` | 批量删（body `{keys:[id…]}`） | 🟠 谨慎 |

**证书对象字段**：`id` `name` `type`(int) `email` `sni`(**JSON 数组字符串**，如 `"[\"example.com\",\"*.example.com\"]"`) `crt`(PEM) `key`(PEM) `dns_provider` `dns_credential` `dns_challenge`(bool) `expired_at` `uid` `usr` `updated_at`。

**`type` 枚举**：`0` = **申请免费证书**（Let's Encrypt，需 80 端口公网可达 + 域名已解析）；`1` = **上传已有证书**（提供 `crt` + `key`）。🔴 `sni` 是**字符串形式的 JSON 数组**，解析时需二次 `json.loads`。
⚠️ 改证书类型时前端会重置表单（`change` 时清空字段），PUT 前务必带全已有字段。
🔴 **`key` 是私钥明文**、**`dns_credential` 是 DNS 服务商凭据**：读取后不得落盘、不得回显、不得写入人设文件或日志。

### 3.7 插件 `/plugins`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| GET | `/plugins` | 插件列表 | — |
| POST / PUT | `/plugins` | 新建 / 更新（需 `waf_nodes`） | 🟠 谨慎 |
| DELETE | `/plugins` | 批量删（body `{keys:[id…]}`） | 🟠 谨慎 |

**插件对象字段**：`id` `name`(如 `basic_auth`，**是标识而非显示名**) `description` `enabled`(**bool**，开关) `content`(Lua 全文) `uid` `usr` `updated_at`。

> 系统自带插件的 `content` **内含示例凭据**（如 basic-auth 的 `admin/admin123`）。这些是**官方模板示例值，切勿照抄上线**。

### 3.8 用户 `/users`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| GET | `/users` | 用户列表 | 🔴 高危 |
| POST | `/users` | 新建用户 | 🟠 谨慎 |
| POST | `/users/login` | 登录（换 JWT）；body 含 `usr`/`pwd`/`otp` | 🟠 谨慎 |
| DELETE | `/users/{id}` | 单删（**无 body**） | 🟠 谨慎 |

**用户对象字段**：`id` `usr`(用户名) `pwd` `role`(int) `fail`(登录失败次数) `otp_url`(**内嵌 TOTP secret 明文**) `enable_otp`(bool) `pwd_expiration`(int) `pwd_expired_at` `updated_at`。

**`role` 枚举**：`0` = 管理员 / `1` = 操作员 / `2` = 审计员。
**`pwd_expiration` 枚举**：`0` = 不限 / `45` / `90` / `180`（天）。
🔴 `GET /users` 返回 `otp_url`，其中**内嵌 TOTP secret 明文**；`pwd` 为口令字段，**按敏感处理**。读取后不得落盘/回显。

### 3.9 系统设置 `/setting`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| GET | `/setting` | 全局配置 | 🔴 高危 |
| PUT | `/setting` | 更新全局配置 | 🟠 谨慎 |
| GET | `/setting/waf` | 数据面 nginx 参数（8 段，见 `configuration.md` §十五） | — |
| PUT | `/setting/waf` | 更新数据面 nginx 参数 | 🔴 高危 |
| GET | `/setting/license` | 授权信息 `{expiration, version}` | — |
| GET | `/setting/latestVersion` | 最新版本 `{version}` | — |
| GET | `/setting/lang` | **读取**当前语言：`{"language":"zh"}`（**改语言不在这里**，走 `PUT /setting` 的 `language` 字段） | — |
| GET | `/setting/update` | **触发升级 —— GET 即动作，不是只读**；成功后前端 3 秒自动刷新。**社区版 Docker 部署下不可用**（升级走更新镜像） | 🔴 高危 |
| GET | `/setting/backupConfig` | 下载配置备份：`content-disposition: attachment; filename="backup.json"`、`application/json`（**内含 `dsn`/`jwt_key`/`api_token` 明文**） | 🔴 高危 |
| GET | `/setting/backupDB` | 下载数据库备份：`filename="backup.sql"`、`application/octet-stream` | 🔴 高危 |
| POST | `/setting/recoverConfig` | **恢复配置：multipart，字段名 `file`（单文件）** ⚠️ 破坏性 | 🔴 高危 |
| POST | `/setting/recoverDB` | **恢复数据库：multipart，字段名 `file`（单文件）** ⚠️ 破坏性 | 🔴 高危 |

> ⚠️ **这一组里有"伪装成只读的动作端点"**：`GET /setting/update` **GET 就触发升级**（不是查询），别当普通 GET 随手调；
> `GET /setting/lang` 才是纯读取（改语言在 `PUT /setting` 的 `language` 字段，面板设置页即如此）——它**只改界面语言，不改已入库的内置规则/插件内容**（内容语言随镜像与部署时的语言种子固化，见 `deployment.md` §一「中文版 / 英文版」）。
> `backupConfig` 的产物含**明文凭据**，`recoverConfig`/`recoverDB` 是**破坏性**恢复 —— 产物落地与调用都按敏感/危险对待。
| GET | `/setting/ipBlock/all` | 全部 IP 封禁记录（前端点「导出」即下载 `ipblock.jsonl`；body 为 **JSONL**，一行一个对象，空名单是 `{}`，**不是 JSON 数组**） | — |
| PUT | `/setting/ipBlock/{action}` | 对某 IP 执行动作，body `{"ip":"<IP>"}` | 🟠 谨慎 |

**`GET /setting` 字段**（v7.2.5）：`id`(节点标识,str) `addr`(管理地址) `dsn` `jwt_key` `jwt_expiration`(秒) `waf_nodes`(array，元素形如 `"127.0.0.1:4447"`) `ml_server` `ml_token` `api_token` `log_db`(bool) `log_level`(`error`/`info`/`debug`) `language` `version`。🔴 其中 `dsn`/`jwt_key`/`api_token`/`ml_token` **均为敏感值**（处置见 §3.9 下方与 `pitfalls.md` §二）。

> 🔴 **`ipBlock` 的 `{action}` 共四个**（v7.2.5）：
> - `check`：查询单个 IP，返回 `{"locked":bool}`；`unlock`：解除单个，返回 `"OK"`；`unlockAll`：解除全部，返回 `"OK"`（空 body 亦可）。UI 按钮走 `PUT`，body `{"ip":"<IP>"}`。
> - `checkAll`：**UI 不使用**——面板「查询所有 / 导出」实际是下载 `GET /setting/ipBlock/all`（JSONL，见上表），不是调这个端点。带合法 ip 调它同样返回 `"OK"`，语义未明，**不要依赖**。
> - 三个 PUT 动作都会**先校验 ip**：空或非法 → `{"err":"IP格式错误"}`（返回 200，不是 4xx，别只按状态码判断成功）。
> ⚠️ **没有"切换锁定"这类动作**：`check` 只查询状态，**解封一律用 `unlock`**（批量 `unlockAll`）。

> **数据来源**：IP 封禁名单存于 Lua **共享内存字典 `ipBlock`**（规则拦截时由引擎自动写入），**不在数据库**，容器内**没有 Redis**。
> **TTL = 600 秒（10 分钟）**：每次规则拦截会重置 TTL；停止触发拦截即自然清零。想立即解封用 `unlock`（批量 `unlockAll`）。

> 🔴 **`GET /setting` 返回敏感字段**：数据库连接串（含口令）、`jwt_key`、`api_token`、`ml_token`。
> **拿到该接口返回就等于拥有面板权限**（可直连业务库、可伪造 token）。硬规则：
> - 不落盘、不回显、不写入人设文件；
> - 需要展示时逐字段打码；
> - 授权客户端才可调用。

### 3.10 CDN 缓存 `/cdn`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| PUT | `/cdn` | 更新/新建（前端 `id===0?"POST":"PUT"`，注意前端写的是 `/cdn`） | 🟠 谨慎 |
| DELETE | `/cdn` | 批量删（body `{keys:[id…]}`） | 🟠 谨慎 |
| DELETE | `/cdn/purge` | 清理缓存（**无参数**） | 🟠 谨慎 |

**CDN 对象字段**（前端默认值）：`id` `host`(域名) `uri`(**基于正则的 URL 路径**，默认 `"/.*"`，如 `"/.+\\.(?:css\|js\|jpe?g\|png\|webp\|avif\|woff2?\|eot\|...)$"`) `cache_time`(str，默认 `"1h"`；单位 `s`/`m`/`h`/`d`/`M`/`y`) `enabled`(**bool**，开关)。

- 缓存状态由响应头 `X-Waf-Cache: HIT / MISS` 反映。
- 南墙自研缓存清理**支持正则匹配 URL 路径**（优于 nginx 商业版仅支持 `*` 通配）。

### 3.11 机器学习 `/ml`

| 方法 | 路径 | 说明 | 风险 |
|:---|:---|:---|:---|
| GET | `/ml` | ML 模型列表 | — |
| PUT / DELETE | `/ml` `/ml/purge` | 管理 | 🟠 谨慎 |

> 社区版调用返回「请升级到商业版」。ML 用于异常流量识别，可自动学习正常流量参数特征生成白名单规则库。

---

## 三之二、字段与枚举的权威来源（可复现）

本文的**类型、枚举取值、默认值**不是推测 —— 来自面板前端实现，随时可重新提取核对：

```bash
TOKEN=$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.config/waf-hosts.json')))['<实例名>']['token'])")
B=https://<面板地址>:4443

# 1) 首页 → 主 bundle 引用全部 chunk（业务 chunk 名都在这里）
curl -sk -H "Api-Token: $TOKEN" $B/ | grep -oE 'assets/[a-zA-Z0-9_.-]+\.js'
# 2) 主 bundle（含 i18n 中文字典 = 字段官方名 + 枚举 label）
curl -sk -o /tmp/index.js $B/assets/index-<hash>.js
# 3) 端点→方法 映射（url + method 同现）
grep -oE 'url:\s*"[^"]+"\s*,\s*method:\s*"[A-Za-z]+"' /tmp/*.js
# 4) 单删形态（路径拼 id）
grep -oE '"/[a-z]+/"\s*\+' /tmp/*.js
```

**判据与陷阱**：

- **前端 JS 是枚举取值的一手来源**（`{label:…,value:"…"}`），官方文档与 i18n 键名都可能与**线上取值不一致**（如负载均衡 `type` 线上是 `roundrobin`/`chash`/`swrr`，而非 i18n 的 `roundRobin`/`ipHash`/`SWRR`）。
- **字段类型以真实响应为准**（`GET /sites` 等），不要从 i18n 的 label 文字推断类型（`mode` 看着像 int，实际是 bool）。
- 面板版本：**v7.2.5**（`GET /setting/license` 返回的 `version`）。换版本后按上面的方法重新提取核对。

---

## 四、错误形状

| 现象 | 返回 | 排查 |
|:---|:---|:---|
| Token 错误 | `{"message":"missing or malformed jwt"}` | 核对 token 逐字 |
| 用了 GET 查日志 | `{"message":"Not Found"}` | 改 `POST /logs` |
| 写规则/插件时节点为空 | `No waf nodes` | `config.json` 的 `waf_nodes` 需非空 |
| body 类型不符 | `{"err":"code=400, message=Unmarshal type error: expected=web.LogQuery, got=string, ..."}` | `query` 必须是**对象**，不能传字符串 |
| 查询返回 0 条且无报错 | `{"data":[],"total":0}` | 先核对时间格式是否带时分秒 |
| 默认规则集删除 | 被拒 | 默认集不可删 |
| JSON 解析报 `Expecting value` | 返回体带 **UTF-8 BOM** | `/setting/ipBlock/all` 等端点返回 `\ufeff[...]`，须用 `utf-8-sig` 解码（脚本已处理） |

---

## 五、脚本调用

随 skill 提供 `scripts/waf.py`（纯标准库，无第三方依赖、支持多实例）。用法见 `SKILL.md`。

```bash
python3 scripts/waf.py hosts                        # 列出配置的所有实例
python3 scripts/waf.py -i <name> ping               # 连通 + 认证自检
python3 scripts/waf.py -i <name> list sites|rules|ruleset|certs|plugins|users
python3 scripts/waf.py -i <name> api GET  /ruleset
python3 scripts/waf.py -i <name> api POST /logs '{"page":1,"page_size":20,"query":{"level":5,"time_range":[]}}'
python3 scripts/waf.py -i <name> logs -q '{"level":5,"host":"example.com"}'   # 日志查询封装

# 写路径（无需手写 Python）
python3 scripts/waf.py -i <name> get rule <ID> [--field content] [--out 文件]   # 取正文到文件（CRLF 保真）
python3 scripts/waf.py -i <name> push rule <ID|new> --file 文件 [--dry-run]      # 回写正文（PUT/POST）
python3 scripts/waf.py -i <name> push ruleset <ID> [--set|--add|--remove …]      # 改启用清单
python3 scripts/waf.py -i <name> ipblock [--check <IP> | --unlock <IP> | --check-all | --unlock-all]                         # 封禁名单 / 解封
python3 scripts/waf.py -i <name> backup [config|db] [--out 文件]                 # 改前备份（落 600 权限文件）
python3 scripts/waf.py -i <name> delete rule|ruleset|cert|plugin <ID> [--dry-run] # 删除（生产写操作，先取授权）
python3 scripts/waf.py -i <A> diff rule|ruleset <ID> --with <B>                   # 跨实例字节级比对（md5/CRLF/差异）
```

> 脚本自动跳过自签证书校验；token 由脚本从配置文件 / 环境变量读取，**不经模型上下文**。
> `get` / `push` 的正文经**文件**传递（不内联 shell），落盘用 `newline=""` 保证 CRLF ↔ LF 不漂移。
> 响应解码统一走 `utf-8-sig`（部分端点带 BOM，如 `GET /setting/ipBlock/all`，否则 `json.loads` 失败）。
