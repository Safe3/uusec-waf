# 功能配置指引

> 覆盖**用户问「某功能怎么配」**与**「帮我配置某功能」**两类场景。
> 每一项都给出：面板路径 → API（可脚本化）→ 关键字段 → 注意事项。
> 写操作前先取授权；改动后**验收看实际生效状态**，不只看 API 返回码。

---

## 一、通用流程

```
确认目标（哪台 WAF / 哪个站点）
  → 查现状（脚本只读：waf.py -i <实例> list ...）
  → 给出待改内容与影响面
  → 取授权
  → 执行
  → 验收（读回配置 + 实际请求验证）
```

**脚本**：`scripts/waf.py`（用法见 `SKILL.md`）。改前先备份：

```bash
python3 <skill>/scripts/waf.py -i <实例> api GET /setting/backupConfig > /tmp/waf-backup-$(date +%F).json
```

---

## 二、接入一个站点

**面板**：站点管理 → 添加站点

| 字段 | 说明 |
|:---|:---|
| 域名（`hosts`） | 支持多域名与通配 `*`（如 `example.com`、`*.example.com`） |
| 上游服务器（`servers`） | `{ip, port, weight}`；多个后端按 `mode` 负载均衡 |
| 负载均衡模式 | `roundRobin`=带权轮询 / `ipHash`=一致性哈希 / `SWRR`=平滑加权轮询 |
| **客户端 IP 来源**（`ip_source`/`ip_order`/`ip_header`） | 🔴 **必配**：决定 `waf.ip` 取值。多层代理下配错 → **所有基于 IP 的防护（CC/爆破/封禁）整体失效** |
| 自定义 Host（`custom_host`） | 回源时改写 `Host` 头 |
| 规则集（`ruleset_id`） | 挂哪套规则集 |

**API**：`GET /sites` 查、`POST /sites` 新建、`PUT /sites` 更新（带 `id`）、`DELETE /sites` 批量删 `{keys:[...]}`。

**验收**：`curl -I https://<域名>` → 响应头 `server` 应为 `uuWAF`。

> ⚠️ 域名**没配站点**时会被默认拦截，返回**规则 ID = -1** 的拦截页（防黑域名指向的法律风险）。看到 `-1` 就是"站点没加"。

---

## 三、配置 SSL 证书

**面板**：证书管理 → 添加证书 / 申请证书

| 方式 | 要点 |
|:---|:---|
| 上传 | 填 `crt` + `key`（PEM） |
| Let's Encrypt（HTTP-01） | 需 **80 端口公网可达**；**每月申请次数有限** |
| Let's Encrypt（DNS-01） | 可申**泛域名**；需 DNS 生效等待；`dns_provider` + `dns_credential` |
| 通配证书 | 支持 `*` 证书通配所有域名（v6.7.0+） |

**API**：`GET /certs`、`POST /certs`、`PUT /certs`（带 `id`）、`DELETE /certs` 批量删。

🔴 `GET /certs` 返回 `key`（**私钥明文**）与 `dns_credential`（DNS 凭据）—— 不落盘、不回显。

---

## 四、IP / URL 白名单（站点级）

**面板**：站点配置 → IP 地址白名单 / URL 路径白名单

| 项 | 格式 |
|:---|:---|
| `ip_whitelist` | 单个 IP 或 **CIDR 网段** |
| `url_whitelist` | 路由表达式：`/foo/*`、`/foo/*action`、`/foo/:name` |

**API**：`PUT /sites`（带 `id`）。

> ⚠️ 站点级白名单是**整站放行**语义：站点里加了 IP 或路径白名单，**该站点不再过任何规则**（不是"只跳过某条规则"）。若只想对个别请求开口子，应改**规则**做精确例外（见 `rule-authoring.md` §4.7），不要用站点白名单。

---

## 五、观察模式（只记录不拦截）

三个层次，按影响面从小到大：

| 层次 | 配置方式 | 粒度 |
|:---|:---|:---|
| **单条规则** | 规则内 `return waf.RULE_LOG_ONLY, "原因"`（v7.2.0+） | 最小 |
| **规则集** | 在规则集中停用某条规则（`PUT /ruleset`） | 该站点 |
| **整站** | 站点 `mode` 字段（`PUT /sites`） | 最大 |

**推荐灰度路径**：新规则先 `RULE_LOG_ONLY` → 观察日志比对 → 确认无误报后切 `RULE_BLOCK`。

> ⚠️ 站点级观察模式下即使规则返回 `RULE_ALLOW` 也仍记日志，因此**白名单看似不生效**时先确认站点是不是观察模式。

---

## 六、封禁名单管理与解封

**面板**：IP 封禁

| 操作 | 接口 |
|:---|:---|
| 查看名单 | `GET /setting/ipBlock/all` |
| 查询某 IP 封禁状态 | `PUT /setting/ipBlock/check`，body `{"ip":"<IP>"}` → `{locked: bool}`；**解封用 `unlock`** |
| 导出名单 | 同 URL 以 blob 下载 `ipblock.jsonl` |

**数据来源**：Lua 共享内存字典 `ipBlock`（**不在数据库，容器内无 Redis**）。

**自愈**：`ipBlock` 条目的 **TTL = 600 秒（10 分钟）**，规则拦截会重置 TTL；**停止触发拦截即自然清零**。
> 感觉"解不开"通常是**仍在持续制造被拦截的请求**在刷新 TTL。停止请求或按上表手动解锁。

---

## 七、CC / 频率防护

**两条路径**：

| 路径 | 位置 | 特点 |
|:---|:---|:---|
| **内置规则 66「防CC攻击规则」/ 68「机器人攻击防护」/ 70「高频错误防护」** | 规则管理 | 开箱即用，按 ID 升序执行 |
| **`cc_protection` 插件** | 插件管理 | 功能强、可精细化（站点级阈值、路径级限速、回源熔断、IP 全局限速） |

**插件版的配置维度**（`plugins[].content` 内为 Lua，可调项已前置）：

| 配置块 | 作用 |
|:---|:---|
| `enableCCProtection` | 总开关 |
| `enableOriginCircuitBreaker` / `originCircuitBreaker` | **回源熔断**：全局统计准备回源请求总数，超限临时阻断所有请求（保护源站总容量） |
| `enableGlobalRateLimit` / `globalRateLimit` | **IP 全局限速**：跨站点按 IP 统计（粗过滤） |
| `enableSiteRateLimit` / `siteDefault` / `siteConfigs` | **站点级限速**：按 Host 独立统计；`siteConfigs` 按域名覆写 |
| `enablePathRateLimit` / `pathRules` | **精准路径限速**：按 Host + Path 前缀单独限速 |

**调参要点**：

- `threshold` / `timeWindow` / `banDuration` 三件套必须成组理解。
- `countStatic`：是否把静态资源算进计数（**静态资源多的站点应设 false**，否则正常浏览即触发）。
- **搜索引擎放行**：官方规则用 `waf.searchEngineValid({"180.76.76.76"}, waf.ip, waf.userAgent)` 排除真实搜索引擎，避免影响收录 —— 自写 CC 规则也应照做。

**API**：`GET /plugins` 取 `content` → 改参数 → `PUT /plugins`（带 `id`，需 `waf_nodes` 非空）。

---

## 八、人机验证（验证码）

| 方式 | 接口 |
|:---|:---|
| 滑动旋转验证码（内置） | `waf.checkRobot(waf, expireTime?, max?)`，默认 600 秒 / 18000 次 |
| Cloudflare Turnstile | `waf.checkTurnstile(waf, siteKey, secret, expireTime?, max?)` |
| 内置规则 71 | 「Turnstile人机验证」 |

🔴 **用人机验证时必须放行验证页所需资源**：`/static/` 与 `/api/v1/captcha/`
—— 否则验证页的 CSS/JS 被拦，页面无法渲染（表现为"卡在验证页"）。

**验证码图片池**：把 PNG 放到容器 `/uuwaf/captcha/images/`，**重启服务**生效。

---

## 九、CDN 缓存加速

**面板**：缓存加速

| 操作 | 接口 |
|:---|:---|
| 更新 CDN 配置 | `PUT /cdn` |
| 清理缓存 | `DELETE /cdn/purge` |

- 缓存状态看响应头 **`X-Waf-Cache: HIT / MISS`**。
- 南墙自研缓存清理**支持正则匹配 URL 路径**（优于 nginx 商业版仅 `*` 通配）。
- 缓存落盘路径 `/tmp/disk_cache_uuwaf`，`max_size=8g`，`inactive=60m`。

---

## 十、自定义拦截页

**面板**：站点配置 → 拦截页（`deny_page`）。

**API**：`PUT /sites`（带 `id`）。

---

## 十一、动态口令（TOTP）

**面板**：系统设置 → 用户管理 → 开启动态口令（`users[].enable_otp`）。

🔴 南墙的 TOTP 用 **HMAC-SHA256**，**与一般动态口令客户端不兼容**。
官方推荐：iOS 用 **Google Authenticator**，Android 用 **FreeOTP**（`https://waf.uusec.com/freeotp.apk`）。

---

## 十二、集群与节点

**面板**：系统设置（`config.json` 的 `id` 与 `waf_nodes`）。

- `waf_nodes`：数据面节点地址列表（默认 `["127.0.0.1:4447"]`）。**写规则/插件要求它非空**，否则报 `No waf nodes`。
- `id`：节点 ID，即上游头 **`X-Waf-Id`** 的值，**集群模式下用于区分请求来自哪个节点**。
- 上游获取真实客户端 IP 用 **`X-Waf-Ip`**。

> 集群管理属**专业版/商业版**能力；社区版仅有单节点。

---

## 十三、地区访问控制

| 方式 | 说明 |
|:---|:---|
| 内置规则 69「区域访问限制」 | 开箱即用 |
| 规则内 `waf.ip2loc(waf.ip, "zh-CN")` | 返回 `country, province, city, iso`，可自定义策略 |

---

## 十四、配置变更的验收与回滚

| 项 | 做法 |
|:---|:---|
| **改前备份** | `GET /setting/backupConfig`（配置）、`GET /setting/backupDB`（数据库） |
| **验收** | 读回配置 + **实际发一条应命中/应放过的请求**，不只看 API 200 |
| **回滚** | 规则：`PUT /rules` 还原文；规则集：`PUT /ruleset` 还原数组；站点：`PUT /sites` |
| **需要重启的配置** | 监听端口、控制台证书、验证码图片池；**其余改完立即生效** |
| **观察期** | 生产变更后留在 `RULE_LOG_ONLY` 或观察模式一段时间再收紧 |

> 🔴 **禁止**用对 WAF 数据面发构造请求的方式做验收（触发规则 13 封禁）。见 `pitfalls.md` §一。

---

## 十五、数据面 nginx 参数（`/setting/waf`，API 可改）

面板把数据面的 nginx 参数开放成 **8 段文本**，每段直接对应容器内一个配置文件 —— **改这里等于改 nginx，但不必进容器**（实测字段与落盘文件一一对应）：

| 字段 | 落盘文件 | 内容 / 常改项 |
|:---|:---|:---|
| `resolver` | `/uuwaf/conf/resolver.conf` | DNS 解析器（默认 `180.76.76.76 valid=30s ipv6=off`）—— 上游写域名时改这里 |
| `listen` | `/uuwaf/conf/listen.conf` | 监听端口 / http2 / IPv6（默认 `80 default_server` + `443 ssl http2`） |
| `ssl` | `/uuwaf/conf/ssl.conf` | 协议与套件；**HSTS 已写好但注释掉，去掉 `#` 即启用**；老客户端兼容组合也在注释里（注意 HTTP/2 要求 TLSv1.2+） |
| `gzip` | `/uuwaf/conf/gzip.conf` | 压缩开关 / 级别 / 类型白名单 |
| `cache` | `/uuwaf/conf/cache.conf` | `proxy_cache` 行为、`X-Waf-Cache` 响应头、强制缓存开关（默认被注释） |
| `proxy` | `/uuwaf/conf/proxy.conf` | 超时（默认 `proxy_read_timeout 600s`）、缓冲区、转发头、隐藏头 |
| `error_page` | `/uuwaf/conf/error_page.conf` | 404 / 50x 自定义错误页 |
| `log` | `/uuwaf/conf/log.conf` | 数据面 `access_log`（默认注释关闭；日志主要落库） |

**改法**：`GET /setting/waf` 取当前全文 → 改 → `PUT /setting/waf` 回写。
**动手前**：先 `waf.py -i <实例> backup config`。这是**全局数据面配置，改错影响所有站点**。
**只能在这里改**：不要 `docker exec` 直接改容器里的 conf —— 面板回写时会覆盖。

常见场景：

| 想做的事 | 改哪段 |
|:---|:---|
| 上游慢 / 大文件下载断流 | `proxy`：加大 `proxy_read_timeout`（默认 600s）与 `proxy_buffers` |
| 加 HSTS | `ssl`：去掉 `add_header Strict-Transport-Security …` 前的 `#` |
| 需要 nginx 访问日志 | `log`：去掉 `#access_log logs/access.log proxy;` 的 `#` |
| 支持老客户端（TLS1.0/1.1） | `ssl`：换成注释中的旧协议/套件组合（会失去 HTTP/2） |
| 换 DNS / 上游用域名 | `resolver`：换成自己的解析器地址 |
| 页面被缓存住了 | `cache`：调 `proxy_cache_bypass` / `proxy_cache_valid`，或启用强制缓存段 |

> ⚠️ **风险等级最高的一类改动**：`listen` / `ssl` 写错会**直接断掉所有站点的 HTTPS**。
> 改这两段前先记录原文、确认控制台（面板）与数据面**不是同一层**（面板 4443 不受影响，仍能进去改回来）。
> 面板 `PUT /setting/waf` 保存后引擎会重写上述 conf 并**自动重载 nginx**，无需手动重启/进容器。
