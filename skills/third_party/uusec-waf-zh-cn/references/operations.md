# 安装、运维与排障

> 官方安装与常见问题原文见 `offline-docs/install.md`、`offline-docs/faq.md`。
> 部署形态、官方 compose 与数据库使用见 `deployment.md`。

---

## 一、安装

### 配置要求

| 项 | 要求 |
|:---|:---|
| 处理器 | 64 位 1 GHz 或更快 |
| 内存 | ≥ 2 GB |
| 磁盘 | ≥ 8 GB |
| 软件依赖 | Docker CE ≥ 20.10.14，Docker Compose ≥ 2.0.0 |

> 建议选**纯净的 Linux x86_64** 服务器。南墙是**云 WAF 反向代理模式**，默认需占用 **80 / 443** 端口。

### 一键安装

```bash
sudo bash -c "$(curl -fsSL https://waf.uusec.com/zh-cn/installer.sh)"
```

安装目录 `/opt/waf/`，管理脚本 `bash /opt/waf/manager.sh`（启动 / 停止 / 更新 / 卸载）。

> 若无法自动安装 Docker Engine，需手动安装。官方脚本副本见 `offline-docs/examples/manager.sh`。

### 快速入门五步

1. **登录后台**：`https://<服务器IP>:4443`，默认用户名 `admin`，密码 `#Passw0rd`。
2. **添加站点**：站点管理 → 添加站点 → 填站点域名与网站服务器 IP。
3. **添加 SSL 证书**：证书管理 → 添加证书 → 上传证书与私钥；无证书可申请 Let's Encrypt 免费证书并自动续期。
4. **改 DNS 指向**：把域名 A 记录改为南墙服务器 IP。
5. **测连通性**：访问站点域名，确认响应头的 `server` 字段为 `uuWAF`。

> 🔴 **部署后立即加固**（官方明确要求）：
> 1. 新建**不易猜解用户名**的新管理员用户；
> 2. **删除默认 `admin` 用户**；
> 3. **开启动态口令（TOTP）**。
>
> 注意：南墙的 TOTP 用 **HMAC-SHA256** 算法，**与一般动态口令客户端不兼容**。官方推荐 iOS 用 Google Authenticator，Android 用 FreeOTP（`https://waf.uusec.com/freeotp.apk`）。

---

## 二、容器与目录结构

> 官方 compose 全文见 `deployment.md` §二。

```
/opt/waf/
├── manager.sh                 容器管理脚本
└── docker-compose.yml

容器内 /uuwaf/（下列为主要项）
├── conf/                      数据面 nginx 配置
│   ├── uuwaf.conf             主配置（监听、共享字典、Lua 阶段钩子）
│   ├── listen.conf            监听端口（80 / 443；443 走 http2）
│   ├── proxy.conf             回源代理头与超时
│   ├── ssl.conf               TLS 协议与密码套件
│   ├── cache.conf             CDN 缓存
│   ├── gzip.conf              压缩
│   ├── log.conf               日志
│   ├── error_page.conf        错误页
│   ├── resolver.conf          DNS
│   ├── cert/                  证书
│   ├── geoip.mmdb             GeoIP 库（60MB）
│   └── （nginx 自带：mime.types、fastcgi/scgi/uwsgi params 等）
├── web/conf/
│   ├── config.json            控制面配置（含敏感字段）
│   ├── server.crt / server.key 控制台自身证书
│   └── rootCA.crt / rootCA.key 根 CA
├── waf/plugins/*.w            内置检测模块（明文 Lua）
├── captcha/images/            人机验证图片池
├── acme/  html/               ACME 验证与错误页
├── logs/                      日志（含 error.log）
├── sbin/uuwaf                 nginx 主程序
├── luajit/bin/luajit-*        内置 LuaJIT（可离线做语法校验）
├── waf-service                Go 服务（控制面 + 内嵌前端）
└── lego                       ACME 客户端（约 70MB）
```

---

## 三、改配置

| 要改什么 | 位置 | 生效方式 |
|:---|:---|:---|
| 管理后台端口 / SSL 证书 | `/uuwaf/web/conf/config.json` 的 `addr`；替换同目录 `server.crt` / `server.key` | **重启** |
| 反代监听端口 | `/uuwaf/conf/uuwaf.conf`（`listen.conf`），按 nginx `listen` 语法；Docker 版改 compose 端口映射 | **重启** |
| 人机验证图片池 | 放 PNG 到 `/uuwaf/captcha/images/` | **重启** |
| 站点 / 规则 / 规则集 / 证书 / 插件 | 面板（REST API） | **立即生效** |
| 缓存加速配置 | 面板 CDN 菜单 | 立即生效 |

> **绝大多数配置改完立即生效，无需重启**。只有监听端口、控制台证书、验证码图片需要重启。

### 访问控制面配置（只读参考）

`/uuwaf/web/conf/config.json` 字段（**实测字段名**）：

| 字段 | 含义 |
|:---|:---|
| `id` | 节点 ID（即上游头 `X-Waf-Id` 的值），**集群模式下用于区分来源** |
| `addr` | 控制台监听地址，默认 `:4443` |
| `dsn` | 🔴 数据库连接串（含口令） |
| `jwt_key` | 🔴 JWT 签名密钥 |
| `jwt_expiration` | JWT 有效期 |
| `waf_nodes` | 数据面节点地址列表（如 `["127.0.0.1:4447"]`），**写规则/插件要求非空** |
| `ml_server` | ML 服务地址 |
| `ml_token` | 🔴 ML 服务 token |
| `api_token` | 🔴 **控制台 REST API 的 Api-Token** |
| `log_db` | 是否落库记录日志 |
| `log_level` | 日志级别 |
| `language` | 界面语言 |
| `version` | 版本号 |

> 🔴 带标记的四项属**敏感数据**：不落盘、不回显、不写入人设文件、不经对话传输。

### 日志文件

| 文件 | 内容 |
|:---|:---|
| `/uuwaf/logs/error.log` | Lua 错误日志（`waf.errLog` / `log.errLog` 的目标） |
| `/uuwaf/logs/` 其余 | 访问与运行日志 |

> 数据面的 `access_log off`；**日志主要落数据库**（`log_db: true`），通过面板或 REST API 查询。配置文件 `error.log` 按日轮转（`error.log-YYYYMMDD.gz`，实测已配 logrotate）。

---

## 四、升级与备份

- 更新：`bash /opt/waf/manager.sh`（含更新选项）。⚠️ 该脚本会**覆盖 `docker-compose.yml`** —— 若有自定义改动需自行备份；且它**从脚本自身所属语言通道**拉 compose（中文通道拉 `waf.uusec.com/zh-cn/docker-compose2.yml`，英文通道拉根路径版）→ 换语言/换镜像要连 `manager.sh` 一起换（见 `deployment.md` §一「中文版 / 英文版」）。
- 备份：控制台「系统设置 → 备份配置 / 备份数据库」；API 为 `GET /setting/backupConfig`、`GET /setting/backupDB`。
- 🔴 **跨大版本升级前必须核对版本分水岭**（见 `internals.md` §十）：
  - **v7.2.0 与旧版本规则不兼容，不支持从旧版本直接升级**。
  - v4.1.0 改变了插件阶段函数命名（旧名 `req_filter` 等 → 新名 `req_pre_filter` 等）。
- 升级前建议：导出配置备份 + 记录当前规则集内容 + 记录自定义规则正文。

---

## 五、常见问题速查（官方 FAQ + 补充）

### 5.1 访问网站出现规则 ID 为 `-1` 的拦截页

域名**没有在站点管理中配置**时，南墙默认拦截该域名的访问 —— 用于防止"黑域名指向"引起法律风险。

**处理**：把该域名加进站点。

### 5.2 经过南墙后如何获取客户端真实 IP

WAF 转发时注入 `X-Waf-Ip`（真实客户端 IP），也可用 `X-Forwarded-For`。

**优先级**：`X-Waf-Ip` > `X-Forwarded-For`。

**WAF 侧**：站点配置里的 `ip_source` / `ip_order` / `ip_header` 决定 `waf.ip` 取值；**配错会导致所有基于 IP 的防护失效**。

### 5.3 集群模式下上游如何区分不同南墙来源

读 `X-Waf-Id`（值 = 各节点 `config.json` 的 `id`）。

### 5.4 如何判断页面是否被 CDN 缓存

看响应头 `X-Waf-Cache`：`HIT` = 已缓存，`MISS` = 未缓存。

### 5.5 证书申请失败

- HTTP-01 验证：需 **80 端口公网可达**。
- DNS-01 验证：无此限制且可申泛域名，但 **DNS 生效需等待时间**。
- Let's Encrypt **每月申请次数有限**，过于频繁会失败。

### 5.6 验证码图片太少

放 PNG 到 `/uuwaf/captcha/images/`，**重启服务**生效。

### 5.7 规则不生效

见 `rule-authoring.md` §七「排障顺序」。

### 5.8 插件导致站点报错

优先检查插件是否引用了**未传入的参数**（如 `waf.scheme` 之类需显式传入而非全局可见的值）。

---

## 六、诊断通道纪律

| 通道 | 用途 | 安全性 |
|:---|:---|:---|
| **控制台 REST API（4443）** | 查日志、规则、站点、封禁 | ✅ **诊断期首选**，不经数据面 |
| **面板 Web** | 人工查看与操作 | ✅ |
| **数据库（只读）** | 查原始记录 / 面板 API 未暴露的字段 | ✅ 只读查询安全；🔴 **严禁非授权写操作**（含测试/清理用途） |
| **共享内存字典（Lua 侧）** | 封禁名单（`ipBlock`）、访问计数（`ipCache`） | ✅ 只读安全 |
| **🔴 WAF 数据面（80/443）** | 用构造请求做复现测试 | ❌ **禁止** —— 见 `pitfalls.md` |

> 🔴 **数据库只读红线**：`INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`/`TRUNCATE` 等写操作一律禁止，写日志清理同样在列；测试产生的日志如实保留并标注来源。需写操作先取授权（内容 + 影响面 + 回滚）。
>
> **封禁状态在 Lua 共享内存字典 `ipBlock` 中，不在数据库**。容器内**没有 Redis**。
> 要核对或解除封禁名单，用面板「IP 封禁」：`GET /setting/ipBlock/all` 取名单，`PUT /setting/ipBlock/unlock` 解封（`check` 只查询状态）。

---

## 七、规则事故应急预案（写坏规则 → 5 分钟内止损）

**症状**：新规则上线后误拦正常业务 / 某路径全断 / 全站 403。

**按顺序做，前两步立即见效**：

| 步 | 动作 | 效果 | 命令 / 位置 |
|:--|:---|:---|:---|
| 1 | 站点 `mode` 改 `false`（观察模式） | **立即停止拦截**（日志照记，便于定位） | `PUT /sites`（带 `id`），或面板站点开关 |
| 2 | 从站点所用规则集移除该规则 ID | 该规则立即失效 | `waf.py -i <实例> push ruleset <集ID> --remove <规则ID>` |
| 3 | 回滚规则正文 | 恢复原状 | `waf.py -i <实例> push rule <ID> --file <改前备份>` |
| 4 | 定位根因 | 防止再犯 | 查 `waf_logs` 的 `rule_id` + `exploit`，确认是哪条判据 |

**关键事实**：规则 / 站点 / 规则集改动**立即生效，无需重启**；只有监听端口、控制台证书、验证码图片池要重启。
所以第 1、2 步是秒级止损 —— **先止血，别先纠结原因**。

> 🔴 反向推论：**新规则上线前先 `RULE_LOG_ONLY` 观察**，等于给这套预案省掉一次事故。
> 复盘后把"为什么误拦"写进规则注释（把判据写窄），不要只改条件不留痕。
> 也可等 `ipBlock` 的 TTL（10 分钟）自然过期 —— 只要期间不再触发拦截。
