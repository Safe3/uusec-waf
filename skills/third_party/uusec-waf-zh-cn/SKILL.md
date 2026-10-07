---
name: uusec-waf-zh-cn
description: "南墙 UUSEC WAF 全能力：部署、运维、站点/证书/白名单/CC 防护/CDN 配置、规则与插件编写调试、控制台 REST API 管理。触发词：WAF、南墙、uuwaf、规则、插件、误报、CC。"
compatibility: "需要 bash 与 python3（3.8+，仅标准库）。pcrecheck.py 需系统 libpcre2；wafcheck.sh 需 WAF 主机上的容器。管理 API 需网络可达面板端口 4443。"
---

# UUSEC WAF（南墙）

工业级开源 WAF（WAAP），基于 **nginx + OpenResty 生态 + LuaJIT**，采用**云 WAF 反向代理**模式：流量先到南墙，由它检测后再回源。

## 能力范围

| 面 | 内容 | 入口 |
|:---|:---|:---|
| **安装部署** | 一键安装、加固、站点接入、证书 | `references/operations.md` |
| **部署与数据库** | 部署形态、官方 compose、DSN 与数据库的使用、启动顺序、升级 | `references/deployment.md` |
| **中文版 / 英文版** | 两条语言通道、两个镜像、`UUWAF_LANGUAGE`、语言随部署固化、更新通道绑定 | `references/deployment.md` §一 |
| **日常运维** | 容器与目录、改配置、升级备份、常见问题 | `references/operations.md` |
| **API 管理** | 站点 / 规则 / 规则集 / 证书 / 插件 / 用户 / 日志 / 封禁 / CDN | `references/management-api.md` + `scripts/waf.py` |
| **规则开发** | 规则模板、规范、模式库、上线与回滚 | `references/rule-authoring.md` |
| **交付前校验** | 三件套：Lua 语法 / 正则 / **语义（API·常量·阶段·钩子·模块·DSL）** | `scripts/rulecheck.py`、`pcrecheck.py`、`wafcheck.sh` |
| **插件开发** | 5 大阶段 × pre/post 共 10 个钩子函数、原生 ngx、共享内存、模式库 | `references/plugin-authoring.md` |
| **运行时机制** | 执行顺序、`RULE_ALLOW` 短路范围、共享内存字典、观察模式 | `references/internals.md` |
| **数据面参数** | nginx 参数（监听 / SSL / 压缩 / 缓存 / 代理超时 / 错误页 / 日志），`/setting/waf` 8 段 | `references/configuration.md` §十五 |
| **避坑** | 数据面禁令、文档与实现不符、静默失效清单 | `references/pitfalls.md` |
| **规则/插件获取** | 官方内置、社区第三方、贡献方式 | 本文「规则与插件资源」一节 |
| **配置场景** | 用户问「某功能怎么配」/「帮我配上」 | `references/configuration.md` |

> 🔴 **动手前请先读 `references/pitfalls.md`**，尤其是「禁止对 WAF 数据面打构造请求」与「凭据清单」两节。

---

## 🚀 上手路径（首次接入照着走）

> 第 0 步：**先定语言版** —— 中文版与英文版是两条通道、两个镜像，语言随部署固化（面板切语言只改界面）。见 `references/deployment.md` §一「中文版 / 英文版」。

1. **配凭据**：面板「系统设置 → API 接口访问 Token」复制 → 写 `~/.config/waf-hosts.json`（权限 600，格式见下文）。
2. **连通自检**：`python3 scripts/waf.py -i <实例名> ping`；或一次跑全套：`bash scripts/selfcheck.sh -i <实例名>`（6 步只读自检，用法见下文）。
3. **先看现状再动手**：`list sites` / `list ruleset` / `list rules` / `logs --size 20` —— 先弄清"哪个站点挂了哪套规则集"。
4. **改前备份**：`python3 scripts/waf.py -i <实例名> backup config`（自动落 600 权限文件）。
5. **写规则 / 插件**：读 `references/rule-authoring.md`（或 `plugin-authoring.md`）→ 按模板产出 → **三件套校验**（语法 / 正则 / 语义）→ `RULE_LOG_ONLY` 观察 → 再切拦截。
6. **出事止损**：`references/operations.md` §七「规则事故应急预案」（5 分钟）。

---

## 交付规则/插件前的硬要求

写规则或插件时**必须**：

1. **格式规范**：开头说明块（规则名称/过滤阶段/危险等级/规则描述）→ `-- <--- 配置参数 --->`（可调项前置集中、逐项中文注释）→ `-- <--- 工具函数 --->` → `-- <--- 主逻辑 --->`。
2. **正则校验**：WAF 用 **PCRE（PCRE1 8.45 + JIT）**，选项用 `"jos"`。**每条正则交付前必须验证**。两个通道，按环境择一：

   **① 独立版 `pcrecheck.py`（默认选它 —— agent 与 WAF 不同机是常态）**
   纯标准库 + `ctypes` 绑定系统 PCRE2，**任何有 Python 3 的机器**都能跑，无需容器：
   ```bash
   python3 <skill目录>/scripts/pcrecheck.py regex '<正则>' '<测试串1>' '<测试串2>'
   python3 <skill目录>/scripts/pcrecheck.py cases '<正则>' <测试串文件>   # 按行批量比对
   python3 <skill目录>/scripts/pcrecheck.py extract <规则文件>   # 提取+逐个校验（别名 file）
   python3 <skill目录>/scripts/pcrecheck.py lua   <规则文件>     # Lua 冒烟（启发式，非权威）
   python3 <skill目录>/scripts/pcrecheck.py engine               # 自检：PCRE 版本/JIT/能力
   python3 <skill目录>/scripts/pcrecheck.py -h
   ```

   **② 容器版 `wafcheck.sh`（仅当本机就是 WAF 主机时可用，保真度最高）**
   用容器内 PCRE1 —— 与运行时**链接同一个库**（`libpcre.so.1`）：
   ```bash
   bash <skill目录>/scripts/wafcheck.sh engine|regex|cases|file|lua
   ```

   🔴 **绝不用 Python `re` / `grep -E` 校验** —— 它们不是 PCRE，会给出"全部通过"的假结论。`pcrecheck.py` 宁可报"环境不可用"，也不换用 `re`。
3. **Lua 语法校验**：
   - **权威**（须 WAF 主机）：容器内 luajit → 输出 `SYNTAX_OK`：
     `bash <skill目录>/scripts/wafcheck.sh lua <规则文件>`
   - **无容器时的启发式冒烟**：`python3 <skill目录>/scripts/pcrecheck.py lua <文件>`
     → `BALANCED(heuristic)` 或 `SYNTAX_SUSPECT`。**刻意不使用 `SYNTAX_OK` 措辞**：它只做括号/块关键字/字符串闭合检查，**不等于编译通过**。
4. **样例齐全**：应拦 ≥2 条、应放 ≥2 条（**含 `..`、大小写、后缀追加等绕过尝试**）。
5. **把校验命令、所用通道与结果一并交付**。用独立版时如实注明"**PCRE2 校验**"——WAF 运行时是 PCRE1 8.45（**真差异只有两处**：变长后顾 `(?<=a{1,3})` 与裸递归 `(?R)`，见 `references/rule-authoring.md` §二之二；`\K`、`(?|…)` 等其实**两边都支持**）。本机即 WAF 主机时，`pcrecheck.py engine` 会用容器内 PCRE1 逐项实测复核。
6. **语义自检（必做）**：`python3 <skill目录>/scripts/rulecheck.py all <文件> [--phase 0|1|2]`。语法与正则都通过**不代表规则能用** —— 它专查语法层抓不到的四类致命错：**不存在的 API、拼错的常量、阶段不匹配的变量、规则里误用 `ngx`/插件变量**；插件还查**钩子名**与 **`require` 的模块是否存在**。`all` 会**连带跑 Lua 语法与正则**（能拿到容器 luajit／本机 luajit 就用权威通道，否则如实提示跳过）—— 一条命令≈三件套。有 ❌ 一律修掉再交付。
7. **版本升级后自检符号表**：`rulecheck.py symbols` 对比官方 API 文档，列出"文档有、脚本表没有"的名字 —— 不空就说明 `rulecheck.py` 的符号表该更新了。

> 细节见 `references/rule-authoring.md` §一/§二/§二之二/§五，插件见 `references/plugin-authoring.md`。

---

## 文档策略：在线优先，离线兜底

本技能同时提供**在线文档入口**与**离线文档副本**。

**优先级：在线优先**（内容最新），网络不可达时用离线副本。

| 内容 | 在线地址（GitHub raw，优先） | 离线副本 |
|:---|:---|:---|
| 规则 / 插件 API（**权威**） | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/api/README.md` | `references/offline-docs/api.zh-CN.md` |
| 安装指南 | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/install.md` | `references/offline-docs/install.md` |
| 开始使用 | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/begin.md` | `references/offline-docs/getting-started.md` |
| 常见问题 | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/problems.md` | `references/offline-docs/faq.md` |
| 贡献指南 | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/contribute.md` | `references/offline-docs/contribute.md` |
| 产品介绍 / 功能对比 | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/guide/README.md` | `references/offline-docs/product-introduction.md` |
| 变更日志 | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/CHANGELOG.md` | `references/offline-docs/CHANGELOG.zh-CN.md` |
| 仓库说明 | `https://raw.githubusercontent.com/Safe3/uusec-waf/main/README_CN.md` | `references/offline-docs/README.zh-CN.md` |
| 在线文档站 | `https://waf.uusec.com/#/zh-cn/guide/install` | — |
| 源码仓库 | `https://github.com/Safe3/uusec-waf` | — |

> 离线副本为**官方原文快照**，可能落后于上游。涉及时效性内容（版本分水岭、新特性、已修复的问题）时**优先取在线**。

---

## 规则与插件资源

### 官方内置

| 类型 | 仓库路径 | 说明 |
|:---|:---|:---|
| 内置规则 | `rules/*.lua` | 官方维护，如 `rules/anti-cc.lua` |
| 内置插件 | `plugins/*.lua` | 官方维护，如 `plugins/kafka-logger.lua`、`plugins/ip-intelligence.lua`、`plugins/basic-auth.lua` |
| 运行时内置规则 / 插件 | 面板「规则管理」「插件管理」 | 安装后即在库中（规则 ID `10~499`，官方自动维护） |

### 社区第三方

| 类型 | 仓库路径 | 说明 |
|:---|:---|:---|
| 第三方规则 | `rules/third_party/*.lua` | 社区贡献，随仓库分发但**非官方维护** |
| 第三方插件 | `plugins/third_party/*.lua` | 社区贡献，**非官方维护** |

🔴 **引用时必须区分内置与第三方**：

- 判据 = **路径前缀**（有无 `third_party/`）+ **文件头署名**。
  - 内置示例：`plugins/ip-intelligence.lua` 署 `Created by Safe3.`
  - 社区示例：文件头写「作者: xxx」。
- 措辞规范：第三方文件应称「**社区贡献的参考实现**」，**不要**写成「官方实现」。

### 获取方法

```bash
# 列出仓库全部规则与插件路径
curl -sL "https://api.github.com/repos/Safe3/uusec-waf/git/trees/main?recursive=1" \
  | grep -o '"path": *"\(rules\|plugins\)/[^"]*"'

# 直接取单个文件
curl -sL "https://raw.githubusercontent.com/Safe3/uusec-waf/main/rules/anti-cc.lua"
curl -sL "https://raw.githubusercontent.com/Safe3/uusec-waf/main/plugins/third_party/auth-plugin.lua"
```

**导入面板的方式**：通过控制台 REST API `POST /rules`、`POST /plugins`（body 含 `content` = Lua 全文），或面板界面粘贴。写操作需配置 `waf_nodes` 非空（见 `management-api.md`）。

### 贡献

向 `rules/` 或 `plugins/` 提 PR。详见 `offline-docs/contribute.md`。

---

## 客户端脚本

`scripts/waf.py` —— 纯标准库、无第三方依赖、支持多实例。

### 实例配置（优先）

`~/.config/waf-hosts.json`（权限 600）：

```json
{
  "<实例名>": {"url": "https://<服务器IP>:4443", "token": "<Api-Token>"}
}
```

- **`url` 填面板可达地址**：本机 `127.0.0.1`、内网 `<服务器IP>` 或域名都行；**端口是面板端口 `4443`**
  （HTTPS，面板默认自签证书 → 脚本自动跳过证书校验；80/443 是数据面、4447 是内置管理面，都不是面板）。
- **新用户两步**：`waf.py init` 生成骨架（自动 600 权限，含 `_说明` 键，脚本会跳过它）→ 用户把 `url`/`token` 填进去 → `-i <实例名> ping` 自检。
- **代填（用户把值给了你时）**：`waf.py hosts --add <名称> --url <URL> --token -`（`-` = 从 **stdin** 读，避免 token 进命令行历史）；脚本**只报长度、从不回显 token**；若 token 是通过对话给的，提醒对方按需轮换。
- 加新 WAF：往该文件加一段即可，**脚本零改动**。
- token 在面板「系统设置 → API 接口访问 Token」复制（**复制需登录面板**；之后调 API 只用该 token，无需再登录）。

环境变量兜底：`WAF_API_URL` + `WAF_API_TOKEN`。

### 用法

```bash
python3 <skill目录>/scripts/waf.py hosts                              # 列出全部实例
python3 <skill目录>/scripts/waf.py -i <实例名> ping                    # 连通 + 认证自检
python3 <skill目录>/scripts/waf.py -i <实例名> list sites|rules|ruleset|certs|plugins|users
python3 <skill目录>/scripts/waf.py -i <实例名> api GET  /ruleset
python3 <skill目录>/scripts/waf.py -i <实例名> api GET  /rules
python3 <skill目录>/scripts/waf.py -i <实例名> api POST /logs \
  '{"page":1,"page_size":20,"query":{"level":5,"time_range":[]}}'
python3 <skill目录>/scripts/waf.py -i <实例名> logs -q '{"level":5,"host":"example.com"}'
python3 <skill目录>/scripts/waf.py -i <实例名> logs -q '{"level":5}' --table   # 表格输出，默认隐藏 request 字段
```

### 写路径（改规则 / 规则集 / 封禁）

**不用手写 Python 绕** —— `get` / `push` 解决「没有 `GET /rules/{id}`」与「正文无法内联进 shell」两个硬伤，**字节保真**（`content` 在服务端是 CRLF，往返不归一化）：

```bash
# 取正文到文件（默认字段 content；--field __meta__ 只看元信息）
python3 <skill目录>/scripts/waf.py -i <实例名> get rule <规则ID> --out /tmp/rule.lua

# 改完回写（PUT，带 id；先 GET 当前对象只替换正文，不猜字段形状）
python3 <skill目录>/scripts/waf.py -i <实例名> push rule <规则ID> --file /tmp/rule.lua --dry-run
python3 <skill目录>/scripts/waf.py -i <实例名> push rule <规则ID> --file /tmp/rule.lua

# 新建规则（POST / id=0）
python3 <skill目录>/scripts/waf.py -i <实例名> push rule new --file /tmp/new.lua --name "我的规则" --level 3

# 改规则集启用清单（--add/--remove 单个，或 --set 整体；数组顺序无意义）
python3 <skill目录>/scripts/waf.py -i <实例名> push ruleset 1 --add <规则ID>
python3 <skill目录>/scripts/waf.py -i <实例名> push ruleset 1 --remove 19 --dry-run

# IP 封禁名单：查看 / 切换某 IP 锁定状态
python3 <skill目录>/scripts/waf.py -i <实例名> ipblock
python3 <skill目录>/scripts/waf.py -i <实例名> ipblock --check <IP> | --unlock <IP>
```

> `push` 全部支持 `--dry-run`（只打印将提交的 body，不发请求）。写操作需 `waf_nodes` 非空，且属**生产变更**——先取授权，改前建议 `GET /setting/backupConfig` 备份，并给出回滚方式。

> `-i <实例名>` 必须放参数首位。
> 脚本自动跳过自签证书校验；token 由脚本从配置文件 / 环境变量读取，**不进对话上下文**。
> `logs` 子命令**默认不打印 `request` 字段**（含凭据），需显式加 `--raw` 才输出。

### 一条命令做完备自检

```bash
# 优先：用 ~/.config/waf-hosts.json 的实例（token 不进命令行）
bash <skill目录>/scripts/selfcheck.sh -i <实例名>

# 兜底：无配置文件时传 url/token，或用环境变量
bash <skill目录>/scripts/selfcheck.sh --url https://<面板地址>:<端口> --token <Api-Token>
WAF_API_URL=https://<面板地址>:<端口> WAF_API_TOKEN=<Api-Token> bash <skill目录>/scripts/selfcheck.sh
```

> 依次跑 6 步**全只读**自检：实例列表 → 连通认证 → 站点 → 规则集 → 日志 → IP 封禁名单。
> 退出码 `0` 全通过 / `1` 有步骤失败（失败行标 `[FAIL]`）/ `2` 参数或环境错误。
> 脚本自动定位同目录的 `waf.py`，**在任意 cwd 都能执行**。
> 🔴 **优先用配置文件**（`~/.config/waf-hosts.json`）—— `--token` 兜底会把 Api-Token 写进进程参数与命令历史，与「token 不进上下文」相冲；确需兜底时先在 shell 里 `export WAF_API_TOKEN=…`，让脚本从环境变量读。

---

## 决策速查

| 我要做什么 | 看哪里 |
|:---|:---|
| 装一套南墙 / 加固 | `references/operations.md` §一 |
| **搞清部署形态 / 数据库怎么用** | `references/deployment.md` §一/§二/§三 |
| **中文版还是英文版 / 语言怎么切换** | `references/deployment.md` §一「中文版 / 英文版」—— 语言随部署固化，面板设置只改界面 |
| **数据库连不上 / 版本兼容 / 启动顺序** | `references/deployment.md` §三/§四/§五 |
| **用户问「某功能怎么配」/ 让我配某功能** | `references/configuration.md` |
| 接一个站点 / 传证书 | `references/configuration.md` §二/§三、`references/management-api.md` §3.1/§3.6 |
| 配 CC / 频率防护 | `references/configuration.md` §七 |
| 配白名单 / 观察模式 / 解封 | `references/configuration.md` §四/§五/§六 |
| 用 API 查日志、查规则 | `references/management-api.md` §3.2/§3.4 |
| **改规则正文 / 改规则集启用清单 / 解封 IP** | `scripts/waf.py` 的 `get` / `push` / `ipblock`（见本文「客户端脚本 → 写路径」） |
| 写一条规则 | `references/rule-authoring.md`（**先读 `references/internals.md`**） |
| **正则怎么写 / 怎么验证** | `references/rule-authoring.md` §二之二（双通道：`pcrecheck.py` 独立版 / `wafcheck.sh` 容器版） |
| 写一条可视化（DSL）规则 | `references/rule-authoring.md` §三之二 |
| 写一个插件 | `references/plugin-authoring.md` |
| 判断用规则还是插件 | `references/rule-authoring.md` §六 |
| 内置规则有 bug 改不了 | `references/internals.md` §五 —— 内置规则由面板维护，**直接改会被回滚**，不要改它 |
| **交付前校验规则/插件（语义层）** | `python3 scripts/rulecheck.py all <文件> [--phase N]`（或 WAF 主机 `bash scripts/wafcheck.sh semantics <文件>`） |
| **插件能用哪些模块** | `references/plugin-authoring.md` §十（实测清单 + 核对命令） |
| 规则和插件到底有什么区别 | `references/internals.md` §三之二（作用域 / ngx / 跨阶段） |
| 规则写了不生效 | `references/rule-authoring.md` §七 排障顺序 |
| 误报怎么处理 | `references/internals.md` §三（`RULE_ALLOW` 代价）+ `references/rule-authoring.md` §4.7 |
| 查为什么被拦 | `references/pitfalls.md` §七（读内置检测模块特征表）+ `references/management-api.md` §3.4 |
| 升级前要注意什么 | `references/internals.md` §十 版本分水岭 + `references/operations.md` §四 |
| 封禁怎么解 | `references/pitfalls.md` §一/§五（TTL 与解除）、`references/configuration.md` §六 |

---

## 安全与合规要求

### 凭据与敏感数据

| 来源 | 敏感内容 | 处置 |
|:---|:---|:---|
| `GET /setting` | `dsn`（含口令）、`jwt_key`、`api_token`、`ml_token` | **不落盘 / 不回显 / 不写入人设文件** |
| `GET /users` | `otp_url`（TOTP secret 明文）、`pwd` | 同上 |
| `GET /certs` | `key`（私钥 PEM）、`dns_credential`（DNS 凭据） | 同上 |
| `POST /logs` 的 `request` | `Authorization`、`Cookie` 等**原样保存** | **默认不打印**；确需时只取必要片段 |
| `config.json` | 上述全部 | 同上 |
| 面板默认凭据 | `admin` / `#Passw0rd` | **部署后必须删除该用户** |

**Api-Token 存放**：权限 **600** 的配置文件（`~/.config/waf-hosts.json`）或环境变量，由**脚本读取**，不经模型上下文。

### 操作纪律

1. **禁止对 WAF 数据面（80/443）打构造请求** —— 触发规则 13 封禁，并连带封掉同链路 IP。诊断只用：控制面 API（4443）、数据库只读、共享内存只读、内置检测模块源码。详见 `references/pitfalls.md` §一。
2. **生产写操作先取授权** —— 改规则、改规则集、解封 IP、改站点/证书配置均属生产变更。先列出待确认问题并说明影响面，取得确认后执行，**并给出回滚方式**。
3. **诊断期全只读**；确需端到端验证时先取得显式授权。
4. **🔴 数据库严禁非授权写操作** —— 数据库（WAF 的 `wafdb` 及任何实例库）**只读**。`INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`/`TRUNCATE` 等一律禁止，**包括测试、验证、清理日志等用途**；日志属原始记录，测试产生的日志**如实保留并标注来源**，不删除、不清空、不修改。确需写操作时先说明内容、影响面与回滚方式，取得授权后执行。诊断通道优先级：控制台 API > 只读查询 > 面板。
5. **改前备份** —— `GET /setting/backupConfig` / `GET /setting/backupDB`。
6. **验收看实际生效状态** —— 不只看 API 返回 200；用应拦/应放请求验证。
7. **不代改外部系统** —— 能给出可直接粘贴的内容，就交给使用者执行。

### 交付物规范

- **规则/插件必须经校验后交付**（Lua 语法 + 每条正则 + 应拦应放样例），并附校验命令与结果。见本文「交付规则/插件前的硬要求」。
- **引用第三方文件时必须区分归属**：`rules/*.lua`、`plugins/*.lua` = 官方；`rules/third_party/*`、`plugins/third_party/*` = **社区贡献**（措辞为「社区贡献的参考实现」，不写「官方实现」）。

---

## 文件清单

```
SKILL.md                        入口：能力范围、文档策略、决策速查、脚本用法
references/
├── management-api.md           控制台 REST API（含实测修正与字段语义）
├── internals.md                运行时机制：执行顺序、ID 分区、RULE_ALLOW、共享内存、观察模式
├── rule-authoring.md           规则编写：模板、规范、**正则（PCRE）与验证**、**DSL 规则**、模式库、排障
├── plugin-authoring.md         插件编写：阶段、原生 ngx、模式库、陷阱
├── operations.md               安装、目录、改配置、升级、常见问题
├── deployment.md               部署与数据库：部署形态、官方 compose、DSN 与数据库的使用、启动顺序、升级
├── configuration.md            **功能配置指引**：站点/证书/白名单/观察模式/CC/验证码/CDN/封禁
├── pitfalls.md                 🔴 禁令、凭据、文档与实现不符、静默失效清单
└── offline-docs/               官方文档与示例离线副本
    ├── api.zh-CN.md            官方规则/插件 API（权威全文）
    ├── install.md / getting-started.md / faq.md / contribute.md
    ├── product-introduction.md / CHANGELOG.zh-CN.md / README.zh-CN.md / README.md / LICENSE.txt
    └── examples/               官方内置与社区规则/插件源码副本
        ├── rule-*.lua          反 CC、爆破、动态限频、高频拦截、高频错误
        ├── plugin-*.lua        kafka-logger、ip-intelligence、basic-auth、auth-session
        ├── manager.sh          官方容器管理脚本
        ├── docker-compose.yml  官方 compose（uuwaf + wafdb，权威）
        └── low-memory-my.cnf   官方小内存 MySQL 调优（compose 中默认注释）
scripts/
├── pcrecheck.py                **独立版**校验器（ctypes + 系统 PCRE2，无需容器；推荐）
├── wafcheck.sh                 容器版校验器（PCRE1 同源 + 权威 luajit，仅 WAF 主机可用）
├── regex-extract.awk           wafcheck.sh 的正则提取器（供 file 子命令使用）
├── rulecheck.py                **语义校验器**（纯标准库，任何机器可跑）：API/常量/阶段/钩子/模块/DSL
├── waf.py                      REST API 客户端（多实例、纯标准库；get/push/ipblock/backup/delete/diff）
└── selfcheck.sh                连通 + 认证 + 常用只读接口的一条命令自检
```

---

## 来源与许可

| 项 | 说明 |
|:---|:---|
| 对象 | [Safe3/uusec-waf](https://github.com/Safe3/uusec-waf)（南墙 UUSEC WAF） |
| 上游许可 | **BSD 2-Clause**，Copyright (c) 2025 UUSEC Technology —— 全文见 `references/offline-docs/LICENSE.txt` |
| 离线副本 | `references/offline-docs/` 下的文档与示例均为**官方原文快照**，许可与版权随上游；分发时保留 `LICENSE.txt` |
| 时效性 | 副本可能落后上游；涉及时效内容（版本分水岭、新特性、已修复问题）**优先取在线原文**，见「文档策略」 |

> 本 skill 为第三方整理的**使用指南**，与 UUSEC Technology 无隶属关系；
> 其中「运行时机制 / 实现层研究 / 踩坑清单」由本 skill 实测归纳，非官方文档内容。
> 规则/文件内容的最终解释权归上游官方文档。
