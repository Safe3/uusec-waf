# uusec-waf Skill

UUSEC 南墙 WAF（WAAP）的 **Agent Skill**：安装部署、日常运维、站点与证书、规则与插件编写调试、控制台 REST API 管理。

> **本仓库是通用开源版。** 采用 [Agent Skills](https://agentskills.io/specification) 标准格式，任何支持该规范的运行时（Claude Code、Codex、QwenPaw 等）均可直接使用；不依赖任何特定 agent 平台的专有工具。
>
> 本 skill 为第三方整理的**使用指南与工具集**，与 UUSEC Technology **无隶属关系**。

---

## 它能做什么

| 面 | 内容 |
|:---|:---|
| **安装部署** | 一键安装、加固、站点接入、证书、中文版 / 英文版通道选择 |
| **部署与数据库** | 部署形态、官方 compose、DSN 与数据库的使用、启动顺序、升级 |
| **日常运维** | 容器与目录、改配置、升级备份、常见问题 |
| **API 管理** | 站点 / 规则 / 规则集 / 证书 / 插件 / 用户 / 日志 / 封禁 / CDN |
| **规则开发** | 规则模板、规范、PCRE 模式库、上线与回滚 |
| **插件开发** | 5 大阶段 × pre/post 共 10 个钩子、原生 ngx、共享内存 |
| **交付前校验** | 三件套：Lua 语法 / 正则 / **语义**（API·常量·阶段·钩子·模块·DSL） |
| **运行时机制** | 执行顺序、`RULE_ALLOW` 短路、共享内存字典、观察模式 |
| **避坑** | 数据面禁令、文档与实现不符、静默失效清单 |

> 🔴 **动手前请先读 `references/pitfalls.md`**，尤其是「禁止对 WAF 数据面打构造请求」与「凭据清单」两节。

---

## 目录结构

```
SKILL.md                        入口：能力范围、文档策略、决策速查、脚本用法
references/
├── management-api.md           控制台 REST API（含实测修正与字段语义）
├── internals.md                运行时机制：执行顺序、ID 分区、RULE_ALLOW、共享内存、观察模式
├── rule-authoring.md           规则编写：模板、规范、PCRE 正则与验证、DSL 规则、模式库、排障
├── plugin-authoring.md         插件编写：阶段、原生 ngx、模式库、陷阱
├── operations.md               安装、目录、改配置、升级、常见问题
├── deployment.md               部署与数据库：部署形态、官方 compose、DSN、启动顺序、升级
├── configuration.md            功能配置指引：站点/证书/白名单/观察模式/CC/验证码/CDN/封禁
├── pitfalls.md                 🔴 禁令、凭据、文档与实现不符、静默失效清单
└── offline-docs/               官方文档与示例离线副本（BSD-2-Clause，见「许可」）
scripts/
├── waf.py                      REST API 客户端（多实例，纯标准库）
├── selfcheck.sh                一条命令做完备自检（6 步只读）
├── rulecheck.py                语义校验器（API/常量/阶段/钩子/模块/DSL）
├── pcrecheck.py                独立版正则校验器（ctypes + 系统 PCRE2，无需容器）
├── wafcheck.sh                 容器版校验器（PCRE1 同源 + 权威 luajit，仅 WAF 主机可用）
└── regex-extract.awk           wafcheck.sh 的正则提取器
```

---

## 安装

把本目录放进运行时的 skills 目录即可（不同运行时路径不同，常见为 `<workspace>/skills/uusec-waf/`）：

```bash
git clone <本仓库地址> uusec-waf
```

**依赖**：`bash`、`python3`（3.8+）。
所有 Python 脚本**仅用标准库**，无第三方依赖；`pcrecheck.py` 额外需要系统 `libpcre2`（多数发行版自带，缺失时脚本会给出提示）。

---

## 配置凭据

面板「系统设置 → API 接口访问 Token」复制，写入 `~/.config/waf-hosts.json`（权限 600）：

```json
{
  "<实例名>": {"url": "https://<服务器IP>:4443", "token": "<Api-Token>"}
}
```

- **`url` 填面板可达地址**：端口是面板端口 `4443`（HTTPS，自签证书由脚本自动跳过校验）。
  注意 `80/443` 是数据面、`4447` 是内置管理面，都不是面板。
- **生成骨架**：`python3 scripts/waf.py init`（自动 600 权限）→ 填入 `url`/`token`。
- **代填**：`python3 scripts/waf.py hosts --add <名称> --url <URL> --token -`（`-` = 从 stdin 读，避免 token 进命令行历史；脚本只报长度、从不回显）。
- **环境变量兜底**：`WAF_API_URL` + `WAF_API_TOKEN`。
- 多实例：往该文件加一段即可，脚本零改动。

> 🔴 Token 不要写进命令行、不要贴进对话或提交进仓库。

---

## 使用

### 连通自检

```bash
python3 scripts/waf.py -i <实例名> ping          # 单步：连通 + 认证
bash    scripts/selfcheck.sh -i <实例名>          # 全套：6 步只读自检
```

`selfcheck.sh` 依次跑「实例列表 → 连通认证 → 站点 → 规则集 → 日志 → IP 封禁名单」，全程只发 GET。
退出码：`0` 全通过 / `1` 有步骤失败 / `2` 参数或环境错误。脚本自动定位同目录的 `waf.py`，任意 cwd 均可执行。

### 常用查询

```bash
python3 scripts/waf.py -i <实例名> list sites|rules|ruleset|certs|plugins|users
python3 scripts/waf.py -i <实例名> api GET /ruleset
python3 scripts/waf.py -i <实例名> logs -q '{"level":5}' --table    # 默认隐藏 request 字段（含凭据）
```

### 写路径（改规则 / 规则集 / 封禁）

```bash
python3 scripts/waf.py -i <实例名> get  rule <规则ID> --out /tmp/rule.lua
python3 scripts/waf.py -i <实例名> push rule <规则ID> --file /tmp/rule.lua --dry-run
python3 scripts/waf.py -i <实例名> push ruleset 1 --add <规则ID>
python3 scripts/waf.py -i <实例名> ipblock --check <IP> | --unlock <IP>
```

> `push` 全部支持 `--dry-run`（只打印将提交的 body，不发请求）。写操作属**生产变更**——先取授权，改前备份，并准备好回滚方式。

### 交付前校验

```bash
python3 scripts/rulecheck.py all <文件> [--phase 0|1|2]   # 语义（必做）
python3 scripts/pcrecheck.py regex '<正则>' '<应命中>' '<应放过>'
bash    scripts/wafcheck.sh lua <文件>                    # 权威 Lua（仅 WAF 主机）
```

---

## 许可与致谢

| 项 | 说明 |
|:---|:---|
| **对象** | [Safe3/uusec-waf](https://github.com/Safe3/uusec-waf)（南墙 UUSEC WAF） |
| **上游许可** | **BSD 2-Clause**，Copyright (c) 2025 UUSEC Technology |
| **离线副本** | `references/offline-docs/` 下文档与示例为官方原文快照，版权随上游，分发时保留 `LICENSE.txt` |
| **时效性** | 副本可能落后上游；版本分水岭、新特性、已修复问题**优先取在线原文** |

`references/offline-docs/` 以外的内容（SKILL.md、其余 references、scripts）为本项目整理与实测归纳，
其中「运行时机制 / 实现层研究 / 踩坑清单」**非官方文档内容**，规则与文件内容的最终解释权归上游官方。

> ⚠️ 时效性提醒：WAF 版本迭代较快，涉及具体版本行为时请以在线官方文档为准。

---

## 贡献

Issue 与 PR 均欢迎。提交规则/插件相关改动前，请先跑通 `rulecheck.py` 与 `pcrecheck.py`。
