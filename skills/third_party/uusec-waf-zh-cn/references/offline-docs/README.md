# 离线文档副本说明

本目录是 **UUSEC WAF（南墙）官方文档与示例源码的离线副本**，用于网络不可达时兜底。

## 来源与授权

- 上游仓库：https://github.com/Safe3/uusec-waf
- 许可协议：**BSD 2-Clause**，Copyright (c) 2025, UUSEC Technology（全文见 `LICENSE.txt`）
- 本目录内容为上游文件的**原样副本**，版权归 UUSEC Technology 及各位贡献者所有，按 BSD-2-Clause 条款再分发。
- 抓取时间：2026-10-02（`main` 分支）

## 文件对应关系

| 本地文件 | 上游路径 |
|:---|:---|
| `api.zh-CN.md` | `docs/zh-cn/api/README.md` |
| `install.md` | `docs/zh-cn/guide/install.md` |
| `getting-started.md` | `docs/zh-cn/guide/begin.md` |
| `faq.md` | `docs/zh-cn/guide/problems.md` |
| `contribute.md` | `docs/zh-cn/guide/contribute.md` |
| `product-introduction.md` | `docs/zh-cn/guide/README.md` |
| `CHANGELOG.zh-CN.md` | `docs/zh-cn/CHANGELOG.md` |
| `README.zh-CN.md` | `README_CN.md` |
| `LICENSE.txt` | `LICENSE` |
| `examples/rule-*.lua` | `rules/*.lua`、`rules/third_party/*.lua` |
| `examples/plugin-*.lua` | `plugins/*.lua`、`plugins/third_party/*.lua` |
| `examples/manager.sh` | `docker/manager.sh` |

## ⚠️ 时效性

离线副本是**某一时刻的快照**，可能落后于上游。涉及时效性内容时优先取在线：

```bash
# 官方 API 文档（权威）
curl -sL https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/api/README.md

# 变更日志（版本分水岭、新特性、已修问题）
curl -sL https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/CHANGELOG.md
```

## 归属区分（引用时必读）

| 路径前缀 | 归属 |
|:---|:---|
| `rules/*.lua`、`plugins/*.lua`、`docs/`、`docker/` | **官方维护** |
| `rules/third_party/*`、`plugins/third_party/*` | **社区贡献**（随仓库分发，非官方维护） |

引用的措辞规范：

- 官方文件 → 「官方内置规则 / 插件」
- 第三方文件 → 「**社区贡献的参考实现**」（**不要**写成「官方实现」）

`examples/` 下的社区贡献文件**保留了原始作者署名**（文件头 `作者:` 一行），这是来源溯源所必需，不属可移除内容。
