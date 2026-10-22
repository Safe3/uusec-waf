# Offline Docs Copy — Notes

This directory is an **offline copy of the UUSEC WAF official documentation and example source code**, used as a fallback when the network is unreachable.

## Source and License

- Upstream repository: https://github.com/Safe3/uusec-waf
- License: **BSD 2-Clause**, Copyright (c) 2025, UUSEC Technology (full text in `LICENSE.txt`)
- The contents of this directory are **verbatim copies** of upstream files; copyright belongs to UUSEC Technology and the respective contributors, redistributed under the BSD-2-Clause terms.
- Snapshot taken: 2026-10-02 (`main` branch)

## File Mapping

| Local file | Upstream path |
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
| `examples/rule-*.lua` | `rules/*.lua`, `rules/third_party/*.lua` |
| `examples/plugin-*.lua` | `plugins/*.lua`, `plugins/third_party/*.lua` |
| `examples/manager.sh` | `docker/manager.sh` |

> Note: this copy mirrors the **Chinese** edition of the upstream docs. The corresponding English originals live under `docs/api/` and `docs/guide/` upstream.

## ⚠️ Freshness

The offline copy is a **point-in-time snapshot** and may lag behind upstream. For anything time-sensitive, prefer fetching online:

```bash
# Official API documentation (authoritative)
curl -sL https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/zh-cn/api/README.md

# Changelog (version watersheds, new features, fixed issues)
curl -sL https://raw.githubusercontent.com/Safe3/uusec-waf/main/docs/CHANGELOG.md
```

## Attribution (Read Before Citing)

| Path prefix | Attribution |
|:---|:---|
| `rules/*.lua`, `plugins/*.lua`, `docs/`, `docker/` | **Officially maintained** |
| `rules/third_party/*`, `plugins/third_party/*` | **Community contributions** (distributed with the repository, not officially maintained) |

Wording conventions when citing:

- Official files → "official built-in rule / plugin"
- Third-party files → "**community-contributed reference implementation**" (**do not** write "official implementation")

Community-contributed files under `examples/` **retain their original author attribution** (the `Author:` line in the file header). This is required for provenance tracking and is not removable content.
