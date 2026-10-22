#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UUSEC WAF (南墙) 控制台 REST API 客户端 —— 纯标准库、无第三方依赖、支持多实例。

用法
----
  waf.py init                                     生成配置骨架（用户自己填 url/token）
  waf.py hosts                                    列出配置中全部实例
  waf.py hosts --add <名称> --url <URL> [--token <T>|--token -] [--update]
                                                 代填实例（`--token -` = 从 stdin 读，不回显）
  waf.py -i <实例名> ping                          连通 + 认证自检
  waf.py -i <实例名> list <资源>                   快捷列表: sites|rules|ruleset|certs|plugins|users
  waf.py -i <实例名> api <METHOD> <PATH> [BODY]    发任意请求
  waf.py -i <实例名> logs [-q <QUERY_JSON>] [--table] [--raw] [--page N] [--size N]
                                                   日志查询（默认隐藏 request 字段）
  waf.py -i <实例名> top | total | live | report    仪表盘快捷数据
  waf.py -i <实例名> ruleset <ID>                  打印指定规则集内的规则清单
  waf.py -i <实例名> get rule <ID> [--field 字段] [--out 文件]
                                                   取单条规则字段（默认 content）
  waf.py -i <实例名> push rule <ID|new> --file 文件 [--name N] [--lf] [--dry-run]
                                                   回写规则正文（保真；new=新建）
  waf.py -i <实例名> push ruleset <ID> [--set JSON | --add ID… | --remove ID…]
                                                   改规则集启用清单
  waf.py -i <实例名> ipblock [--check <IP> | --unlock <IP> | --check-all | --unlock-all]
                                                   封禁名单（--check-all 同）/ 查状态 / 解封
  waf.py -i <实例名> backup [config|db] [--out 文件]
                                                   导出配置 / 数据库备份（改前必做）
  waf.py -i <实例名> delete rule|ruleset|cert|plugin <ID> [--dry-run]
                                                   删除（生产写操作，先取授权）
  waf.py -i <实例名A> diff rule|ruleset <ID> --with <实例名B>
                                                   跨实例比对同一规则/规则集（字节级）
  waf.py -h | --help                               帮助

写路径说明
----------
  * `get`/`push` 解决「没有 GET /rules/{id}」与「正文无法内联进 shell」两个硬伤：
    先把正文落到文件，改完再回写，**字节保真**（不归一化换行，除非显式 --lf）。
  * `push` 会先 GET 当前对象，只替换指定字段后回写 —— 不猜字段形状。
    加 `--dry-run` 只打印将发送的 body，不发请求。
  * 写操作需 `waf_nodes` 非空；属生产变更，执行前先取授权（见 SKILL.md 操作纪律）。

实例来源（优先级）
------------------
  1. `-i <实例名>`：从配置文件 ~/.config/waf-hosts.json 选实例（推荐）。
  2. 环境变量（无 -i 时兜底）：WAF_API_URL + WAF_API_TOKEN。

配置文件格式（~/.config/waf-hosts.json，权限应为 600）
-----------------------------------------------------
  {
    "<实例名>": {"url": "https://<服务器IP>:4443", "token": "<Api-Token>"}
  }
  - 新用户：先 `waf.py init` 生成骨架，填好后 `-i <实例名> ping` 自检。
  - 加新 WAF：往该文件加一段即可，本脚本零改动；也可 `hosts --add` 代填。
  - token 存 600 权限文件，由脚本读取，不经模型上下文、不进对话。
  - url 填面板可达地址（本机 127.0.0.1 / 内网 IP / 域名均可），端口用面板端口 4443。
  - Api-Token 在面板「系统设置 → API 接口访问 Token」复制（复制需登录面板；之后调 API 只用该 token）。

安全说明
--------
  * 所有请求自动跳过自签证书校验（面板默认自签）。
  * `logs` 子命令默认移除 `request` 字段 —— 该字段含 Authorization / Cookie 等凭据。
    确需原始报文时显式加 `--raw`，并自行确保不落盘、不回显。
  * 认证失败返回 `{"message":"missing or malformed jwt"}`，通常为 token 逐字错误。

常见误用（详见 references/management-api.md）
--------------------------------------------
  * 查日志必须用 POST；`GET /logs` 返回 Not Found。
  * 日志 `time_range` 必须带时分秒；纯日期会静默返回 0 条。本脚本会自动补齐时分秒。
  * `level: 5` 表示"全部"。
  * 取规则正文用 `GET /rules`；`GET /ruleset/rules` 返回的 content 恒为空。
"""
import difflib
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

CONFIG_PATH = os.path.expanduser("~/.config/waf-hosts.json")
API_PREFIX = "/api/v1"

BASE = None
TOKEN = None
INSTANCE = None


# --------------------------------------------------------------------------- #
# 实例选择
# --------------------------------------------------------------------------- #
def _load_config(raw=False):
    """读配置。raw=False 时跳过 `_` 开头的说明键（它们不是实例）。"""
    if not os.path.exists(CONFIG_PATH):
        _die("未找到配置文件 %s\n"
             "  可先跑 `waf.py init` 生成骨架，或用环境变量 WAF_API_URL + WAF_API_TOKEN"
             % CONFIG_PATH)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:                                    # noqa: BLE001
        _die("配置文件解析失败: %s" % exc)
    if raw:
        return data
    return {k: v for k, v in data.items() if not str(k).startswith("_")}


def _is_placeholder(v):
    """骨架里的占位值（空 / `<...>`）不算"已配置"。"""
    s = str(v or "").strip()
    return (not s) or s.startswith("<")


def _save_config(cfg):
    """原子写回配置，权限固定 600（凭据文件，不进 git、不进对话）。"""
    os.makedirs(os.path.dirname(CONFIG_PATH) or ".", mode=0o700, exist_ok=True)
    tmp = "%s.tmp-%d" % (CONFIG_PATH, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)


SKELETON = {
    "_说明": ("每个键是一个 WAF 实例：url = 面板可达地址（如 https://<服务器IP>:4443，"
              "端口是面板端口；80/443 是数据面、4447 是内置管理面）；"
              "token = 面板「系统设置 → API 接口访问 Token」里复制的那串。"
              "本文件权限须为 600，不要提交到 git、不要贴进对话。"),
    "mywaf": {"url": "https://<服务器IP>:4443", "token": "<在这里粘贴 Api-Token>"},
}


def cmd_init(force=False):
    """生成配置骨架，交给用户自己填 url / token。"""
    if os.path.exists(CONFIG_PATH):
        if not force:
            print("配置文件已存在：%s" % CONFIG_PATH)
            print("  （只加实例用 `hosts --add`；确实要重建用 `init --force`，旧文件会先备份）")
            return
        bak = "%s.bak-%s" % (CONFIG_PATH, time.strftime("%Y%m%d-%H%M%S"))
        os.replace(CONFIG_PATH, bak)
        os.chmod(bak, 0o600)
        print("旧配置已备份：%s" % bak)
    _save_config(SKELETON)
    print("已生成配置骨架：%s（权限 600）" % CONFIG_PATH)
    print("  ① 把 `mywaf` 改成实例名、填上 url 与 token（或让 agent 用 `hosts --add` 代填）")
    print("  ② 自检：python3 %s -i <实例名> ping" % sys.argv[0])


def _select(name):
    global BASE, TOKEN, INSTANCE
    cfg = _load_config()
    if name not in cfg:
        _die("配置文件中不存在实例 '%s'。可用: %s" % (name, ", ".join(cfg) or "(空)"))
    entry = cfg[name] or {}
    BASE = str(entry.get("url", "")).rstrip("/")
    TOKEN = str(entry.get("token", ""))
    INSTANCE = name
    if not BASE or not TOKEN:
        _die("实例 '%s' 缺少 url 或 token" % name)


def _use_env():
    global BASE, TOKEN, INSTANCE
    BASE = os.environ.get("WAF_API_URL", "").rstrip("/")
    TOKEN = os.environ.get("WAF_API_TOKEN", "")
    INSTANCE = "(env)"
    if not BASE or not TOKEN:
        _die("缺少实例：请用 -i <实例名> 选配置实例，"
             "或设置环境变量 WAF_API_URL + WAF_API_TOKEN")


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def _req(method, path, body=None, timeout=30, raw_path=False):
    """发请求。path 不以 / 开头时自动加 /api/v1 前缀。"""
    url = path if raw_path else (BASE + API_PREFIX + path)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE              # 面板默认自签证书
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("Api-Token", TOKEN)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            # 部分端点返回带 UTF-8 BOM 的 JSON（如 /setting/ipBlock/all），
            # 用 utf-8-sig 解码自动剥掉 BOM，否则 json.loads 会失败。
            return resp.status, resp.read().decode("utf-8-sig", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8-sig", "replace")
    except Exception as exc:                                    # noqa: BLE001
        _die("请求失败: %s" % exc)


def _pretty(text):
    try:
        return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
    except Exception:                                           # noqa: BLE001
        return text


def _die(msg):
    sys.stderr.write("[错误] %s\n" % msg)
    sys.exit(2)


# --------------------------------------------------------------------------- #
# 日志查询辅助
# --------------------------------------------------------------------------- #
def _norm_time_range(tr):
    """把纯日期补成带时分秒的时间范围。

    面板对 `["YYYY-MM-DD","YYYY-MM-DD"]` 会静默返回 0 条；
    必须带时分秒才生效。这里自动补齐，避免踩坑。
    """
    if not tr:
        return []
    if not isinstance(tr, (list, tuple)) or len(tr) != 2:
        _die("time_range 必须是 [起, 止] 两元素数组")
    out = []
    for idx, item in enumerate(tr):
        s = str(item).strip()
        if not s:
            return []
        if " " not in s:
            s = s + (" 00:00:00" if idx == 0 else " 23:59:59")
        out.append(s)
    return out


def _strip_request(record):
    """移除含凭据的 request 字段。"""
    if isinstance(record, dict) and "request" in record:
        rec = dict(record)
        raw = rec.pop("request", "")
        rec["request"] = "<已省略 %d 字节，含凭据；需要时用 --raw>" % len(str(raw))
        return rec
    return record


def cmd_logs(args):
    query, page, size, table, want_raw = {}, 1, 20, False, False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-q" and i + 1 < len(args):
            try:
                query = json.loads(args[i + 1])
            except Exception as exc:                             # noqa: BLE001
                _die("解析 -q 失败: %s" % exc)
            i += 2
            continue
        if a == "--page" and i + 1 < len(args):
            page = int(args[i + 1]); i += 2; continue
        if a == "--size" and i + 1 < len(args):
            size = int(args[i + 1]); i += 2; continue
        if a == "--table":
            table = True; i += 1; continue
        if a == "--raw":
            want_raw = True; i += 1; continue
        _die("logs 未知参数: %s" % a)

    query.setdefault("level", 5)                # 5 = 全部
    if "time_range" in query:
        query["time_range"] = _norm_time_range(query["time_range"])

    status, text = _req("POST", "/logs",
                        {"page": page, "page_size": size, "query": query})
    try:
        payload = json.loads(text)
    except Exception:                                            # noqa: BLE001
        _die("返回非 JSON（HTTP %s）: %s" % (status, text[:200]))
    if isinstance(payload, dict) and payload.get("err"):
        _die(payload["err"])

    rows = payload.get("data", [])
    total = payload.get("total", 0)
    if not want_raw:
        rows = [_strip_request(r) for r in rows]

    if table and rows:
        print("total=%s  page=%s  size=%s" % (total, page, size))
        print("%-20s %-8s %-18s %-16s %-26s %s" %
              ("updated_at", "level", "rule", "ip", "host", "url"))
        for r in rows:
            print("%-20s %-8s %-18s %-16s %-26s %s" % (
                str(r.get("updated_at", ""))[:19],
                r.get("level", ""),
                str(r.get("name", ""))[:18],
                str(r.get("ip", ""))[:16],
                str(r.get("host", ""))[:26],
                str(r.get("url", ""))[:60],
            ))
        print("(request 字段已省略；如确需原始报文，加 --raw)")
    else:
        print(json.dumps({"total": total, "data": rows},
                         ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------- #
# 子命令
# --------------------------------------------------------------------------- #
LIST = {
    "sites":   "GET /sites",
    "rules":   "GET /rules",
    "ruleset": "GET /ruleset",
    "certs":   "GET /certs",
    "plugins": "GET /plugins",
    "users":   "GET /users",
}


def cmd_list(resource):
    if resource not in LIST:
        _die("可用资源: %s" % ", ".join(sorted(LIST)))
    method, path = LIST[resource].split(" ", 1)
    status, text = _req(method, path)
    if status >= 400:
        _die("HTTP %s: %s" % (status, text[:200]))
    try:
        data = json.loads(text)
    except Exception:                                            # noqa: BLE001
        print(text); return

    if resource == "sites":
        if isinstance(data, dict) and isinstance(data.get("sites"), list):
            print("规则集选项:")
            for opt in data.get("options", []) or []:
                print("  [%s] %s" % (opt.get("value"), opt.get("label")))
            print("站点:")
            for s in data["sites"]:
                hosts = s.get("hosts")
                hosts = ",".join(hosts) if isinstance(hosts, list) else str(hosts)
                print("  [%s] %-46s ruleset=%s  mode=%s  %s" % (
                    s.get("id"), hosts, s.get("ruleset_id"),
                    s.get("mode"), s.get("description", "")))
            print("(mode: true=拦截模式 / false=观察模式；规则集 ID 见上方选项)")
            return
    if resource == "ruleset":
        for rs in data if isinstance(data, list) else [data]:
            try:
                ids = json.loads(rs.get("content") or "[]")
            except Exception:                                    # noqa: BLE001
                ids = []
            print("  [%s] %-14s %d 条  %s" %
                  (rs.get("id"), rs.get("name"), len(ids), rs.get("updated_at", "")))
            print("       %s" % json.dumps(ids, separators=(",", ":")))
        return
    if resource in ("rules", "certs", "plugins", "users"):
        for item in data if isinstance(data, list) else [data]:
            if resource == "rules":
                t = item.get("type")
                tag = "Lua" if t == 1 else ("DSL" if t == 0 else "?")
                nm = item.get("name") or "（DSL 规则，内容在 content）"
                print("  [%s] %-26s type=%s(%s) level=%s phase=%s len=%s" % (
                    item.get("id"), str(nm)[:26], t, tag,
                    item.get("level"), item.get("phase"),
                    len(item.get("content") or "")))
            elif resource == "certs":
                print("  [%s] %-20s sni=%s" % (
                    item.get("id"), str(item.get("name"))[:20], item.get("sni", "")))
            elif resource == "plugins":
                print("  [%s] %-20s enabled=%s" % (
                    item.get("id"), str(item.get("name"))[:20], item.get("enabled")))
            else:
                print("  [%s] %s  otp=%s" % (
                    item.get("id"), item.get("usr"), item.get("enable_otp")))
        print("(注: rules 的 content 已省略；取正文用 `api GET /rules` 后本地筛选——"
              "没有 `GET /rules/{id}`，实测返回 Not Found)")
        return
    print(_pretty(text))


def cmd_ruleset(rid):
    """打印规则集成员。

    注意: `GET /ruleset/rules` 的 `id` 参数**不生效**（恒返回规则库全量摘要），
    因此这里改为读 `GET /ruleset` 拿到各规则集的 `content` 数组（真正的成员清单），
    再按需过滤到指定规则集。
    """
    status, text = _req("GET", "/ruleset")
    if status >= 400:
        _die("HTTP %s: %s" % (status, text[:200]))
    try:
        sets = json.loads(text)
    except Exception:                                            # noqa: BLE001
        print(text); return
    if not isinstance(sets, list):
        sets = [sets]

    wanted = str(rid) if rid else None
    if wanted and not any(str(s.get("id")) == wanted for s in sets):
        _die("规则集 %s 不存在。可用: %s" %
             (rid, ", ".join("%s(%s)" % (s.get("id"), s.get("name")) for s in sets)))

    for rs in sets:
        if wanted and str(rs.get("id")) != wanted:
            continue
        try:
            ids = json.loads(rs.get("content") or "[]")
        except Exception:                                        # noqa: BLE001
            ids = []
        print("规则集 [%s] %s —— %d 条启用规则:" %
              (rs.get("id"), rs.get("name"), len(ids)))
        print("  %s" % json.dumps(ids, separators=(",", ":")))
        print("  （执行顺序按规则 ID 升序，与数组顺序无关）")


def _field_hint(path):
    """对已知端点，返回一行字段含义提示（避免每次翻文档）。"""
    H = {
        "/sites": "hosts=域名数组 mode=bool(true拦截/false观察) type=LB算法(roundrobin|chash|swrr) "
                  "servers=[{ip,port,weight}] scheme=回源协议 ip_source=0socket/1XFF/2自定义头 "
                  "ip_order=倒数第n ip_header=头名 is_websocket/is_ml/is_cache/force_ssl=bool",
        "/rules": "type=0DSL/1Lua level=0提示..4严重 phase=0请求/1返回头/2返回体 "
                  "content=正文(CRLF或LF) name仅Lua有(DSL为空) uid恒1(非内置判据)",
        "/ruleset": "content=JSON数组字符串(启用哪些规则ID；执行按ID升序，数组顺序无意义)",
        "/certs": "type=0申请/1上传 sni=JSON数组字符串 crt/key=PEM(敏感) dns_credential(敏感)",
        "/plugins": "name=标识 enabled=bool content=Lua全文(系统自带含示例凭据，勿照抄)",
        "/users": "role=0管理员/1操作员/2审计员 pwd_expiration=0不限/45/90/180 "
                  "otp_url含TOTP明文(敏感) fail=登录失败次数",
        "/setting": "id/addr/dsn(敏感)/jwt_key(敏感)/jwt_expiration/waf_nodes=数组[\"ip:port\"]/"
                    "ml_server/ml_token(敏感)/api_token(敏感)/log_db(bool)/log_level(error|info|debug)/language/version",
        "/setting/waf": "resolver/listen/http2/ssl/gzip/cache/proxy/error_page/log 等数据面参数",
        "/cdn": "host=域名 uri=正则路径 cache_time=单位s/m/h/d/M/y enabled=bool",
        "/ml": "host/uri/schema/enabled（商业版；社区版返回升级提示）",
        "/logs/total": "[总请求,今日,7天,拦截]",
        "/logs/top": "{attackers,sites,types}",
        "/logs/live": "{usage:{cpu,mem,disk},req,atk,geo}(atk/geo是JSON字符串，需二次解析)",
        "/audits": "type=操作类型 usr ip info updated_at",
    }
    key = path.split("?")[0]
    if key in H:
        return H[key]
    if key.startswith("/setting/ipBlock"):
        return "动作：check=查状态 / unlock=解封 / checkAll / unlockAll（body 均 {ip}）"
    if key.startswith("/rules/"):
        return "单删（无 body）；取正文须 GET /rules 后筛选（无 GET /rules/{id}）"
    return None


def cmd_api(args):
    if len(args) < 2:
        _die("用法: waf.py -i <实例名> api <METHOD> <PATH> [BODY_JSON]")
    method, path = args[0].upper(), args[1]
    body = None
    if len(args) > 2:
        try:
            body = json.loads(args[2])
        except Exception as exc:                                 # noqa: BLE001
            _die("解析 BODY 失败: %s" % exc)
    status, text = _req(method, path, body)
    print(_pretty(text))
    hint = _field_hint(path)
    if hint:
        print("\n# 字段含义（%s）：%s" % (path, hint))
    sys.exit(0 if status < 400 else 1)


def cmd_hosts(rest=()):
    """无参数 = 列出实例；`--add <名称> --url <URL> [--token <T>|--token -] [--update]` = 代填。"""
    if "--add" in rest or "--url" in rest or "--token" in rest:
        return _hosts_add(rest)
    if not os.path.exists(CONFIG_PATH):
        print("未找到配置文件 %s" % CONFIG_PATH)
        print("  可先跑 `waf.py init` 生成骨架，或改用环境变量 WAF_API_URL + WAF_API_TOKEN。")
        return
    cfg = _load_config()
    if not cfg:
        print("配置文件为空。")
        return
    print("已配置的 WAF 实例 (%s):" % CONFIG_PATH)
    for name, entry in cfg.items():
        entry = entry or {}
        tok = str(entry.get("token", ""))
        # 只报「是否已配置」与长度，不回显 token 任何片段 —— 避免凭据进入模型上下文
        state = "(待填)" if _is_placeholder(tok) else ("已配置(%d 字符)" % len(tok))
        url = str(entry.get("url", ""))
        print("  - %-14s %-32s token=%s%s" %
              (name, url, state, "  ← url 也是占位" if _is_placeholder(url) else ""))


def _hosts_add(rest):
    """把用户给的 url / token 写进配置文件。token 支持从 stdin 读（`--token -`），
    避免出现在命令行历史里；任何情况下都不回显 token。"""
    name = url = token = None
    update = "--update" in rest
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--update":
            i += 1
            continue
        if a in ("--add", "--url", "--token"):
            if i + 1 >= len(rest):
                _die("用法: waf.py hosts --add <名称> --url <URL> [--token <T>|--token -] [--update]")
            val = rest[i + 1]
            if a == "--add":
                name = val
            elif a == "--url":
                url = val
            else:
                token = sys.stdin.read().strip() if val == "-" else val
            i += 2
            continue
        _die("用法: waf.py hosts --add <名称> --url <URL> [--token <T>|--token -] [--update]")
    if not name or not url:
        _die("用法: waf.py hosts --add <名称> --url <URL> [--token <T>|--token -] [--update]")
    cfg = _load_config(raw=True) if os.path.exists(CONFIG_PATH) else dict(SKELETON)
    if name in cfg and not update:
        _die("实例 '%s' 已存在（要覆盖加 --update）" % name)
    cfg[name] = {"url": url.rstrip("/"),
                 "token": token if token is not None else "<在这里粘贴 Api-Token>"}
    _save_config(cfg)
    n = len(str(cfg[name]["token"]))
    print("已写入实例 '%s'：url=%s  token=%s" %
          (name, cfg[name]["url"], "(待填)" if _is_placeholder(cfg[name]["token"])
           else "已配置(%d 字符)" % n))
    print("  自检：python3 %s -i %s ping" % (sys.argv[0], name))
    if token:
        print("  提醒：若 token 是通过对话/命令行给的，建议按需轮换（它已出现在那些记录里）。")


# --------------------------------------------------------------------------- #
# 写路径：get / push / ipblock
# --------------------------------------------------------------------------- #
def _http(method, path, body=None):
    """发请求并把返回解析为 JSON；非 2xx 或非 JSON 一律报错退出。"""
    status, text = _req(method, path, body)
    if status >= 400:
        _die("HTTP %s: %s" % (status, text[:300]))
    try:
        return json.loads(text)
    except Exception:                                            # noqa: BLE001
        _die("返回非 JSON（HTTP %s）: %s" % (status, text[:200]))


def _find(lst, rid):
    for item in lst if isinstance(lst, list) else []:
        if str(item.get("id")) == str(rid):
            return item
    return None


def _to_id(v):
    """把规则 ID 尽量规范成 int（规则集 content 里服务端存的是 int）。"""
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def cmd_get(args):
    """取单条规则的字段（默认 content）—— 绕开「没有 GET /rules/{id}」。

    正文含 CRLF 时按字节原样写文件（newline="" 不做换行转换），
    保证「取 → 改 → 回写」不产生整文件伪 diff。
    """
    if len(args) < 2 or args[0] != "rule":
        _die("用法: waf.py -i <实例名> get rule <ID> [--field 字段] [--out 文件]\n"
             "  --field 默认 content；用 --field __meta__ 只看元信息（不含正文）")
    rid, field, out = args[1], "content", None
    i = 2
    while i < len(args):
        a = args[i]
        if a == "--field" and i + 1 < len(args):
            field = args[i + 1]; i += 2; continue
        if a == "--out" and i + 1 < len(args):
            out = args[i + 1]; i += 2; continue
        _die("get 未知参数: %s" % a)

    rules = _http("GET", "/rules")
    rule = _find(rules, rid)
    if rule is None:
        ids = ", ".join(str(r.get("id")) for r in rules) if isinstance(rules, list) else "?"
        _die("规则 %s 不存在。共 %s 条，可用 ID: %s" %
             (rid, len(rules) if isinstance(rules, list) else "?", ids))

    if field == "__meta__":
        print(json.dumps({k: v for k, v in rule.items() if k != "content"},
                         ensure_ascii=False, indent=2))
        return
    if field not in rule:
        _die("规则 %s 无字段 '%s'。可用: %s" % (rid, field, ", ".join(sorted(rule))))

    val = rule.get(field)
    text = val if isinstance(val, str) else json.dumps(val, ensure_ascii=False, indent=2)
    if out:
        # newline="" → 不转换换行，CRLF / LF 原样落盘（字节保真）
        with open(out, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print("已写入 %s（%d 字符，CRLF 行 %d，LF 行 %d）" %
              (out, len(text), text.count("\r\n"),
               text.count("\n") - text.count("\r\n")))
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _read_payload(fpath, to_lf):
    if not fpath:
        _die("必须用 --file 指定正文文件（避免正文内联进 shell 造成转义/换行损坏）")
    if not os.path.exists(fpath):
        _die("文件不存在: %s" % fpath)
    with open(fpath, encoding="utf-8", newline="") as fh:
        content = fh.read()
    if to_lf:
        content = content.replace("\r\n", "\n")
    if content == "":
        _die("文件为空，拒绝写入（如需清空正文请走面板）")
    return content


def _push_rule(args):
    dry = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    if not args:
        _die("用法: waf.py -i <实例名> push rule <ID|new> --file <文件> "
             "[--name 名称] [--type 1] [--level 3] [--phase 0] [--lf] [--dry-run]\n"
             "  new = 新建（POST / id=0）；填数字 ID = 更新（PUT，带 id）")
    target = args[0]
    fpath, name, to_lf, opts = None, None, False, {}
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--file" and i + 1 < len(args):
            fpath = args[i + 1]; i += 2; continue
        if a == "--name" and i + 1 < len(args):
            name = args[i + 1]; i += 2; continue
        if a == "--lf":
            to_lf = True; i += 1; continue
        if a in ("--type", "--level", "--phase", "--description") and i + 1 < len(args):
            opts[a[2:]] = args[i + 1]; i += 2; continue
        _die("push rule 未知参数: %s" % a)

    content = _read_payload(fpath, to_lf)

    if target in ("new", "0"):
        body = {"id": 0, "name": name or os.path.basename(fpath),
                "type": int(opts.get("type", 1)), "level": int(opts.get("level", 3)),
                "phase": int(opts.get("phase", 0)),
                "description": opts.get("description", ""), "content": content}
        method, action = "POST", "新建"
    else:
        cur = _find(_http("GET", "/rules"), target)
        if cur is None:
            _die("规则 %s 不存在。更新请确认 ID；新建请用 `push rule new`。" % target)
        body = dict(cur)                     # 以服务端当前对象为底，只动必要字段
        body["content"] = content
        if name is not None:
            body["name"] = name
        for k in ("type", "level", "phase"):
            if k in opts:
                body[k] = int(opts[k])
        if "description" in opts:
            body["description"] = opts["description"]
        method, action = "PUT", "更新"

    print("将%s规则 %s：%d 字符（CRLF 行 %d / LF 行 %d），type=%s level=%s phase=%s" %
          (action, target, len(content), content.count("\r\n"),
           content.count("\n") - content.count("\r\n"),
           body.get("type"), body.get("level"), body.get("phase")))
    if dry:
        print("[dry-run] 未发送。将提交 body 的字段: %s" % ", ".join(sorted(body)))
        return
    res = _http(method, "/rules", body)
    print("已提交（%s /rules）：%s" % (method, json.dumps(res, ensure_ascii=False)[:300]))
    print("提示：规则须挂进站点所用规则集才生效；验收看实际生效状态，不看 HTTP 200。")


def _push_ruleset(args):
    dry = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    if not args:
        _die("用法: waf.py -i <实例名> push ruleset <ID> "
             "[--set '[9,500]' | --add 500 | --remove 19] [--dry-run]")
    rid = args[0]
    sets = _http("GET", "/ruleset")
    if not isinstance(sets, list):
        sets = [sets]
    cur = _find(sets, rid)
    if cur is None:
        _die("规则集 %s 不存在。可用: %s" %
             (rid, ", ".join("%s(%s)" % (s.get("id"), s.get("name")) for s in sets)))

    try:
        ids = json.loads(cur.get("content") or "[]")
    except Exception:                                            # noqa: BLE001
        ids = []
    before = list(ids)
    i = 1
    while i < len(args):
        a = args[i]
        if a in ("--set", "--add", "--remove") and i + 1 < len(args):
            v = args[i + 1]
            if a == "--set":
                ids = json.loads(v)
            elif a == "--add":
                if _to_id(v) not in ids:
                    ids.append(_to_id(v))
            else:
                ids = [x for x in ids if str(x) != str(v)]
            i += 2; continue
        _die("push ruleset 未知参数: %s" % a)

    added = [x for x in ids if x not in before]
    removed = [x for x in before if x not in ids]
    print("规则集 [%s] %s：%d → %d 条（+%s / -%s）" %
          (cur.get("id"), cur.get("name"), len(before), len(ids),
           ",".join(map(str, added)) or "无", ",".join(map(str, removed)) or "无"))
    if ids == before:
        print("无变化，未发送。")
        return
    body = dict(cur)
    body["content"] = json.dumps(ids)
    if dry:
        print("[dry-run] 未发送。将提交规则集 %s 的 content。" % cur.get("id"))
        return
    res = _http("PUT", "/ruleset", body)
    print("已提交（PUT /ruleset）：%s" % json.dumps(res, ensure_ascii=False)[:200])
    print("提示：数组顺序无意义，执行按规则 ID 升序；改前建议先 GET /setting/backupConfig 备份。")


def cmd_push(args):
    if not args:
        _die("用法: waf.py -i <实例名> push rule|ruleset …（见 waf.py -h）")
    if args[0] == "rule":
        _push_rule(args[1:])
    elif args[0] == "ruleset":
        _push_ruleset(args[1:])
    else:
        _die("push 仅支持: rule | ruleset")


def cmd_ipblock(args):
    """IP 封禁名单操作。

    实测前端只有四个动作（PUT /setting/ipBlock/<action>，body {"ip":...}）：
      check / unlock / checkAll / unlockAll
    注意 `check` 是**查询**该 IP 的封禁状态（返回 {locked:bool}），**不是**解封。
    """
    ACTIONS = {"check": "查询单个 IP 封禁状态", "unlock": "解除单个 IP 封禁",
               "checkAll": "导出全部名单（同默认输出）", "unlockAll": "解除所有"}
    if args:
        a = args[0]
        if a == "--check-all":
            # 面板「查询所有」按钮实际是下载 GET /setting/ipBlock/all（JSONL），并非调用 PUT .../checkAll
            # （后者需合法 ip，UI 从不使用）。这里保持一致：直接导出名单。
            _print_ipblock()
            return
        if a == "--unlock-all":
            print(json.dumps(_http("PUT", "/setting/ipBlock/unlockAll", {}),
                             ensure_ascii=False))
            print("（解除所有封禁属生产变更，解前先确认确非攻击源）")
            return
        if a in ("--check", "--unlock"):
            if len(args) < 2:
                _die("用法: waf.py -i <实例名> ipblock %s <IP>" % a)
            act = "check" if a == "--check" else "unlock"
            res = _http("PUT", "/setting/ipBlock/" + act, {"ip": args[1]})
            print("%s %s：%s" % (ACTIONS[act], args[1],
                                 json.dumps(res, ensure_ascii=False)))
            if act == "unlock":
                print("（解封属生产变更：先确认该 IP 确实不是攻击源）")
            return
        _die("ipblock 未知参数: %s\n"
             "  用法: ipblock [--check <IP> | --unlock <IP> | --check-all | --unlock-all]\n"
             "  %s" % (a, "；".join("%s=%s" % (k, v) for k, v in ACTIONS.items())))
    _print_ipblock()


def _print_ipblock():
    status, text = _req("GET", "/setting/ipBlock/all")
    if status >= 400:
        _die("HTTP %s: %s" % (status, text[:300]))
    # 前端把 checkAll 的结果下载为 ipblock.jsonl —— body 是 JSONL（一行一个对象），空名单为 `{}`。
    # 所以不能用 json.loads 整段解析，也不能把 dict 当成"1 条"。
    recs = []                                    # [(ip, 备注)]
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(obj, dict):
            ipk = next((k for k in ("ip", "address", "addr", "key") if k in obj), None)
            if ipk:                              # 单条记录：{"ip":...,"count":...}
                recs.append((str(obj[ipk]),
                             "，".join("%s=%s" % (k, v) for k, v in obj.items()
                                       if k != ipk)))
            else:                                # 映射形式：{"1.2.3.4": 次数}
                for k, v in obj.items():
                    recs.append((str(k), "" if v is True else "次数=%s" % v))
        elif isinstance(obj, list):
            recs.extend((str(x), "") for x in obj)
        else:
            recs.append((str(obj), ""))
    print("IP 封禁名单（%d 条；存于 Lua 共享内存 ipBlock，TTL 600s，停止触发后自清）:" %
          len(recs))
    if not recs:
        print("  （空）")
    for ip, note in recs:
        print("  %s%s" % (ip, ("  " + note) if note else ""))


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def _fetch_rule(rid):
    rules = _http("GET", "/rules")
    rule = _find(rules, rid)
    if rule is None:
        _die("规则 %s 不存在" % rid)
    return rule


def cmd_delete(args):
    """单条删除：rule/ruleset 走路径删除，cert/plugin 走 body 批量删除。"""
    if len(args) < 2:
        _die("用法: waf.py -i <实例名> delete rule|ruleset|cert|plugin <ID> [--dry-run]\n"
             "  ⚠️ 删除属生产写操作：先取授权，必要时先 `backup`。")
    kind, rid = args[0], _to_id(args[1])
    dry = "--dry-run" in args
    if kind in ("rule", "ruleset"):
        path, body = "/%ss/%s" % (kind, rid), None
    elif kind in ("cert", "plugin"):
        path, body = "/%ss" % kind, {"keys": [rid]}
    else:
        _die("delete 只支持 rule / ruleset / cert / plugin")
    if dry:
        print("[dry-run] DELETE %s  body=%s" % (path, json.dumps(body) if body else "无"))
        return
    status, text = _req("DELETE", path, body)
    print("[HTTP %s] %s" % (status, _pretty(text)))
    if status < 400:
        print("⚠️ 已提交删除。请核对：站点是否仍挂在被删的规则集上；规则集 content 是否还引用它。")


def cmd_backup(args):
    """导出配置 / 数据库备份到本地文件（改前备份用）。"""
    what = args[0] if args and not args[0].startswith("-") else "config"
    out = None
    i = 0
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            out = args[i + 1]; i += 2; continue
        i += 1
    if what not in ("config", "db"):
        _die("用法: waf.py -i <实例名> backup [config|db] [--out 文件]")
    path = "/setting/backupConfig" if what == "config" else "/setting/backupDB"
    status, text = _req("GET", path)
    if status >= 400:
        _die("备份失败 HTTP %s: %s" % (status, text[:200]))
    if not out:
        out = "/tmp/waf-%s-backup-%s.json" % (what, time.strftime("%Y%m%d-%H%M%S"))
    # 备份含口令/密钥 → 权限 600，避免落到 /tmp 被人读
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    hint = "（权限 600；改前备份，验证无误后可删）"
    if what == "config":
        hint = "🔴 含敏感字段（dsn/jwt_key/api_token/ml_token）：勿回显、勿入库 " + hint
    print("已保存 %s：%d 字节 %s" % (out, len(text.encode()), hint))


def cmd_diff(args):
    """跨实例比对同一条规则 / 规则集（字节级 + 首个差异）。"""
    if len(args) < 2 or args[0] not in ("rule", "ruleset"):
        _die("用法: waf.py -i <实例名A> diff rule|ruleset <ID> --with <实例名B> [--field content]")
    kind, rid, other, field = args[0], args[1], None, "content"
    i = 2
    while i < len(args):
        if args[i] == "--with" and i + 1 < len(args):
            other = args[i + 1]; i += 2; continue
        if args[i] == "--field" and i + 1 < len(args):
            field = args[i + 1]; i += 2; continue
        _die("diff 未知参数: %s" % args[i])
    if not other:
        _die("需要 --with <实例名B>")
    res = "/rules" if kind == "rule" else "/ruleset"
    one = _find(_http("GET", res), rid)
    if one is None:
        _die("%s %s 在 %s 上不存在" % (kind, rid, INSTANCE))
    left, left_name = str(one.get(field) or ""), INSTANCE
    _select(other)
    two = _find(_http("GET", res), rid)
    if two is None:
        _die("%s %s 在 %s 上不存在" % (kind, rid, INSTANCE))
    right, right_name = str(two.get(field) or ""), INSTANCE
    lb, rb = left.encode(), right.encode()
    print("%s %s · field=%s" % (kind, rid, field))
    print("  %-10s %7d 字节  CRLF %-4d md5 %s" %
          (left_name, len(lb), lb.count(b"\r\n"), hashlib.md5(lb).hexdigest()))
    print("  %-10s %7d 字节  CRLF %-4d md5 %s" %
          (right_name, len(rb), rb.count(b"\r\n"), hashlib.md5(rb).hexdigest()))
    if lb == rb:
        print("  ✅ 逐字节一致")
        return
    if lb.replace(b"\r\n", b"\n") == rb.replace(b"\r\n", b"\n"):
        print("  ⚠️ 仅换行符不同（CRLF vs LF），内容一致")
        return
    print("  ❌ 内容不同（左 %s / 右 %s），逐行差异：" % (left_name, right_name))
    for line in list(difflib.unified_diff(left.splitlines(), right.splitlines(),
                                          lineterm="", n=1))[:40]:
        print("    " + line)


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    name = None
    if argv[0] == "-i":
        if len(argv) < 2:
            _die("-i 后面需要实例名")
        name, argv = argv[1], argv[2:]
    if not argv:
        print(__doc__)
        sys.exit(0)

    if argv[0] == "init":                        # 不需要选实例
        cmd_init(force="--force" in argv[1:])
        return
    if argv[0] == "hosts":                       # hosts 不需要选实例
        cmd_hosts(argv[1:])
        return

    # 先校验子命令，再要求实例 —— 否则打错命令会报"缺少实例"，误导排查方向
    KNOWN = ("api", "list", "logs", "ruleset", "ping", "top", "total", "live", "report",
             "get", "push", "ipblock", "backup", "delete", "diff")
    if argv[0] not in KNOWN:
        sys.stderr.write("[错误] 未知子命令: %s\n" % argv[0])
        sys.stderr.write("可用: hosts, %s\n" % ", ".join(KNOWN))
        sys.exit(2)

    _select(name) if name else _use_env()

    cmd, rest = argv[0], argv[1:]
    if cmd == "api":
        cmd_api(rest)
    elif cmd == "list":
        cmd_list(rest[0] if rest else "")
    elif cmd == "logs":
        cmd_logs(rest)
    elif cmd == "get":
        cmd_get(rest)
    elif cmd == "push":
        cmd_push(rest)
    elif cmd == "ipblock":
        cmd_ipblock(rest)
    elif cmd == "backup":
        cmd_backup(rest)
    elif cmd == "delete":
        cmd_delete(rest)
    elif cmd == "diff":
        cmd_diff(rest)
    elif cmd == "ruleset":
        cmd_ruleset(rest[0] if rest else "")
    elif cmd == "ping":
        status, text = _req("GET", "/setting/license")
        print("[HTTP %s] %s" % (status, _pretty(text)))
        sys.exit(0 if status < 400 else 1)
    elif cmd == "top":
        print(_pretty(_req("GET", "/logs/top")[1]))
    elif cmd == "total":
        print(_pretty(_req("GET", "/logs/total")[1]))
    elif cmd == "live":
        print(_pretty(_req("GET", "/logs/live")[1]))
    elif cmd == "report":
        print(_pretty(_req("POST", "/logs/report", {})[1]))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
