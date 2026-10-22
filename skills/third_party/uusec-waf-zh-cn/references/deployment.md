# 部署与数据库

> 官方 compose 原文：`offline-docs/examples/docker-compose.yml`；小内存 MySQL 调优示例：`offline-docs/examples/low-memory-my.cnf`。
> 安装步骤与常见问题见 `operations.md`；官方原文见 `offline-docs/install.md`、`offline-docs/faq.md`。

---

## 一、部署形态

南墙本体是**单容器**（内含 nginx + LuaJIT + Go 控制面 + 内嵌前端）。**数据库是独立组件**，官方 compose 自带一个 MySQL 容器。

| 形态 | 组成 |
|:---|:---|
| **自包含**（官方 compose） | `uuwaf` 容器 + `wafdb`（MySQL）容器，专用 `wafnet` 网桥 |
| **外部数据库** | `uuwaf` 容器 + 其他 MySQL 实例，通过 DSN 连接 |

判断当前形态：

```bash
docker ps --format '{{.Names}}\t{{.Image}}' | grep -iE 'uuwaf|wafdb'
# 有 wafdb → 自包含；只有 uuwaf → 外部数据库
docker inspect uuwaf --format '{{range .Config.Env}}{{println .}}{{end}}' | grep UUWAF_DB_DSN
```

### 中文版 / 英文版：两条通道、两个镜像

官方按语言分成**两条安装通道**，镜像与 compose 是两套（两个仓库的镜像 config digest 不同 → **不是互为镜像源**，内容和语言都不一样）：

| | 英文（国际站） | 中文（国内站） |
|:---|:---|:---|
| 安装脚本 | `https://waf.uusec.com/installer.sh` | `https://waf.uusec.com/zh-cn/installer.sh` |
| 更新用 compose | `https://waf.uusec.com/docker-compose2.yml` | `https://waf.uusec.com/zh-cn/docker-compose2.yml` |
| WAF 镜像 | `uusec/waf:latest`（Docker Hub） | `swr.cn-south-1.myhuaweicloud.com/uusec/waf:latest`（华为 SWR，国内加速） |
| 数据库镜像 | `mysql:5.7` | `swr.cn-south-1.myhuaweicloud.com/uusec/mysql:5.7.44` |
| 语言变量 | 不设（英文） | `UUWAF_LANGUAGE=zh` |

**语言在部署时定，不在面板里定。** 内置规则、插件等内容随镜像的语言种子（`locales/zh.sql` / `locales/en.sql`）入库，`UUWAF_LANGUAGE` 指明用哪一套。**面板里的语言设置只改界面**（`PUT /setting` 的 `language`，见 `management-api.md` 的 `GET /setting/lang`）——已入库的规则/插件内容不会跟着变。所以**要另一种语言的内容，只能按对应通道重新部署**（换镜像 + 该通道的 compose），靠设置切换做不到。

⚠️ **`manager.sh` 的「更新」从脚本自身所属通道拉 compose 并覆盖本地的 `docker-compose.yml`**（中文通道的脚本拉 `zh-cn/docker-compose2.yml`，英文通道拉根路径版）。跨通道混用（例如中文脚本 + 英文 compose）会在下次更新时被拉回该通道的镜像与语言 —— 换语言要连 `manager.sh`、compose、镜像一起换。

---

## 二、官方 compose

官方文件在仓库 `docker/docker-compose.yml`（安装脚本从 `https://uuwaf.uusec.com/docker-compose.yml` 拉取），本地副本见 `offline-docs/examples/docker-compose.yml`。原文：

```yaml
networks:
  wafnet:
    name: wafnet
    driver: bridge
    ipam:
      driver: default
      config:
      - gateway: 172.31.254.1
        subnet: 172.31.254.0/24
    driver_opts:
      com.docker.network.bridge.name: wafnet

services:
  uuwaf:
    image: uusec/waf:latest
    #ulimits:
    #  nproc: 65535
    #  nofile:
    #    soft: 102400
    #    hard: 102400
    container_name: uuwaf
    restart: always
    network_mode: host
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - ./waf_config:/uuwaf/web/conf
      - ./waf_acme:/uuwaf/acme
      - ./waf_logs:/uuwaf/logs
    environment:
      - UUWAF_DB_DSN=root:${MYSQL_PASSWORD}@tcp(127.0.0.1:6612)/uuwaf?charset=utf8mb4&parseTime=true&loc=Local
      #- UUWAF_LANGUAGE=zh
      #- UUWAF_RESOLVER=resolver 127.0.0.11 valid=30s ipv6=off;
    depends_on:
      wafdb:
        condition: service_healthy

  wafdb:
    image: mysql:5.7
    container_name: wafdb
    restart: always
    networks:
      wafnet:
        ipv4_address: 172.31.254.3
    ports:
      - "6612:3306"
    volumes:
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
      - ./waf_data:/var/lib/mysql
      #- ./low-memory-my.cnf:/etc/mysql/my.cnf
    environment:
      - MYSQL_ROOT_PASSWORD=${MYSQL_PASSWORD}
    command: ["--max_connections=512"]
    healthcheck:
      test: ["CMD", "mysqladmin", "-uroot", "-p${MYSQL_PASSWORD}", "ping", "-h", "127.0.0.1", "--silent"]
      start_period: 3s
      interval: 5s
      timeout: 3s
      retries: 10
```

要点：

| 项 | 说明 |
|:---|:---|
| `uuwaf` 用 **`network_mode: host`** | 不加入 `wafnet` → DSN 走**宿主端口**（`6612` 是 `wafdb:3306` 的映射），容器名 `wafdb` 不可解析 |
| `wafdb` 映射 `6612:3306` | 宿主 6612 被占用则起不来；DSN 端口填 **6612** |
| 数据库镜像 **`mysql:5.7`** | 官方固定版本 |
| `command: ["--max_connections=512"]` | 官方显式设置的连接数 |
| `depends_on: condition: service_healthy` | 等 healthcheck 通过再启动 uuwaf |
| `--silent` healthcheck | `mysqladmin ping` 用真实凭据；改密码后须同步 compose，否则持续失败 |
| 可选（compose 中已注释） | `ulimits`（nproc/nofile）、`UUWAF_LANGUAGE`、`UUWAF_RESOLVER`、`low-memory-my.cnf` |
| 安装脚本生成的 `.env` | 只含一行 `MYSQL_PASSWORD=<32 位随机串>` |

管理脚本 `/opt/waf/manager.sh`：启动 / 停止 / 重启 / 更新 / 修复 / 卸载。启动前会检查 **80、443、777、4443、4447** 是否被占用。卸载会清理 `uuwaf`、`wafdb` 容器 + `wafnet` 网络 + `*_waf_*` 卷 + `uuwaf` 镜像。

---

## 三、数据库的使用

### 连接配置：环境变量 `UUWAF_DB_DSN`

数据库连接信息由 `UUWAF_DB_DSN` 决定（v6.7.0 起提供，用于自定义数据库连接）。格式为 Go MySQL driver 的 DSN：

```
<user>:<password>@tcp(<host>:<port>)/<dbname>?charset=utf8mb4&parseTime=true&loc=Local
```

| 部件 | 要求 |
|:---|:---|
| `charset` | **`utf8mb4`** —— 否则中文/emoji 落库损坏（配合 `log.utf8` 使用） |
| `parseTime` | **`true`** —— 否则时间列扫描失败 |
| `loc` | 时区，官方用 `Local`；配错会导致日志时间偏移 |
| `<dbname>` / `<user>` | 库名与账号，由使用者指定 |

> ⚠️ DSN 含数据库口令，属**敏感数据**（见 `pitfalls.md` §二）。
> ⚠️ 改 DSN 后需 `docker compose down && up -d` —— `restart` **不会**重新加载环境变量。

其他 DB 相关环境变量（compose 中默认注释）：

| 变量 | 用途 |
|:---|:---|
| `UUWAF_LANGUAGE` | 界面语言（如 `zh`） |
| `UUWAF_RESOLVER` | 自定义 DNS resolver |

### 库结构

南墙**自动创建数据库结构**（v6.8.0 起支持）→ 不需要手工建表，只需提供可用库与账号。
日志是否落库由 `config.json` 的 **`log_db`** 控制（使用 kafka 日志时可关闭）。

> 注意：**IP 封禁名单不在数据库**，在 Lua 共享内存字典 `ipBlock`；容器内**没有 Redis**（见 `pitfalls.md` §八）。

### 数据库版本

| 数据库 | 状态 |
|:---|:---|
| **MySQL 5.7** | 官方 compose 固定版本 |
| MySQL 8.x | 官方文档未声明支持；CHANGELOG 有"数据库升级到 8.x"条目 |
| MariaDB | 官方无声明；协议兼容 |
| PostgreSQL / SQLite | ❌ 不支持（DSN 是 MySQL 方言） |

使用 MySQL 8.x 时需留意：

1. **认证插件**：`mysql_native_password` 在 8.0 标记废弃、8.4 默认不再启用/已移除；8.x 默认 `caching_sha2_password`，需较新的 Go driver 支持。若报"认证失败 / plugin cannot be loaded"，先查此处。
2. **`sql_mode`**：8.x 默认 `ONLY_FULL_GROUP_BY` / `STRICT_TRANS_TABLES`，5.7 宽松模式下能跑的 SQL 在 8.x 可能报错。
3. **`lower_case_table_names`**：只在初始化时有效，运行期不可改；跨版本迁移时取值不同会找不到表。

---

## 四、启动顺序

官方 compose 用 `depends_on: condition: service_healthy` + `wafdb` 的 `healthcheck`，保证**数据库先就绪、再启动南墙**。CHANGELOG 有两条相关历史修复（"修复系统重启后南墙先于数据库启动，导致南墙连接不上数据库的问题"）。

> `depends_on` 只作用于**同一 compose 项目内**的服务。
> 南墙进程不会因"连不上数据库"退出，故 `restart: always` 不会触发重启。

---

## 五、常见现象对照

| 现象 | 常见原因 |
|:---|:---|
| 面板能开但功能报错 / 查不到日志 | DSN 的主机、端口、库名有误；注意自包含形态下端口是**宿主映射端口**（6612），且 host 网络下**容器名不可解析** |
| 改 DSN 后不生效 | 用了 `restart` 而非 `down && up`（环境变量不重载） |
| 中文/emoji 落库损坏 | DSN `charset` 不是 `utf8mb4` |
| 日志时间偏移 | DSN `loc` 或容器 `/etc/localtime` 挂载不正确 |
| 端口起不来 | 80/443/777/4443/4447 被占用 |
| `wafdb` 起不来 | 宿主 `6612` 被占用 |
| 账号/权限报错（MySQL 8.x） | 认证插件差异，见 §三 |
| 面板极慢 | 数据库 `innodb_buffer_pool_size` 过小（如挂了 `low-memory-my.cnf`） |

> 升级（含 `manager.sh` 覆盖 `docker-compose.yml`、备份、版本分水岭）见 `operations.md` §四。
