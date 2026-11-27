# Deployment and Database

> Official compose source: `offline-docs/examples/docker-compose.yml`; small-memory MySQL tuning example: `offline-docs/examples/low-memory-my.cnf`.
> Installation steps and common issues: `operations.md`; official source: `offline-docs/install.md`, `offline-docs/faq.md`.

---

## 1. Deployment Topology

uuWAF itself is a **single container** (containing nginx + LuaJIT + the Go control plane + an embedded frontend). **The database is a separate component**; the official compose ships one MySQL container.

| Topology | Composition |
|:---|:---|
| **Self-contained** (official compose) | A `uuwaf` container + a `wafdb` (MySQL) container, on a dedicated `wafnet` bridge |
| **External database** | A `uuwaf` container + some other MySQL instance, connected via DSN |

Determining the current topology:

```bash
docker ps --format '{{.Names}}\t{{.Image}}' | grep -iE 'uuwaf|wafdb'
# wafdb present -> self-contained; only uuwaf -> external database
docker inspect uuwaf --format '{{range .Config.Env}}{{println .}}{{end}}' | grep UUWAF_DB_DSN
```

### Chinese edition / English edition: two channels, two images

Officially the product is split by language into **two installation channels**, with two separate sets of images and compose files (the images of the two repositories have different config digests -> **they are not mirrors of each other**; both the contents and the language differ):

| | English (international site) | Chinese (domestic site) |
|:---|:---|:---|
| Install script | `https://waf.uusec.com/installer.sh` | `https://waf.uusec.com/zh-cn/installer.sh` |
| Compose used for updates | `https://waf.uusec.com/docker-compose2.yml` | `https://waf.uusec.com/zh-cn/docker-compose2.yml` |
| WAF image | `uusec/waf:latest` (Docker Hub) | `swr.cn-south-1.myhuaweicloud.com/uusec/waf:latest` (Huawei SWR, accelerated within China) |
| Database image | `mysql:5.7` | `swr.cn-south-1.myhuaweicloud.com/uusec/mysql:5.7.44` |
| Language variable | not set (English) | `UUWAF_LANGUAGE=zh` |

**The language is decided at deployment time, not in the panel.** Built-in rules, plugins and the like are seeded into the database from the image's language seed (`locales/zh.sql` / `locales/en.sql`), and `UUWAF_LANGUAGE` says which set to use. **The language setting in the panel only changes the UI** (`language` in `PUT /setting`; see `GET /setting/lang` in `management-api.md`) -- the already-seeded rule/plugin contents do not follow it. So **to get content in the other language you can only redeploy through the corresponding channel** (switch the image + that channel's compose); switching through settings cannot do it.

⚠️ **"Update" in `manager.sh` pulls the compose belonging to the script's own channel and overwrites the local `docker-compose.yml`** (the Chinese-channel script pulls `zh-cn/docker-compose2.yml`, the English-channel one pulls the root-path version). Mixing channels (for example a Chinese script + an English compose) means the next update pulls you back to that channel's image and language -- changing the language means changing `manager.sh`, the compose and the image together.

---

## 2. The Official Compose

The official file is `docker/docker-compose.yml` in the repository (the install script pulls it from `https://uuwaf.uusec.com/docker-compose.yml`); a local copy is in `offline-docs/examples/docker-compose.yml`. Original text:

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

Key points:

| Item | Description |
|:---|:---|
| `uuwaf` uses **`network_mode: host`** | It does not join `wafnet` -> the DSN goes over the **host port** (`6612` is the mapping of `wafdb:3306`), and the container name `wafdb` does not resolve |
| `wafdb` maps `6612:3306` | If host 6612 is already taken it will not start; put **6612** in the DSN port |
| Database image **`mysql:5.7`** | The version pinned by the official setup |
| `command: ["--max_connections=512"]` | The connection count explicitly set by the official setup |
| `depends_on: condition: service_healthy` | Waits for the healthcheck to pass before starting uuwaf |
| `--silent` healthcheck | `mysqladmin ping` uses the real credentials; after changing the password the compose must be updated too, otherwise it keeps failing |
| Optional (already commented out in the compose) | `ulimits` (nproc/nofile), `UUWAF_LANGUAGE`, `UUWAF_RESOLVER`, `low-memory-my.cnf` |
| The `.env` generated by the install script | Contains only one line, `MYSQL_PASSWORD=<32-character random string>` |

Management script `/opt/waf/manager.sh`: start / stop / restart / update / repair / uninstall. Before starting it checks whether **80, 443, 777, 4443, 4447** are occupied. Uninstalling cleans up the `uuwaf` and `wafdb` containers + the `wafnet` network + the `*_waf_*` volumes + the `uuwaf` image.

---

## 3. Using the Database

### Connection configuration: the `UUWAF_DB_DSN` environment variable

The database connection information is determined by `UUWAF_DB_DSN` (available since v6.7.0, for custom database connections). The format is the Go MySQL driver DSN:

```
<user>:<password>@tcp(<host>:<port>)/<dbname>?charset=utf8mb4&parseTime=true&loc=Local
```

| Part | Requirement |
|:---|:---|
| `charset` | **`utf8mb4`** -- otherwise Chinese/emoji are corrupted when stored (used together with `log.utf8`) |
| `parseTime` | **`true`** -- otherwise scanning time columns fails |
| `loc` | Time zone; the official setup uses `Local`; getting it wrong shifts log timestamps |
| `<dbname>` / `<user>` | Database name and account, chosen by the user |

> ⚠️ The DSN contains the database password, so it is **sensitive data** (see `pitfalls.md` §2).
> ⚠️ After changing the DSN you need `docker compose down && up -d` -- `restart` does **not** reload environment variables.

Other DB-related environment variables (commented out by default in the compose):

| Variable | Purpose |
|:---|:---|
| `UUWAF_LANGUAGE` | UI language (e.g. `zh`) |
| `UUWAF_RESOLVER` | Custom DNS resolver |

### Database structure

uuWAF **creates the database structure automatically** (supported since v6.8.0) -> no manual table creation is needed; just provide a usable database and account.
Whether logs are stored in the database is controlled by **`log_db`** in `config.json` (it can be turned off when using kafka logging).

> Note: **the IP ban list is not in the database** but in the Lua shared memory dict `ipBlock`; there is **no Redis** in the container (see `pitfalls.md` §8).

### Database versions

| Database | Status |
|:---|:---|
| **MySQL 5.7** | The version pinned by the official compose |
| MySQL 8.x | Not declared as supported in the official docs; the CHANGELOG has an entry "database upgraded to 8.x" |
| MariaDB | No official statement; protocol-compatible |
| PostgreSQL / SQLite | ❌ Not supported (the DSN is MySQL dialect) |

When using MySQL 8.x, keep in mind:

1. **Authentication plugin**: `mysql_native_password` is deprecated in 8.0 and no longer enabled / already removed by default in 8.4; 8.x defaults to `caching_sha2_password`, which needs a newer Go driver. If you see "authentication failed / plugin cannot be loaded", check here first.
2. **`sql_mode`**: 8.x defaults to `ONLY_FULL_GROUP_BY` / `STRICT_TRANS_TABLES`; SQL that runs under 5.7's lax mode may error on 8.x.
3. **`lower_case_table_names`**: only takes effect at initialization time and cannot be changed at runtime; migrating across versions with a different value means tables cannot be found.

---

## 4. Startup Order

The official compose uses `depends_on: condition: service_healthy` + the `healthcheck` on `wafdb` to guarantee that **the database is ready before uuWAF starts**. The CHANGELOG has two related historical fixes ("fixed the problem where uuWAF started before the database after a system reboot, so uuWAF could not connect to the database").

> `depends_on` only applies to services **within the same compose project**.
> The uuWAF process does not exit because it "cannot connect to the database", so `restart: always` does not trigger a restart.

---

## 5. Common Symptoms

| Symptom | Common cause |
|:---|:---|
| The panel opens but features error out / logs cannot be found | Wrong DSN host, port or database name; note that in the self-contained topology the port is the **host-mapped port** (6612), and under host networking **container names do not resolve** |
| Changing the DSN has no effect | You used `restart` instead of `down && up` (environment variables are not reloaded) |
| Chinese/emoji corrupted when stored | The DSN `charset` is not `utf8mb4` |
| Log timestamps shifted | Wrong DSN `loc`, or an incorrect `/etc/localtime` mount in the container |
| Ports will not come up | 80/443/777/4443/4447 are occupied |
| `wafdb` will not start | Host `6612` is occupied |
| Account/permission errors (MySQL 8.x) | Authentication plugin differences, see §3 |
| The panel is extremely slow | The database `innodb_buffer_pool_size` is too small (e.g. `low-memory-my.cnf` is mounted) |

> Upgrades (including `manager.sh` overwriting `docker-compose.yml`, backups, and version watersheds) are in `operations.md` §4.
