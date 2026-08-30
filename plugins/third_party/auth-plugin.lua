---
--- 站点认证插件
--- 为指定站点添加登录验证页面
---
--- 作者: YourName
--- 更新日期: 2026/05/31
---
local ngx = ngx
local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local ngx_print = ngx.print
local ngx_exit = ngx.exit
local ngx_time = ngx.time
local ngx_kv = ngx.shared
local resty_random = require("resty.random")
local resty_string = require("resty.string")
local ipmatcher = require("resty.ipmatcher")

local _M = {
    version = 3.4,
    name = "site-auth-plugin",
    priority = 50
}

-- <--- 配置参数 --->

-- 站点认证配置：{域名, 用户名, 密码, cookie有效期(秒)}
-- cookie有效期设为0表示会话cookie（浏览器关闭即失效），设为正数表示持久化时长
local site_auth_config = {
    -- {"example.com", "admin", "change-this-password", 0},
    -- {"private.example.com", "admin", "change-this-password", 86400},
}

-- IP白名单（CIDR格式）：白名单内的IP无需认证即可访问
local ip_whitelist = {
    -- "192.168.1.0/24",
    -- "10.0.0.0/8",
}

-- API路径白名单：格式 "域名/路径前缀"，匹配的路径无需认证（如图片直链）
local api_whitelist = {
    -- "example.com/api/public/",
    -- "static.example.com/assets/",
}

-- 请求头放行白名单：匹配指定域名、请求头和值后无需认证
-- host 支持具体域名或 "*"；header 为请求头名称；value 为请求头值；case_sensitive 控制值是否区分大小写
local header_allowlist = {
    -- { host = "example.com", header = "X-Auth-Token", value = "change-me", case_sensitive = true },
    -- { host = "*", header = "X-Internal-Bypass", value = "change-me", case_sensitive = true },
}

-- 全局认证设置
local default_session_duration = 7200   -- 会话cookie模式下的默认有效期，单位秒（默认2小时）
local cookie_name = "WAF_AUTH_SESSION"  -- 认证会话Cookie名称
local csrf_cookie_name = "WAF_AUTH_CSRF" -- 历史CSRF Cookie名称，仅用于清理旧Cookie
local session_prefix = "sess:"          -- 会话存储键前缀
local max_login_attempts = 5           -- 最大登录尝试次数（超过后封禁IP）
local login_attempt_window = 3600      -- 登录失败次数统计窗口，单位秒（默认1小时）
local login_ban_duration = 600         -- 登录失败封禁时长，单位秒（默认10分钟）
local renew_threshold = 0.3            -- 会话续期阈值（剩余有效期比例，0.3即剩余30%时续期）

-- <--- 初始化 --->

local ipm, ipm_err
do
    if #ip_whitelist > 0 then
        ipm, ipm_err = ipmatcher.new(ip_whitelist)
        if not ipm then
            ngx_log(ngx_ERR, "auth-plugin: 初始化IP白名单失败: ", ipm_err)
        end
    end
end

-- <--- 工具函数 --->

local function generate_random_token(length)
    local random_bytes = resty_random.bytes(length)
    if not random_bytes then
        ngx_log(ngx_ERR, "auth-plugin: 无法生成随机token")
        return nil
    end
    return resty_string.to_hex(random_bytes)
end

local function escape_html(str)
    if type(str) ~= "string" then return "" end
    local replacements = {
        ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;",
        ['"'] = "&quot;", ["'"] = "&#39;"
    }
    return (str:gsub("[&<>'\"]", replacements))
end

local function format_cookie_expires(max_age)
    if max_age <= 0 then return "" end
    local expires_time = ngx_time() + max_age
    return os.date("!%a, %d %b %Y %H:%M:%S GMT", expires_time)
end

local function create_cookie_header(name, value, max_age, secure)
    local parts = {
        string.format("%s=%s", name, value),
        "Path=/",
        "HttpOnly",
        "SameSite=Lax"
    }
    if secure then table.insert(parts, "Secure") end
    if max_age and max_age > 0 then
        table.insert(parts, string.format("Max-Age=%d", max_age))
        local expires = format_cookie_expires(max_age)
        if expires ~= "" then table.insert(parts, string.format("Expires=%s", expires)) end
    end
    return table.concat(parts, "; ")
end

local function clear_cookie_header(name, secure)
    local parts = {
        string.format("%s=", name),
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=0",
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    }
    if secure then table.insert(parts, "Secure") end
    return table.concat(parts, "; ")
end

local function get_login_page(req_uri, error_message, site_name)
    local escaped_error = escape_html(tostring(error_message or ""))
    local form_action = escape_html(tostring(req_uri or "/"))
    local site_title = site_name and escape_html(site_name) or "安全验证"
    return [[<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="theme-color" content="#f8fafc">
<title>]] .. site_title .. [[</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Helvetica Neue',system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;line-height:1.5;-webkit-font-smoothing:antialiased;position:relative;overflow:hidden}
.background{position:fixed;top:0;left:0;right:0;bottom:0;background:radial-gradient(ellipse 120% 100% at 10% 0%,rgba(167,139,250,0.28),transparent 45%),radial-gradient(ellipse 100% 120% at 90% 10%,rgba(56,189,248,0.22),transparent 45%),radial-gradient(ellipse 80% 100% at 50% 100%,rgba(251,146,60,0.18),transparent 40%),radial-gradient(ellipse 60% 80% at 80% 80%,rgba(244,114,182,0.15),transparent 40%),linear-gradient(170deg,#f8fafc 0%,#f1f5f9 100%);z-index:0}
.auth-container{width:100%;max-width:400px;position:relative;z-index:10}
.auth-card{background:rgba(255,255,255,0.78);backdrop-filter:blur(32px) saturate(180%);-webkit-backdrop-filter:blur(32px) saturate(180%);border-radius:20px;border:1px solid rgba(255,255,255,0.6);box-shadow:0 4px 6px rgba(0,0,0,0.02),0 12px 24px rgba(0,0,0,0.04),inset 0 1px 1px rgba(255,255,255,0.7);overflow:hidden}
.auth-header{padding:1.5rem 2rem;border-bottom:1px solid rgba(0,0,0,0.05);text-align:center}
.auth-title{font-size:1.25rem;font-weight:600;color:#1d1d1f;letter-spacing:-0.02em}
.auth-body{padding:2rem}
.auth-heading{font-size:0.9375rem;font-weight:500;color:#424245;text-align:center;margin-bottom:1.75rem}
.error-message{background:rgba(255,59,48,0.1);border-radius:12px;padding:0.75rem 1rem;margin-bottom:1.5rem;text-align:center;font-size:0.875rem;color:#ff3b30;font-weight:500}
.form-group{margin-bottom:1rem}
.form-label{display:block;font-size:0.8125rem;font-weight:600;color:#6e6e73;margin-bottom:0.5rem;letter-spacing:0.01em}
.form-input{width:100%;height:44px;padding:0 0.875rem;background:rgba(255,255,255,0.9);border:1px solid rgba(0,0,0,0.08);border-radius:12px;font-size:1rem;color:#1d1d1f;font-family:inherit;transition:background-color 0.2s,border-color 0.2s,box-shadow 0.2s;-webkit-appearance:none;appearance:none}
.form-input::placeholder{color:#86868b}
.form-input:hover{background:rgba(255,255,255,0.98);border-color:rgba(0,0,0,0.12)}
.form-input:focus{outline:none;background:#fff;border-color:rgba(0,122,255,0.5);box-shadow:0 0 0 4px rgba(0,122,255,0.15)}
.form-submit{width:100%;height:44px;margin-top:1.5rem;background:linear-gradient(180deg,#007aff,#0066d6);border:none;border-radius:12px;font-size:1rem;font-weight:600;color:#fff;cursor:pointer;font-family:inherit;letter-spacing:-0.01em;transition:transform 0.1s,box-shadow 0.2s;box-shadow:0 1px 3px rgba(0,0,0,0.12)}
.form-submit:hover{box-shadow:0 4px 12px rgba(0,122,255,0.3)}
.form-submit:active{transform:scale(0.98)}
.form-footer{margin-top:1.75rem;text-align:center}
.form-footer-text{font-size:0.8125rem;color:#86868b;letter-spacing:0.01em}
@media(max-width:480px){body{padding:1rem}.auth-body,.auth-header{padding:1.5rem}.form-input,.form-submit{height:48px;font-size:16px}.auth-card{border-radius:16px}}
@media(prefers-reduced-motion:reduce){.form-submit{transition:none}}
</style>
</head>
<body>
<div class="background"></div>
<div class="auth-container">
<div class="auth-card">
<div class="auth-header"><div class="auth-title">]] .. site_title .. [[</div></div>
<div class="auth-body">
<div class="auth-heading">请输入账号密码继续访问</div>
]] .. (escaped_error ~= "" and '<div class="error-message">' .. escaped_error .. '</div>' or "") .. [[
<form method="POST" action="]] .. form_action .. [[" autocomplete="off">
<div class="form-group"><label class="form-label" for="username">用户名</label><input type="text" id="username" name="username" class="form-input" placeholder="请输入用户名" required autocapitalize="none" autocorrect="off"></div>
<div class="form-group"><label class="form-label" for="password">密码</label><input type="password" id="password" name="password" class="form-input" placeholder="请输入密码" required></div>
<button type="submit" class="form-submit">登录</button>
</form>
<div class="form-footer"><p class="form-footer-text">访问受保护，请完成身份验证</p></div>
</div>
</div>
</div>
</body>
</html>]]
end

local function parse_cookies(cookie_header)
    if not cookie_header then return {} end
    local cookies = {}
    for cookie in cookie_header:gmatch("[^;]+") do
        local key, value = cookie:match("^%s*([^=%s]+)%s*=%s*([^;]*)")
        if key and value then cookies[key] = value end
    end
    return cookies
end

local function get_site_auth(host)
    for _, config in ipairs(site_auth_config) do
        if host:lower() == config[1]:lower() then
            return { username = config[2], password = config[3], site_name = config[1], cookie_duration = config[4] or 0 }
        end
    end
    return nil
end

local function validate_login(waf, auth_config)
    if not waf.form or not waf.form["FORM"] then return false end
    local form = waf.form["FORM"]
    return form["username"] == auth_config.username and form["password"] == auth_config.password
end

local function check_whitelist(host, uri)
    if type(host) ~= "string" or type(uri) ~= "string" then return false end
    host = host:lower()
    uri = uri:lower()
    for _, rule in ipairs(api_whitelist) do
        local rule_host, path_prefix = rule:match("^([^/]+)/(.*)$")
        if not rule_host then rule_host = rule; path_prefix = "" end
        if host == rule_host:lower() and (path_prefix == "" or uri:find("/"..path_prefix, 1, true) == 1) then return true end
    end
    return false
end

local function get_header_value(waf, header_name)
    if not waf or not waf.reqHeaders or type(header_name) ~= "string" then return nil end
    local direct = waf.reqHeaders[header_name]
    if direct then return direct end
    local lower_name = header_name:lower()
    for k, v in pairs(waf.reqHeaders) do
        if type(k) == "string" and k:lower() == lower_name then
            return v
        end
    end
    return nil
end

local function header_value_match(actual, expected, case_sensitive)
    if actual == nil or expected == nil then return false end
    if type(actual) == "table" then actual = actual[1] end
    actual = tostring(actual)
    expected = tostring(expected)
    if case_sensitive == false then
        return actual:lower() == expected:lower()
    end
    return actual == expected
end

local function check_header_allowlist(waf, host)
    if not waf or type(host) ~= "string" then return false end
    local lower_host = host:lower()
    for _, rule in ipairs(header_allowlist) do
        local rule_host = tostring(rule.host or "*"):lower()
        if rule.enabled ~= false and (rule_host == "*" or rule_host == lower_host) then
            local actual = get_header_value(waf, rule.header)
            if header_value_match(actual, rule.value, rule.case_sensitive) then
                return true
            end
        end
    end
    return false
end

local function get_cookie_value(waf, name)
    if waf.cookies and waf.cookies[name] then return waf.cookies[name] end
    if waf.reqHeaders then
        local cookie_header = waf.reqHeaders["Cookie"] or waf.reqHeaders["cookie"]
        if cookie_header then return parse_cookies(cookie_header)[name] end
    end
    local ngx_cookie = ngx.var.http_cookie
    if ngx_cookie then return parse_cookies(ngx_cookie)[name] end
    return nil
end

local function renew_session_if_needed(session_key, expire_time, session_duration)
    local remaining = expire_time - ngx_time()
    if remaining < session_duration * renew_threshold then
        local new_expire = ngx_time() + session_duration
        local ok, err = ngx_kv.db:set(session_key, new_expire, session_duration)
        if not ok then
            ngx_log(ngx_ERR, "auth-plugin: 续期会话失败: ", err or "unknown")
            return expire_time, false
        end
        return new_expire, true
    end
    return expire_time, false
end

local function append_set_cookie(cookie_value)
    if not cookie_value then return end
    local existing = ngx.header["Set-Cookie"]
    if not existing then
        ngx.header["Set-Cookie"] = cookie_value
        return
    end
    if type(existing) == "table" then
        table.insert(existing, cookie_value)
        ngx.header["Set-Cookie"] = existing
        return
    end
    ngx.header["Set-Cookie"] = { existing, cookie_value }
end

local function block_login_banned_ip(waf)
    waf.msg = "IP因登录失败次数过多已被拦截"
    waf.rule_id = 10001
    waf.deny = true
    ngx_kv.ipBlock:incr(waf.ip, 1, 0)
    ngx_exit(403)
    return true, true
end

-- <--- 主逻辑 --->

function _M.resp_header_post_filter(waf)
    local renew_cookie = ngx.ctx.auth_plugin_renew_cookie
    if not renew_cookie then
        return
    end

    append_set_cookie(create_cookie_header(
        renew_cookie.name,
        renew_cookie.value,
        renew_cookie.max_age,
        renew_cookie.secure
    ))
end

function _M.req_post_filter(waf)
    if not waf then return end

    local host = tostring(waf.host or "")
    local req_uri = tostring(waf.uri or "")
    local method = tostring(waf.method or "")
    local is_https = (waf.scheme == "https")
    local auth_config = get_site_auth(host)
    if not auth_config then return end
    if not waf.ip or waf.ip == "" then return end

    local session_duration = auth_config.cookie_duration > 0 and auth_config.cookie_duration or default_session_duration
    local is_session_cookie = (auth_config.cookie_duration == 0)

    if ipm and ipm:match(waf.ip) then return end
    if check_whitelist(host, req_uri) then return end
    if check_header_allowlist(waf, host) then return end

    -- 检查已有会话
    local session_cookie = get_cookie_value(waf, cookie_name)
    if session_cookie then
        local session_key = session_prefix .. session_cookie
        local session_data = ngx_kv.db:get(session_key)
        if session_data then
            local expire_time, valid = nil, false
            if type(session_data) == "number" then
                expire_time = session_data
                valid = expire_time > ngx_time()
            elseif session_data == true then
                expire_time = ngx_time() + session_duration
                ngx_kv.db:set(session_key, expire_time, session_duration)
                valid = true
            end
            if valid then
                local _, renewed = renew_session_if_needed(session_key, expire_time, session_duration)
                if renewed and not is_session_cookie then
                    ngx.ctx.auth_plugin_renew_cookie = {
                        name = cookie_name,
                        value = session_cookie,
                        max_age = auth_config.cookie_duration,
                        secure = is_https
                    }
                end
                return
            else
                ngx_kv.db:delete(session_key)
            end
        end
    end

    -- 登录尝试次数检查
    local attempts_key = "login_attempts:" .. waf.ip .. ":" .. host
    local ban_key = "login_ban:" .. waf.ip .. ":" .. host

    if ngx_kv.ipCache:get(ban_key) then
        return waf.block(true)
    end

    local attempts = ngx_kv.ipCache:get(attempts_key) or 0

    -- POST 登录处理
    if method == "POST" then
        if validate_login(waf, auth_config) then
            local new_session_id = generate_random_token(32)
            if not new_session_id then
                ngx_log(ngx_ERR, "auth-plugin: 无法生成会话ID")
                ngx.header["Set-Cookie"] = clear_cookie_header(csrf_cookie_name, is_https)
                ngx.header["Content-Type"] = "text/html; charset=utf-8"
                ngx_print(get_login_page(req_uri, "系统繁忙，请稍后重试", auth_config.site_name))
                return ngx_exit(ngx.HTTP_OK)
            end

            local new_session_key = session_prefix .. new_session_id
            local expire_time = ngx_time() + session_duration
            local ok, err = ngx_kv.db:set(new_session_key, expire_time, session_duration)
            if not ok then
                ngx_log(ngx_ERR, "auth-plugin: 保存会话失败: ", err or "unknown")
                ngx.header["Set-Cookie"] = clear_cookie_header(csrf_cookie_name, is_https)
                ngx.header["Content-Type"] = "text/html; charset=utf-8"
                ngx_print(get_login_page(req_uri, "系统繁忙，请稍后重试", auth_config.site_name))
                return ngx_exit(ngx.HTTP_OK)
            end
            ngx_kv.ipCache:delete(attempts_key)
            ngx_kv.ipCache:delete(ban_key)
            local session_header = create_cookie_header(cookie_name, new_session_id, auth_config.cookie_duration, is_https)
            local csrf_clear = clear_cookie_header(csrf_cookie_name, is_https)
            ngx.header["Set-Cookie"] = { session_header, csrf_clear }
            return waf.redirect(req_uri)
        end

        attempts = attempts + 1
        if attempts >= max_login_attempts then
            ngx_kv.ipCache:set(ban_key, 1, login_ban_duration, 2)
            ngx_kv.ipCache:delete(attempts_key)
            return block_login_banned_ip(waf)
        end
        ngx_kv.ipCache:set(attempts_key, attempts, login_attempt_window)
    end

    -- 显示登录页面
    ngx.header["Set-Cookie"] = clear_cookie_header(csrf_cookie_name, is_https)
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    local error_msg = (method == "POST") and "用户名或密码错误" or nil
    ngx_print(get_login_page(req_uri, error_msg, auth_config.site_name))
    return ngx_exit(ngx.HTTP_OK)
end

return _M