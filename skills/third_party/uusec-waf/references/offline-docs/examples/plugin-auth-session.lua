---
--- 作者: MCQSJ(https://github.com/MCQSJ)
--- 更新日期: 2025/07/24
--- 身份验证插件，用于保护指定域名的请求，需要输入正确的用户名和密码才能访问。
--- 更新内容：更新为cookie鉴权，避免ip变动导致频繁登录；支持自动续期，避免频繁登录；白名单路径更新为路径匹配，包含该路径均放行。
---
local ngx = ngx
local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local ngx_print = ngx.print
local ngx_exit = ngx.exit
local ngx_time = ngx.time
local ngx_kv = ngx.shared
local resty_random = require "resty.random"
local resty_string = require "resty.string"

local _M = {
    version = 2.1,
    name = "auth-plugin"
}

-- 站点认证配置 {域名, 用户名, 密码}
local site_auth_config = {
    {"abc.com", "admin", "passwd"},
    {"123.cn", "admin", "passwd"}
}

-- API白名单(路径前缀,包含此路径的请求均会直接放行)
local api_whitelist = {
    "abc.com/v1/",
    "123.cn/i/"
}

-- 全局设置
local session_duration = 7200       -- 会话有效期(秒)
local cookie_name = "WAF_AUTH_SESSION"
local session_prefix = "sess:"
local max_login_attempts = 5        -- 最大登录失败次数
local renew_threshold = 0.3         -- 续期阈值（剩余时间小于30%时续期）

-- 生成安全的随机会话ID
local function generate_session_id()
    local random_bytes = resty_random.bytes(32)
    if not random_bytes then
        ngx_log(ngx_ERR, "无法生成随机会话ID")
        return nil
    end
    return resty_string.to_hex(random_bytes)
end

-- 处理特殊字符(防XSS)
local function escape_html(str)
    if type(str) ~= "string" then return "" end
    local replacements = {
        ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;",
        ['"'] = "&quot;", ["'"] = "&#39;"
    }
    return (str:gsub("[&<>'\"]", replacements))
end

-- 登录页面HTML模板
local function get_login_page(req_uri, error_message, site_name)
    local escaped_error_message = escape_html(tostring(error_message or ""))
    local form_action = escape_html(tostring(req_uri or "/"))
    local site_title = site_name and escape_html(site_name) or "安全验证"
    
    return [[
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>]] .. site_title .. [[</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#3B82F6',
                        danger: '#EF4444',
                        neutral: '#1F2937',
                        'neutral-light': '#6B7280',
                        'neutral-bg': '#F9FAFB'
                    },
                    fontFamily: {
                        sans: ['Inter', 'system-ui', 'sans-serif'],
                    },
                }
            }
        }
    </script>
    <style type="tailwindcss">
        @layer utilities {
            .content-auto {
                content-visibility: auto;
            }
        }
    </style>
</head>
<body class="font-sans bg-gradient-to-br from-neutral-bg to-blue-50 min-h-screen flex flex-col items-center justify-center p-4">
    <div class="w-full max-w-md">
        <div class="bg-white rounded-2xl shadow-lg overflow-hidden transition-all duration-300 hover:shadow-xl">
            <div class="bg-primary text-white py-3 px-6 flex items-center">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="mr-2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <span class="font-medium">]] .. site_title .. [[</span>
            </div>
            <div class="p-8">
                <div class="text-center mb-8">
                    <div class="inline-flex items-center justify-center w-24 h-24 rounded-full bg-primary/10 text-primary mb-6">
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </div>
                    <h1 class="text-2xl md:text-3xl font-bold text-neutral mb-4">身份验证</h1>
                    <p class="text-neutral-light">您的访问受保护，请输入正确的账号密码</p>
                </div>
                ]] .. (escaped_error_message ~= "" and '<div class="mb-4 p-3 bg-danger/10 text-danger rounded-lg flex items-center"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="mr-2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="9" x2="12" y2="13" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="12" y1="17" x2="12.01" y2="17" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>' .. escaped_error_message .. '</span></div>' or "") .. [[
                <form method="POST" action="]] .. form_action .. [[">
                    <div class="mb-4">
                        <label for="username" class="block text-neutral font-medium mb-2">用户名</label>
                        <input type="text" id="username" name="username" placeholder="输入用户名" required class="w-full px-4 py-3 border border-neutral-light rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-300">
                    </div>
                    <div class="mb-6">
                        <label for="password" class="block text-neutral font-medium mb-2">密码</label>
                        <input type="password" id="password" name="password" placeholder="输入密码" required class="w-full px-4 py-3 border border-neutral-light rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-300">
                    </div>
                    <button type="submit" class="w-full px-6 py-4 bg-primary text-white rounded-lg hover:bg-primary/90 transition-all duration-300 shadow-md shadow-primary/20 flex items-center justify-center font-medium">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="mr-2">
                            <path d="M12 15l3-3m0 0l-3-3m3 3H8m13 0a9 9 0 11-18 0 9 9 0 0118 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                        登录
                    </button>
                </form>
                <div class="mt-8 text-center">
                    <p class="text-neutral-light text-sm">如果您遇到问题，请联系管理员</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
    ]]
end

-- 解析Cookie头
local function parse_cookies(cookie_header)
    if not cookie_header then return {} end
    
    local cookies = {}
    for cookie in cookie_header:gmatch("[^;]+") do
        local key, value = cookie:match("^%s*([^=%s]+)%s*=%s*([^;]*)")
        if key and value then
            cookies[key] = value
        end
    end
    return cookies
end

-- 获取当前站点的认证配置
local function get_site_auth(host)
    for _, config in ipairs(site_auth_config) do
        if host:lower() == config[1]:lower() then
            return {
                username = config[2],
                password = config[3],
                site_name = config[1]
            }
        end
    end
    return nil
end

-- 校验登录凭证
local function validate_login(waf, auth_config)
    if not waf.form or not waf.form["FORM"] then
        return false
    end
    
    local form = waf.form["FORM"]
    if form then
        local username = form["username"]
        local password = form["password"]
        return username == auth_config.username and password == auth_config.password
    end
    return false
end

-- 检查API白名单
local function check_whitelist(host, uri)
    if type(host) ~= "string" or type(uri) ~= "string" then
        return false
    end
    
    host = host:lower()
    uri = uri:lower()
    
    for _, rule in ipairs(api_whitelist) do
        local rule_host, path_prefix = rule:match("^([^/]+)/(.*)$")
        if not rule_host then
            rule_host = rule
            path_prefix = ""
        end
        
        if host == rule_host:lower() then
            if path_prefix == "" or uri:find("/"..path_prefix, 1, true) == 1 then
                return true
            end
        end
    end
    return false
end

-- 创建安全Cookie
local function create_secure_cookie(session_id, scheme)
    return string.format("%s=%s; Path=/; HttpOnly; SameSite=Lax%s",
        cookie_name,
        session_id,
        scheme == "https" and "; Secure" or ""
    )
end

-- 增强型获取Cookie
local function get_auth_cookie(waf)
    if waf.cookies and waf.cookies[cookie_name] then
        return waf.cookies[cookie_name]
    end
    
    if waf.reqHeaders then
        local cookie_header = waf.reqHeaders["Cookie"] or waf.reqHeaders["cookie"]
        if cookie_header then
            local cookies = parse_cookies(cookie_header)
            return cookies[cookie_name]
        end
    end
    
    local ngx_cookie = ngx.var.http_cookie
    if ngx_cookie then
        local cookies = parse_cookies(ngx_cookie)
        return cookies[cookie_name]
    end
    
    return nil
end

-- 智能会话续期机制
local function renew_session_if_needed(session_key, expire_time)
    local current_time = ngx_time()
    local remaining_time = expire_time - current_time
    
    if remaining_time < session_duration * renew_threshold then
        local new_expire_time = current_time + session_duration
        ngx_kv.db:set(session_key, new_expire_time, session_duration)
        return new_expire_time
    end
    
    return expire_time
end

-- 请求阶段后过滤器
function _M.req_post_filter(waf)
    local host = tostring(waf.host or "")
    local req_uri = tostring(waf.uri or "")
    local method = tostring(waf.method or "")

    local auth_config = get_site_auth(host)
    if not auth_config then
        return
    end

    if check_whitelist(host, req_uri) then
        return
    end

    local session_cookie = get_auth_cookie(waf)
    
    if session_cookie then
        local session_key = session_prefix .. tostring(session_cookie)
        local session_data = ngx_kv.db:get(session_key)
        
        if session_data then
            local expire_time
            local session_valid = false
            
            if type(session_data) == "number" then
                expire_time = session_data
                session_valid = expire_time > ngx_time()
            elseif session_data == true then
                expire_time = ngx_time() + session_duration
                ngx_kv.db:set(session_key, expire_time, session_duration)
                session_valid = true
            end
            
            if session_valid then
                renew_session_if_needed(session_key, expire_time)
                return
            else
                ngx_kv.db:delete(session_key)
            end
        end
    end

    local login_attempts_key = "login_attempts:" .. tostring(waf.ip) .. ":" .. host
    local login_attempts = ngx_kv.ipCache:get(login_attempts_key) or 0
    
    if login_attempts >= max_login_attempts then
        ngx_kv.ipBlock:incr(waf.ip, 1, 0, 600)
        waf.msg = "IP因登录失败次数过多已被拦截"
        waf.rule_id = 10001
        waf.deny = true
        return ngx_exit(403)
    end

    local show_error = false
    if method == "POST" then
        if validate_login(waf, auth_config) then
            local new_session_id = generate_session_id()
            if new_session_id then
                local new_session_key = session_prefix .. new_session_id
                local expire_time = ngx_time() + session_duration
                ngx_kv.db:set(new_session_key, expire_time, session_duration)
                ngx_kv.ipCache:delete(login_attempts_key)
                
                ngx.header["Set-Cookie"] = create_secure_cookie(new_session_id, waf.scheme)
                return waf.redirect(req_uri)
            else
                show_error = true
            end
        else
            login_attempts = login_attempts + 1
            ngx_kv.ipCache:set(login_attempts_key, login_attempts, 3600)
            show_error = true
        end
    end

    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    if show_error then
        ngx_print(get_login_page(req_uri, "用户名或密码错误，请重试。", auth_config.site_name))
    else
        ngx_print(get_login_page(req_uri, nil, auth_config.site_name))
    end
    return ngx_exit(ngx.HTTP_OK)
end

return _M