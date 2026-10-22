---
--- CC防护插件
--- 集成封禁黑名单、回源熔断、IP全局限速、路径限速与站点限速
---

local ngx = ngx
local ngx_exit = ngx.exit
local ngx_kv = ngx.shared

local _M = {
    version = 1.8,
    name = "cc-protection",
    priority = 100
}

-- <--- 配置参数 --->

-- CC 防护总开关；false 时整个插件不执行任何 CC 检测
local enableCCProtection = true

-- 回源熔断开关；全局统计所有准备回源请求总数，超限后临时阻断所有后续请求
local enableOriginCircuitBreaker = true

-- IP 全局限速开关；按 IP 统计所有站点的总请求频率，作为粗过滤
local enableGlobalRateLimit = true

-- 精准路径限速开关；对指定 Host + Path 单独限速
local enablePathRateLimit = true

-- 站点频率限制开关；按 Host 独立统计请求频率
local enableSiteRateLimit = true

-- 回源熔断配置；纯全局计数，不区分 IP、Host、Path，用于保护源站总容量
local originCircuitBreaker = {
    enabled = true,        -- 当前配置项开关
    threshold = 3000,      -- 全局时间窗口内允许的最大准备回源请求总数
    timeWindow = 10,       -- 统计时间窗口，单位为秒
    breakDuration = 30,    -- 全局熔断持续时间，单位为秒
    countStatic = true     -- 是否统计静态资源请求；true 表示所有准备回源请求都计入
}

-- IP 全局限速配置；跨站点按 IP 统计所有请求总数，未超限时继续执行后续精细策略
local globalRateLimit = {
    enabled = true,       -- 当前配置项开关
    threshold = 1000,     -- 时间窗口内允许的最大请求数
    timeWindow = 30,      -- 统计时间窗口，单位为秒
    banDuration = 3600,   -- 超限后的封禁时间，单位为秒
    countStatic = false   -- 是否统计静态资源请求；false 表示只统计动态请求
}

-- 站点默认频率限制配置；未单独配置的站点使用此配置
local siteDefault = {
    enabled = true,       -- 当前配置项开关
    threshold = 120,      -- 时间窗口内允许的最大请求数
    timeWindow = 60,      -- 统计时间窗口，单位为秒
    banDuration = 3600,   -- 超限后的封禁时间，单位为秒
    countStatic = false   -- 是否统计静态资源请求；false 表示只统计动态请求
}

-- 站点频率限制配置；key 为访问域名，未配置的域名使用 siteDefault
local siteConfigs = {
    -- ["example.com"] = {
    --     enabled = true,
    --     threshold = 800,
    --     timeWindow = 60,
    --     banDuration = 3600,
    --     countStatic = false
    -- },
    -- ["api.example.com"] = {
    --     enabled = true,
    --     threshold = 500,
    --     timeWindow = 60,
    --     banDuration = 3600,
    --     countStatic = false
    -- }
}

-- 精准路径限速配置；匹配指定 Host 和 Path 前缀后使用独立频率限制
local pathRules = {
    -- {
    --     enabled = true,
    --     host = "api.example.com",
    --     path = "/api/send",
    --     threshold = 60,
    --     timeWindow = 60,
    --     banDuration = 600
    -- }
}

-- <--- 工具函数 --->

local function isDynamic(waf)
    return waf.isQueryString or ((waf.reqContentLength or 0) > 0)
end

local function isBanned(banKey)
    local _, flags = ngx_kv.ipCache:get(banKey)
    return flags == 2
end

local function doDeny(waf, msg, ruleId)
    waf.msg = msg
    waf.rule_id = ruleId
    waf.deny = true
    ngx_exit(403)
    return true, true
end

local function checkRate(rateKey, banKey, limit)
    local count = ngx_kv.ipCache:get(rateKey)

    if not count then
        ngx_kv.ipCache:set(rateKey, 1, limit.timeWindow, 1)
        return false
    end

    local newCount = ngx_kv.ipCache:incr(rateKey, 1)

    if newCount and newCount > limit.threshold then
        ngx_kv.ipCache:set(banKey, 1, limit.banDuration, 2)
        return true
    end

    return false
end

local function checkOriginCircuitBreaker(waf)
    if not enableOriginCircuitBreaker or not originCircuitBreaker.enabled then
        return
    end

    local breakKey = "cc-break:origin"
    local rateKey = "cc-origin:rate"

    if isBanned(breakKey) then
        return waf.block(true)
    end

    if not originCircuitBreaker.countStatic and not isDynamic(waf) then
        return
    end

    local count = ngx_kv.ipCache:get(rateKey)

    if not count then
        ngx_kv.ipCache:set(rateKey, 1, originCircuitBreaker.timeWindow, 1)
        return
    end

    local newCount = ngx_kv.ipCache:incr(rateKey, 1)

    if newCount and newCount > originCircuitBreaker.threshold then
        ngx_kv.ipCache:set(breakKey, 1, originCircuitBreaker.breakDuration, 2)
        return doDeny(waf, "回源请求总量超限", 10014)
    end
end

-- <--- 主逻辑 --->

function _M.req_pre_filter(waf)
    if not enableCCProtection then
        return
    end

    if not waf or not waf.ip or waf.ip == "" then
        return
    end

    local ip = waf.ip
    local host = (waf.host or ""):lower()
    local uri = (waf.uri or ""):lower()

    if host == "" then
        return
    end

    local originResult = checkOriginCircuitBreaker(waf)
    if originResult then
        return originResult
    end

    if enableGlobalRateLimit and globalRateLimit.enabled then
        local gBanKey = "cc-ban:global:" .. ip

        if isBanned(gBanKey) then
            return waf.block(true)
        end

        if globalRateLimit.countStatic or isDynamic(waf) then
            local gRateKey = "cc-rate:global:" .. ip

            if checkRate(gRateKey, gBanKey, globalRateLimit) then
                return doDeny(waf, "IP全局频率超限", 10011)
            end
        end
    end

    if enablePathRateLimit then
        for _, rule in ipairs(pathRules) do
            if rule.enabled then
                local ruleHost = (rule.host or ""):lower()
                local rulePath = (rule.path or ""):lower()

                if host == ruleHost and rulePath ~= "" and uri:find(rulePath, 1, true) == 1 then
                    local pBanKey = "cc-ban:path:" .. host .. ":" .. rulePath .. ":" .. ip

                    if isBanned(pBanKey) then
                        return waf.block(true)
                    end

                    local pRateKey = "cc-rate:path:" .. host .. ":" .. rulePath .. ":" .. ip

                    if checkRate(pRateKey, pBanKey, rule) then
                        return doDeny(waf, "路径限速触发", 10012)
                    end

                    return
                end
            end
        end
    end

    if enableSiteRateLimit then
        local siteConf = siteConfigs[host] or siteDefault

        if siteConf.enabled ~= false then
            local sBanKey = "cc-ban:site:" .. host .. ":" .. ip

            if isBanned(sBanKey) then
                return waf.block(true)
            end

            if siteConf.countStatic or isDynamic(waf) then
                local sRateKey = "cc-rate:site:" .. host .. ":" .. ip

                if checkRate(sRateKey, sBanKey, siteConf) then
                    return doDeny(waf, "站点频率超限", 10013)
                end
            end
        end
    end

    return
end

return _M
