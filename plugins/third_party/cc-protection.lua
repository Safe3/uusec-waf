---
--- CC Protection Plugin
--- Integrates ban blacklist, origin circuit breaker, global IP rate limiting, path rate limiting and site rate limiting
---

local ngx = ngx
local ngx_exit = ngx.exit
local ngx_kv = ngx.shared

local _M = {
    version = 1.8,
    name = "cc-protection",
    priority = 100
}

-- <--- Configuration --->

-- Master switch for CC protection; when false the whole plugin performs no CC detection
local enableCCProtection = true

-- Origin circuit breaker switch; globally counts all requests about to be fetched from origin, temporarily blocks all subsequent requests once exceeded
local enableOriginCircuitBreaker = true

-- Global IP rate limiting switch; counts the total request rate of all sites per IP, used as a coarse filter
local enableGlobalRateLimit = true

-- Precise path rate limiting switch; applies separate rate limits to the specified Host + Path
local enablePathRateLimit = true

-- Site rate limiting switch; counts request rate independently per Host
local enableSiteRateLimit = true

-- Origin circuit breaker configuration; pure global counter that does not distinguish IP, Host or Path, used to protect the overall capacity of the origin
local originCircuitBreaker = {
    enabled = true,        -- Switch for this configuration item
    threshold = 3000,      -- Maximum number of requests about to be fetched from origin allowed within the global time window
    timeWindow = 10,       -- Statistics time window, in seconds
    breakDuration = 30,    -- Global circuit breaker duration, in seconds
    countStatic = true     -- Whether to count static resource requests; true means all requests about to be fetched from origin are counted
}

-- Global IP rate limiting configuration; counts all requests per IP across sites, and continues with the finer subsequent policies when not exceeded
local globalRateLimit = {
    enabled = true,       -- Switch for this configuration item
    threshold = 1000,     -- Maximum number of requests allowed within the time window
    timeWindow = 30,      -- Statistics time window, in seconds
    banDuration = 3600,   -- Ban duration after exceeding the limit, in seconds
    countStatic = false   -- Whether to count static resource requests; false means only dynamic requests are counted
}

-- Site default rate limiting configuration; sites without their own configuration use this one
local siteDefault = {
    enabled = true,       -- Switch for this configuration item
    threshold = 120,      -- Maximum number of requests allowed within the time window
    timeWindow = 60,      -- Statistics time window, in seconds
    banDuration = 3600,   -- Ban duration after exceeding the limit, in seconds
    countStatic = false   -- Whether to count static resource requests; false means only dynamic requests are counted
}

-- Site rate limiting configuration; the key is the accessed domain name, unconfigured domain names use siteDefault
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

-- Precise path rate limiting configuration; uses an independent rate limit once the specified Host and Path prefix match
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

-- <--- Utility functions --->

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
        return doDeny(waf, "Total origin fetch requests exceeded", 10014)
    end
end

-- <--- Main logic --->

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
                return doDeny(waf, "Global IP rate limit exceeded", 10011)
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
                        return doDeny(waf, "Path rate limit triggered", 10012)
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
                    return doDeny(waf, "Site rate limit exceeded", 10013)
                end
            end
        end
    end

    return
end

return _M
