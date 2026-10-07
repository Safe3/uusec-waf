--[[
规则名称: 高频错误防护
过滤阶段: 返回HTTP头阶段
危险等级: 中危
规则描述: 针对频繁触发错误的请求的行为进行防护
作者: MCQSJ(https://github.com/MCQSJ)
更新日期: 2024/12/21
--]]

local function isSpecifiedError(status)
    local allowed_errors = {400, 401, 403, 404, 405, 429, 444}
    return waf.inArray(status, allowed_errors)
end

-- 配置参数
local threshold = 10     -- 错误次数阈值
local timeWindow = 60    -- 时间窗口，单位为秒
local banDuration = 1440 * 60 -- 封禁时间，1440分钟 = 86400秒

local ip = waf.ip

local status = waf.status

if not isSpecifiedError(status) then
    return false
end

local errorCache = waf.ipCache
local errorKey = "error:" .. ip

local errorCount, flag = errorCache:get(errorKey)

if not errorCount then
    errorCache:set(errorKey, 1, timeWindow)
else
    if flag == 2 then
        return waf.block(true)
    end

    errorCache:incr(errorKey, 1)
    if errorCount + 1 >= threshold then
        errorCache:set(errorKey, errorCount + 1, banDuration, 2)
        return waf.RULE_BLOCK, "高频错误触发，IP已被封禁"
    end
end

return false
