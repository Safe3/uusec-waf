--[[
规则名称: 登录爆破防护
过滤阶段: 请求阶段
危险等级: 高危
规则描述: 针对路径中包含登录、注册等关键词的URL进行防护
作者: MCQSJ(https://github.com/MCQSJ)
更新日期: 2024/12/21
--]]

-- 配置参数
local threshold = 30     -- 错误次数阈值
local timeWindow = 180    -- 时间窗口，单位为秒
local banDuration = 1440 * 60 -- 封禁时间，单位为秒

local sh = waf.ipCache
local bruteForceKey = 'brute-force-login:' .. waf.ip

-- 定义特征路径关键词列表
local targetPaths = { "login", "signin", "signup", "register", "reset", "passwd", "account", "user" }

if not waf.pmMatch(waf.toLower(waf.uri), targetPaths) then
    return false
end

local requestCount, flag = sh:get(bruteForceKey)
if not requestCount then
    sh:set(bruteForceKey, 1, timeWindow, 1)
else
    if flag == 2 then
        return waf.block(true)
    end

    sh:incr(bruteForceKey, 1)
    if requestCount + 1 > threshold then
        sh:set(bruteForceKey, requestCount + 1, banDuration, 2)
        return waf.RULE_BLOCK, "检测到登录接口发生爆破攻击，已封禁IP"
    end
end

return false
