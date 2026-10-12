--[[
规则名称: 高频攻击防护
过滤阶段: 请求阶段
危险等级: 高危
规则描述: 针对发起高频率攻击的行为进行防护
作者: MCQSJ(https://github.com/MCQSJ)
更新日期: 2024/12/21
！！！注意: 因为南墙WAF特性，此规则生效对规则ID有要求，需要将此规则与南墙自带规则的第一个规则交换位置才能生效！！！
]]

-- 配置参数
local threshold = 60     -- 错误次数阈值
local banDuration = 1440 * 60 -- 封禁时间，单位为秒

local sh = waf.ipCache
local ip_stats = waf.ipBlock
local ip = waf.ip
local block_key = "blocked-" .. ip

local c, f = sh:get(block_key)
if c and f == 2 then
    return waf.block(true)
end

local recent_count = ip_stats:get(ip)
if recent_count and recent_count > threshold then
    sh:set(block_key, 1, banDuration, 2)
    return waf.RULE_BLOCK, "IP频繁触发拦截，已被拉黑"
end

return false
