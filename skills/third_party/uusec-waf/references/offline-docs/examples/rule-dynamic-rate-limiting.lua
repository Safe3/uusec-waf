--[[
规则名称: 高级动态限频防护
过滤阶段: 请求阶段
危险等级: 严重
规则描述: 动态频率限制和资源防盗刷功能，支持按分类独立开关动态阈值，每类资源可设置独立检测窗口，可缓解CC攻击和资源盗刷等问题。
作者: MCQSJ(https://github.com/MCQSJ)
更新日期: 2025/03/26
--]]

-- 全局配置参数
local totalWindow = 60      -- 统计站点总访问量的时间窗口，单位为秒
local banDuration = 1440 * 60 -- 封禁时间，单位为秒（1440分钟 = 86400秒）
local totalVisitsKey = "total-visits" -- 统计全局访问量的key

-- 资源类型配置
local resourceLimits = {
    -- 大资源：压缩包、程序、视频等
    large = {
        types = {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso", "dmg", "exe", "msi", "pkg", "apk", "deb", "rpm", "mp4", "mov", "avi", "wmv", "flv", "mkv", "webm", "m4v", "3gp"},
        baseThreshold = 5,   -- 基础限制次数
        timeWindow = 300,    -- 5分钟检测窗口
        enableDynamic = true -- 是否启用动态阈值
    },
    -- 小资源：图片、字体等
    small = {
        types = {"png", "svg", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "ico", "psd", "ttf", "woff", "woff2", "eot", "otf"},
        baseThreshold = 30,  -- 基础限制次数
        timeWindow = 60,     -- 1分钟检测窗口
        enableDynamic = true -- 是否启用动态阈值
    },
    -- 常用资源：CSS、JS、JSON等
    common = {
        types = {"css", "js", "json", "xml", "txt", "rtf", "csv"},
        baseThreshold = 200, -- 基础限制次数
        timeWindow = 60,     -- 1分钟检测窗口
        enableDynamic = true -- 是否启用动态阈值
    },
    -- 其他资源：API请求等无后缀或未分类请求
    other = {
        baseThreshold = 60,  -- 基础限制次数
        timeWindow = 10,     -- 10秒检测窗口
        enableDynamic = true -- 是否启用动态阈值
    }
}

-- 动态调整阈值配置（仅当分类启用动态阈值时使用）
local dynamicThresholds = {
    low = {    -- 低流量模式(总访问量<=200)
        factor = 100,       -- 宽松模式系数(百分比)
        name = "宽松模式"
    },
    mid = {    -- 中流量模式(200<总访问量<=300)
        factor = 50,        -- 适中模式系数(百分比)
        name = "适中模式"
    },
    high = {   -- 高流量模式(总访问量>300)
        factor = 20,        -- 紧急模式系数(百分比)
        name = "紧急模式"
    }
}

-- 定义总访问量挡位
local totalVisitLimits = {
    low = 200,              -- 低于此处的值时为宽松模式
    mid = 300               -- 高于low低于此处值时为适中模式，高于此处值时为紧急模式
}

local function getFileExtension(uri)
    return uri:match("^.+(%..+)$")
end

local function getResourceConfig(uri)
    local ext = getFileExtension(uri)
    if ext then
        ext = ext:lower()
        for category, config in pairs(resourceLimits) do
            if config.types then
                for _, fileType in ipairs(config.types) do
                    if ext == "." .. fileType then
                        return config.baseThreshold, config.timeWindow, category, config.enableDynamic
                    end
                end
            end
        end
    end
    local other = resourceLimits.other
    return other.baseThreshold, other.timeWindow, "other", other.enableDynamic
end

local function getDynamicFactor(visits)
    if visits <= totalVisitLimits.low then
        return dynamicThresholds.low.factor, dynamicThresholds.low.name
    elseif visits <= totalVisitLimits.mid then
        return dynamicThresholds.mid.factor, dynamicThresholds.mid.name
    else
        return dynamicThresholds.high.factor, dynamicThresholds.high.name
    end
end

local function calculateThreshold(base, factor, useDynamic)
    if not useDynamic then
        return base
    end
    local result = (base * factor) / 100
    if result < 1 then
        return 1
    end
    return result - (result % 1)
end

local sh = waf.ipCache
local totalVisits = sh:incr(totalVisitsKey, 1, 0, totalWindow)
if not totalVisits then
    return false
end

local dynamicFactor, currentMode = getDynamicFactor(totalVisits)

local baseThreshold, timeWindow, resourceType, enableDynamic = getResourceConfig(waf.uri)

local finalThreshold = calculateThreshold(baseThreshold, dynamicFactor, enableDynamic)

local ipKey = 'dynamic-protect-' .. resourceType .. '-' .. waf.ip
local count, flag = sh:get(ipKey)

if not count then
    sh:set(ipKey, 1, timeWindow, 1)
else
    if flag == 2 then
        return waf.block(true)
    end
    sh:incr(ipKey, 1)
    if count + 1 >= finalThreshold then
        sh:set(ipKey, count + 1, banDuration, 2)
        local modeInfo = enableDynamic and ("当前模式:" .. currentMode) or "固定阈值模式"
        return waf.RULE_BLOCK, "IP因请求" .. resourceType .. "资源频率过高被封禁(" .. modeInfo .. ",窗口:" .. timeWindow .. "秒,阈值:" .. finalThreshold .. ")"
    end
end

return false