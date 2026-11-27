
## :grapes: 规则

?>这里对规则所用到的一些变量和相关函数进行说明，更多规则编写方法请大家参照WAF管理后台中的规则管理当中的众多实际例子。规则模板见：https://github.com/Safe3/uusec-waf/blob/main/rules/anti-cc.lua ，一条防cc攻击的安全规则。欢迎各位贡献安全规则，详情见：https://waf.uusec.com/#/guide/contribute 。

### 规则示例

```lua
--[[
规则名称: anti cc
过滤阶段: 请求阶段
危险等级: 中危
规则描述: 当一分钟访问/api/路径频率超过360次，则在5分钟内拦截该ip访问
--]]


if not waf.startWith(waf.toLower(waf.uri), "/api/") then
    return false
end

local sh = waf.ipCache
local ccIp = 'cc-' .. waf.ip
local c, f = sh:get(ccIp)
if not c then
    sh:set(ccIp, 1, 60, 1)           -- 设置1分钟也就是60秒访问计数时间
else
    if f == 2 then
        return waf.block(true)       -- 重置TCP连接，不记录日志
    end
    sh:incr(ccIp, 1)
    if c + 1 >= 360 then             -- 频率超过360次
        sh:set(ccIp, c + 1, 300, 2)  -- 设置5分钟也就是300秒拦截时间
        return waf.RULE_BLOCK, ccIp  -- 返回参数，第一个值为waf.RULE_BLOCK表示拦截操作；第二个参数ccIp为日志记录内容；
    end
end

return false
```



### 规则常量

##### waf.RULE_BLOCK
- 类型: ``number``
- 默认值: ``1``
- 用法: 只读，当规则返回该值时表示为拦截操作，即黑名单规则。

##### waf.RULE_ALLOW

- 类型: ``number``
- 默认值: ``2``
- 用法: 只读，当规则返回该值时表示为允许操作，即白名单规则。

##### waf.RULE_LOG_ONLY

- 类型: ``number``
- 默认值: ``3``
- 用法: 只读，当规则返回该值时表示为只记录操作，用于单个规则的观察模式。



### 规则变量

#### 请求阶段变量
##### waf.ip
- 类型: ``string``
- 默认值: ``客户端访问ip``
- 用法: 只读，用于获取客户端访问ip，可以在WAF后台站点管理中配置客户端ip来源，获取方式为Socket或X-Forwarded-For中的倒序第n个ip。

##### waf.scheme

- 类型: ``string``
- 默认值: ``客户端访问http协议，值为字符串http或https``
- 用法: 只读。

##### waf.httpVersion

- 类型: ``number``
- 默认值: ``http协议版本，值为1.0、1.1、2.0、3.0``
- 用法: 只读。

##### waf.host

- 类型: ``string``
- 默认值: ``客户端访问host头``
- 用法: 只读。

##### waf.ipBlock

- 类型: ``table``
- 默认值: ``键值存储库，用于存放已拦截的客户端ip``
- 用法: 见ngx.shared.DICT。

##### waf.ipCache

- 类型: ``table``
- 默认值: ``键值存储库，用于存放访问的客户端ip``
- 用法: 见ngx.shared.DICT。

##### waf.requestLine

- 类型: ``string``
- 默认值: ``原始的request line数据``
- 用法: 只读。

##### waf.uri

- 类型: ``string``
- 默认值: ``解码处理过的URI，不带参数``
- 用法: 只读。

##### waf.method

- 类型: ``string``
- 默认值: ``请求方法``
- 用法: 只读。

##### waf.reqUri

- 类型: ``string``
- 默认值: ``原始URI，带参数``
- 用法: 只读。

##### waf.userAgent

- 类型: ``string``
- 默认值: ``客户端请求的User-Agent头数据``
- 用法: 只读。

##### waf.referer

- 类型: ``string``
- 默认值: ``客户端请求的Referer头数据``
- 用法: 只读。

##### waf.reqContentType

- 类型: ``string``
- 默认值: ``客户端请求的Content-Type头数据``
- 用法: 只读。

##### waf.XFF

- 类型: ``string``
- 默认值: ``客户端请求的X-Forwarded-For头数据``
- 用法: 只读。

##### waf.origin

- 类型: ``string``
- 默认值: ``客户端请求的Origin头数据``
- 用法: 只读。

##### waf.reqHeaders

- 类型: ``table``
- 默认值: ``请求的所有header对象``
- 用法: 只读。

##### waf.hErr

- 类型: ``string``
- 默认值: ``请求header解析出错信息``
- 用法: 只读。

##### waf.isQueryString

- 类型: ``bool``
- 默认值: ``true或false``
- 用法: 只读，是否存在请求参数。

##### waf.reqContentLength

- 类型: ``number``
- 默认值: ``0``
- 用法: 只读，请求body内容长度，整数值。

##### waf.queryString

- 类型: ``table``
- 默认值: ``请求url参数，key、value``
- 用法: 只读。

##### waf.qErr

- 类型: ``string``
- 默认值: ``请求参数解析出错信息``
- 用法: 只读。

##### waf.form

- 类型: ``table``
- 默认值: ``请求body对象``
- 用法: 只读。

##### waf.form["RAW"]

- 类型: ``string``
- 默认值: ``请求body的原始数据``
- 用法: 只读。

##### waf.form["FORM"]

- 类型: ``table``
- 默认值: ``请求body参数，key、value``
- 用法: 只读，表单如: {uid="12",vid={[1]="select",[2]="a from b"}}。

##### waf.form["FILES"]

- 类型: ``table``
- 默认值: ``解析出的请求body中上传文件信息``
- 用法: 只读，文件信息如: {name={[1]="filename",[2]="file content"}}。

##### waf.fErr

- 类型: ``string``
- 默认值: ``解析请求body出错信息``
- 用法: 只读，一般是恶意畸形请求包。

##### waf.cookies

- 类型: ``table``
- 默认值: ``请求cookie参数，key、value``
- 用法: 只读。

##### waf.cErr

- 类型: ``string``
- 默认值: ``解析请求cookie出错信息``
- 用法: 只读。

#### 返回http头阶段新增变量

##### waf.status

- 类型: ``number``
- 默认值: ``返回http状态，整数值``
- 用法: 只读。

##### waf.respHeaders

- 类型: ``table``
- 默认值: ``返回的所有header对象，key、value``
- 用法: 只读。

##### waf.respContentLength

- 类型: ``number``
- 默认值: ``返回body内容长度，整数值``
- 用法: 只读。

##### waf.respContentType

- 类型: ``string``
- 默认值: ``服务端返回的Content-Type头数据``
- 用法: 只读。

####  返回页面阶段新增变量

##### waf.respBody

- 类型: ``string``
- 默认值: ``返回body页面内容``
- 用法: 只读。

##### waf.replaceFilter

- 类型: ``bool``
- 默认值: ``false``
- 用法: 当返回内容类型为text/html、text/plain、json、xml时，通知南墙替换返回页面内容，则设置waf.replaceFilter = true，可用于数据脱敏、敏感词替换等场景。

##### 规则示例

```lua
--[[
规则名称: 数据脱敏
过滤阶段: 返回页面阶段
危险等级: 中危
规则描述: 对返回页面中的身份证和手机号进行*替换脱敏
--]]


if waf.respContentLength == 0 or waf.respContentLength >= 2097152 then
    return
end

-- 只保留身份证号前2位和后2位
local newstr, n, err = waf.rgxGsub(waf.respBody, [[\b((1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|[7-9]1)\d{4}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx])\b]], function(m)
    return m[0]:sub(1, 2) .. "**************" .. m[0]:sub(-2)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
if n > 0 then
    waf.respBody = newstr
    -- 通知南墙进行数据替换
    waf.replaceFilter = true
end

-- 只保留手机号前3位和后4位
newstr, n, err = waf.rgxGsub(waf.respBody, [[\b1(?:(((3[0-9])|(4[5-9])|(5[0-35-9])|(6[2,5-7])|(7[0135-8])|(8[0-9])|(9[0-35-9]))[ -]?\d{4}[ -]?\d{4})|((74)[ -]?[0-5]\d{3}[ -]?\d{4}))\b]], function(m)
    return m[0]:sub(1, 3) .. "****" .. m[0]:sub(-4)
end, "jos")
if not newstr then
    waf.errLog("error: ", err)
    return
end
if n > 0 then
    waf.respBody = newstr
    -- 通知南墙进行数据替换
    waf.replaceFilter = true
end
```



### 规则 API

#### 规则通用 API

##### waf.startWith(sstr,dstr)
- 参数: ``sstr 为原字符串，dstr 为查找字符串``
- 功能: 判断字符串 sstr 是否以 dstr 开头
- 返回值: ``true 或 false``

##### waf.endWith(sstr,dstr)

- 参数: ``sstr 为原字符串，dstr 为查找字符串``
- 功能: 判断字符串 sstr 是否以 dstr 结尾
- 返回值: ``true 或 false``

##### waf.toLower(sstr)

- 参数: ``sstr 为原字符串``
- 功能: 将字符串 sstr 转化为小写
- 返回值: ``sstr 小写``

##### waf.contains(sstr,dstr)

- 参数: ``sstr 为原字符串，dstr 为查找字符串``
- 功能: 判断字符串 sstr 是否在字符串 dstr
- 返回值: ``true 或 false``

##### waf.regex(sstr,pat,ext)

- 参数: ``sstr 为原字符串，pat 为正则表达式，ext 为正则属性``
- 功能: 在字符串 sstr 中匹配正则表达式 pat，用法同ngx.re.match
- 返回值: ``所有匹配项、错误``

##### waf.rgxMatch(sstr,pat,ext)

- 参数: ``sstr 为原字符串，pat 为正则表达式，ext 为正则属性``
- 功能: 在字符串 sstr 中匹配正则表达式 pat
- 返回值: ``true 或 false``

##### waf.rgxGmatch(sstr,pat,ext)

- 参数: ``sstr 为原字符串，pat 为正则表达式，ext 为正则属性``
- 功能: 在字符串 sstr 中匹配正则表达式 pat，用法同ngx.re.gmatch
- 返回值: ``迭代器iterator,错误err``

##### waf.rgxSub(subject, regex, replace, options?)

- 参数: ``subject 为原字符串，regex 为正则表达式，replace 为要替换的字符串，options为正则选项``
- 功能: 替换字符串 subject 中正则表达式 regex 匹配到的内容为 replace，用法同ngx.re.sub
- 返回值: ``newstr, n, err分别为新字符串、替换个数、错误信息``

##### waf.rgxGsub(subject, regex, replace, options?)

- 参数: ``subject 为原字符串，regex 为正则表达式，replace 为要替换的字符串，options为正则选项``
- 功能: 替换字符串 subject 中所有正则表达式 regex 匹配到的内容为 replace，用法同ngx.re.gsub
- 返回值: ``newstr, n, err分别为新字符串、替换个数、错误信息``

##### waf.kvFilter(v,match,valOnly)

- 参数: ``v 为要匹配对象，match 为匹配函数,valOnly 为 true 则只匹配 value``
- 功能: 用于匹配 cookie、queryString 等 key，value 键值对数据，在对象 v 中用 match 函 数匹配内容
- 返回值: ``true,匹配内容或 false,nil``

##### waf.knFilter(v,match,p)

- 参数: ``v 为要匹配对象，match 为匹配函数，p 为 1 时匹配上传文件名，为 0 时文件内容``
- 功能: 用于过滤上传文件信息，在对象 v 中用 match 函数匹配内容
- 返回值: ``true,匹配内容或 false,nil``

##### waf.jsonFilter(v, match,parsed,valOnly)

- 参数: ``v 为要匹配对象，match 为匹配函数，parsed 为 false 时解析类型为字符串 v 值，为 true 时解析类型为 table 的 v 值, valOnly 为 true 则只匹配 value``
- 功能: 用于遍历过滤请求中的 json 数据，在对象 v 中用 match 函数匹配内容
- 返回值: ``true,匹配内容或 false,nil``

##### waf.base64Decode(str)

- 参数: ``str 为要解码的 base64 字符串``
- 功能: 用于解码 base64 数据为明文数据
- 返回值: ``明文字符串或 nil``

##### waf.checkSQLI(str, level?)

- 参数: ``str 为要检测的字符串；level可省略，为严格等级，数值越大越严格，范围0至3``
- 功能: 基于语义引擎检测 sql 注入攻击
- 返回值: ``true 或 false``

##### waf.checkRCE(str, level?)

- 参数: ``str 为要检测的字符串；level可省略，为严格等级，数值越大越严格，范围0至3``
- 功能: 基于语义引擎检测命令注入攻击
- 返回值: ``true 或 false``

##### waf.checkPT(str)

- 参数: ``str 为要检测的字符串``
- 功能: 基于语义引擎检测路径遍历攻击
- 返回值: ``true 或 false``

##### waf.checkXSS(str)

- 参数: ``str 为要检测的字符串``
- 功能: 基于语义引擎检测xss攻击
- 返回值: ``true 或 false``

##### waf.strCounter(sstr,dstr)

- 参数: ``sstr 为原字符串，dstr 为查找字符串``
- 功能: 计算字符串 dstr 在 sstr 中出现的次数
- 返回值: ``整数``

##### waf.trim(str)

- 参数: ``str 为原字符串``
- 功能: 去掉字符串 str 两边的空格
- 返回值: ``去掉两边空格后的字符串``

##### waf.inArray(str,arr)

- 参数: ``str 为原字符串，arr为字符串数组``
- 功能: 判断字符串 str 是否存在于arr字符串数组中
- 返回值: ``true 或 false``

##### waf.pmMatch(sstr,dict)

- 参数: ``sstr 为原字符串，dict 为查找字典，以 lua 表的形式，如：{“aaa”, “bbb”, “ccc”}``

- 功能: 高效多模匹配多个字符串，发现其中一个字符串立即返回

- 返回值: ``true，字典中的字符串或 false，nil``

##### waf.urlDecode(sstr)

- 参数: ``sstr 为原字符串``
- 功能: 将 sstr 进行 url 解码还原成字符串
- 返回值: ``解码后的字符串``

##### waf.htmlEntityDecode(sstr)

- 参数: ``sstr 为原字符串``
- 功能: 将字符串 sstr 进行 html 实体解码
- 返回值: ``解码后的字符串``

##### waf.hexDecode(sstr)

- 参数: ``sstr 为原字符串``
- 功能: 将字符串 sstr 进行 hex 解码
- 返回值: ``解码后的字符串``

##### waf.block(reset)

- 参数: ``reset 为true时直接重置tcp不返回任何内容，否则返回403页面``
- 功能: 拦截客户端请求，直接重置客户端连接或返回403页面，与return搭配使用

##### waf.checkRobot(waf, expireTime?, max?)

- 参数: ``waf 为固定waf对象；认证成功后当前ip时间达到 expireTime(单位秒，默认值600，值为0时不过期)或请求数达到 max(默认值18000，值为0时不限次数)后重新显示验证页面``
- 功能: 检测机器人攻击，如数据爬虫、扫描攻击、CC拒绝服务攻击等，并生成滑动旋转图片验证码，与return搭配使用

##### waf.checkTurnstile(waf, siteKey, secret, expireTime?, max?)

- 参数: ``waf 为固定waf对象；siteKey 和 secret 为Cloudflare Turnstile的组件配置参数；认证成功后当前ip时间达到 expireTime(单位秒，默认值600，值为0时不过期)或请求数达到 max(默认值18000，值为0时不限次数)后重新显示验证页面``
- 功能: 使用Cloudflare Turnstile来进行自动人机验证，检测机器人攻击，如数据爬虫、扫描攻击、CC拒绝服务攻击等，与return搭配使用

##### waf.redirect(uri, status?)

- 参数: ``uri为重定向的链接，status为返回http状态（可选），默认为302``
- 功能: 重定向客户端请求到新的链接，与return搭配使用

##### waf.ip2loc(ip, lang?)

- 参数: ``ip为要查询的ip地址，lang为显示语言，如en、zh-CN等，默认值"en"``
- 功能: 将ip地址转化为国家、省份、城市、地区代码地理位置信息
- 返回值: ``country、 province、 city、iso_code，如：中国、湖北省、武汉市、CN``

##### waf.errLog(...)

- 参数: ``1个或多个字符串``
- 功能: 记录错误日志到/uuwaf/logs/error.log中
- 返回值: ``无``

##### waf.searchEngineValid(dns, ip, ua)

- 参数: ``dns为要查询的dns服务器ip，ip为要查询的ip地址，ua为请求的User-Agent``
- 功能: 用于验证请求是否真的来自于搜索引擎，避免高频限制规则影响搜索引擎收录
- 返回值: ``name字符串值，为搜索引擎名称； valid布尔值，值为true则是真实搜索引擎，反之不是``



## :melon: 插件

?>南墙支持强大的插件扩展功能，方便用户自行实现一些特有功能。插件模板见：https://github.com/Safe3/uusec-waf/blob/main/plugins/kafka-logger.lua ，一个kafka日志记录插件。欢迎各位贡献安全插件，详情见：https://waf.uusec.com/#/guide/contribute 。

### 插件编写

一个标准的插件包含以下几个部分，每个部分若无功能实现可省略，每个大阶段分为pre和post前后两个小阶段，分别代表南墙逻辑处理执行前和南墙逻辑处理执行后。南墙v4.1.0之前的版本没有小阶段，请使用req_filter、resp_header_filter、resp_body_filter、log。每个过滤阶段可以返回两个bool值，第一个值为true则不再继续执行下一个插件，第二个值为true则直接返回，不再继续执行后续安全规则。

```lua
local _M = {
    version = 0.1,          --  插件版本
    name = "kafka-logger",  --  插件名称
    priority = 1            --  插件执行优先级，值越大优先级越高
}

-- ssl阶段前过滤，waf参数值为nil
function _M.ssl_pre_filter(waf)

end

-- ssl阶段后过滤，waf参数值为nil
function _M.ssl_post_filter(waf)

end

-- 请求阶段前过滤
function _M.req_pre_filter(waf)

end

-- 请求阶段后过滤
function _M.req_post_filter(waf)

end

-- 返回header阶段前过滤
function _M.resp_header_pre_filter(waf)

end

-- 返回header阶段后过滤
function _M.resp_header_post_filter(waf)

end

-- 返回body阶段前过滤
function _M.resp_body_pre_filter(waf)

end

-- 返回body阶段后过滤
function _M.resp_body_post_filter(waf)

end

-- 日志记录阶段前过滤
function _M.log_pre_filter(waf)

end

-- 日志记录阶段后过滤
function _M.log_post_filter(waf)

end

return _M
```



- #### SSL阶段过滤函数

- 该阶段用于获取客户端请求的域名和设置SSL证书，waf变量的值为nil。

- #### 请求阶段过滤函数

- 该阶段用于过滤客户端发送的请求数据，waf变量同规则变量一致，可自行实现该函数功能。

- #### 返回header阶段过滤函数

- 该阶段用于过滤服务器返回的header头数据，waf变量同规则变量一致，可自行实现该函数功能。

- #### 返回body阶段过滤函数

- 该阶段用于过滤服务器返回的body内容数据，waf变量同规则变量一致，可自行实现该函数功能。

- #### 日志记录阶段执行函数

- 该阶段用于日志记录阶段做一些日志处理与推送，waf变量同规则变量一致，可自行实现该函数功能。



### 常用功能函数

#### 各阶段数据共享

##### waf.ctx

有时为了在各个执行函数间共享同一个数据，可以通过给waf.ctx赋值来实现，如：

```lua
function _M.resp_body_pre_filter(waf)
	waf.ctx = "share"
end

function _M.log_pre_filter(waf)
	log.errLog(waf.ctx)
end
```



#### 记录错误日志

```lua
local log = require("waf.log")
```



##### log.errLog(...)

- 参数: ``可变参数，类型为字符串``
- 功能: 将信息写入错误日志/uuwaf/logs/error.log
- 返回值: ``无``

##### log.utf8(str)

- 参数: ``字符串``
- 功能: 将str字符编码转换为utf-8编码，防止数据写入数据库或json编码时出错
- 返回值: ``字符串``

##### log.getReq()

- 参数: ``无``
- 功能: 获取客户端http请求信息
- 返回值: ``字符串``

##### log.encodeJson(obj)

- 参数: ``lua table对象``
- 功能: 将lua table对象转化json字符串
- 返回值: ``json字符串``

##### log.broker(func，...)

- 参数: ``func为函数，可变参数为传给函数func的参数``
- 功能: 代理执行函数func，并传参。
- 返回值: ``无``

:smile: 其它隐藏功能彩蛋，由用户自行去发掘。