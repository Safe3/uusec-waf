# 常见问题
> 南墙 的发展离不开社区的每一位用户的支持，欢迎在[github](https://github.com/Safe3/uusec-waf)上点个小星星，这里收集常见的使用问题 。



### 🍎 为什么访问网站会出现规则ID为-1的拦截页面？ <!-- {docsify-ignore} -->
?> 如果域名没有在南墙站点管理中配置，访问南墙默认会拦截该域名的访问，以防止黑域名指向引起的法律风险。



### 🍐 经过南墙代理的网站如何获取客户端真实ip？ <!-- {docsify-ignore} -->
?> 南墙转发给网站的HTTP请求头中会加入X-Waf-Ip字段，它的值即为客户端ip，也可以通过X-Forwarded-For来获取。



### 🍑 集群模式下上游网站如何区分不同的南墙来源？ <!-- {docsify-ignore} -->

?> 南墙转发给网站的HTTP请求头中会加入X-Waf-Id字段，它的值即为用户在/uuwaf/web/conf/config.json中配置的id值，用户可以通过该值来区分网站请求来自那台南墙服务器。



### 🍊 如何查看南墙CDN是否缓存了我们的网页？ <!-- {docsify-ignore} -->

?> 南墙提供了一个X-Waf-Cache返回头用以查看缓存情况，如X-Waf-Cache: HIT表示已缓存，X-Waf-Cache: MISS表示未缓存。



### 🍍 如何修改南墙管理后台的端口和SSL证书？ <!-- {docsify-ignore} -->

?> 南墙管理后台的配置位于/uuwaf/web/conf/config.json中，addr字段值即为ip地址和端口。替换SSL证书可以替换/uuwaf/web/conf/目录中的server.crt和server.key文件，之后重启服务使配置生效。



### 🍈 如何修改南墙反向代理默认监听端口？ <!-- {docsify-ignore} -->

?> 南墙默认只监听http 80、https 443端口，用户可自行在/uuwaf/conf/uuwaf.conf中自定义任意监听端口，配置方式请参考nginx 的 [listen](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen) 设置，之后重启服务使配置生效。Docker版用户可以修改docker-compose.yml中的port端口映射。



### 🍌 为何无法获取免费SSL证书？ <!-- {docsify-ignore} -->

?> 南墙使用HTTP 01验证方式自动获取Let‘s Encrypt免费证书时需要确保南墙80端口能被公网ip访问才能通过Let‘s Encrypt的验证。使用DNS-01验证时无此限制，并且可以申请泛域名证书，但DNS生效需要时间，有时要稍等一段时间后再试。另外Let‘s Encrypt每月可申请的证书次数有一定限制，过于频繁申请也会造成申请失败。



### 🍆 如何补充丰富南墙滑动旋转验证码图片数量？ <!-- {docsify-ignore} -->

?> 选择合适大小的png图片，放入/uuwaf/captcha/images/目录，然后重启服务使配置生效。



### 🌶️ 如何调用南墙控制台的REST API？ <!-- {docsify-ignore} -->

?> 请求时在HTTP头中加入 "Api-Token: xxxxxx"，xxxxxx为你的实际token值，可在南墙系统设置中找到，然后请求南墙控制台的REST API就可以了。
