<p align="center">
    ⭐请帮我们点个star以支持我们不断改进，谢谢！
</p>

# 南墙简介

[![GitHub stars](https://img.shields.io/github/stars/Safe3/uusec-waf.svg?label=关注&nbsp;南墙&style=for-the-badge)](https://github.com/Safe3/uusec-waf)
[![Chat](https://img.shields.io/badge/Discuss-加入讨论组-7289da.svg?style=for-the-badge)](https://github.com/Safe3/uusec-waf/discussions)

> **南墙**WEB应用防火墙（简称：`uuWAF`）一款工业级免费、高性能、高扩展，支持AI和语义引擎的Web应用和API安全防护产品。它是有安科技推出的一款全方位网站防护产品，率先实现了流量层、系统层、运行时层3层纵深防御功能。

![](http://waf.uusec.com/_media/waf.png)

🏠安装及使用请访问官网： https://waf.uusec.com/


## :dart: 技术优势
:ophiuchus: 智能的0day防御

南墙创新性的运用机器学习技术，使用`异常检测算法`对http正常与攻击流量进行区分识别，并对正常流量进行白名单威胁建模。通过`机器学习算法`自动学习正常流量中的参数特征，并转化成对应的参数白名单规则库，可以在面对各种突发0day漏洞时，无需添加规则即可拦截攻击，免除网站管理者一出现漏洞就需挑灯夜战升级的痛苦。

:taurus: 极致的CDN加速

南墙自研超越nginx商业版`proxy_cache_purge`才具备的任意缓存清理功能，nginx商业版只支持*模式匹配的方式清理缓存，南墙进一步支持正则表达式匹配url路径的缓存清理方式，相比nginx商业版具备更高的灵活性和实用性。用户可以在享受极致CDN加速的同时，更方便的解决缓存过期问题。

:virgo: 强大的主动防御

南墙自研的主机`主动防御`和`RASP`功能可以系统层和应用运行时层实现更加强大双层防御，可以有效防止0day漏洞攻击，主机层主动防御可以在系统内核层拦截底层攻击，如限制进程的网络通信、进程创建、文件读写、系统提权、系统溢出攻击等。运行时应用自防御RASP则插入java JVM、php Zend等运行时引擎中有效跟踪运行时上下文并拦截各种web 0day漏洞攻击。

:libra: 先进的语义引擎

南墙采用业界领先的`SQL、XSS、RCE、LFI` 4种基于语义分析的检测引擎，结合多种深度解码引擎可对`base64、json、form-data`等HTTP内容真实还原，从而有效抵御各种绕过WAF的攻击方式，并且相比传统正则匹配具备准确率高、误报率低、效率高等特点，管理员无需维护庞杂的规则库，即可拦截多种攻击类型。

:gemini: 高级的规则引擎

南墙积极运用`nginx`和`luajit`的高性能、高灵活性特点，除了提供对普通用户友好性较好的传统规则创建模式，还提供了高扩展性、高灵活性的lua脚本规则编写功能，使得有一定编程功底的高级安全管理员可以创造出一系列传统WAF所不能实现的高级漏洞防护规则，用户可以编写一系列插件来扩展WAF现有功能。从而使得在拦截一些复杂漏洞时，可以更加得心应手。




## :rocket: 一键安装

南墙为你提供了强大灵活的扩展和安全规则的编写API，在管理后台发布后所有规则无需重启立即生效，远超市面上大部分免费WAF产品如`ModSecurity`，规则展示如下：

![](http://waf.uusec.com/_media/rule.png)

🏠请访问官网： https://waf.uusec.com/ 下载 南墙WAF使用说明书 了解规则API详情

南墙安装及其简便，通常在几分钟内即可安装完毕，具体耗时视网络下载情况而定。

注意：请尽量选择一台纯净Linux x86_64环境的服务器安装，因为南墙采用云WAF反向代理模式，默认需要使用80、443端口。

### 安装方式

软件依赖：Docker 20.10.14 版本以上，Docker Compose 2.0.0 版本以上。

若遇到无法自动安装Docker Engine，请参考[阿里云](https://help.aliyun.com/zh/ecs/use-cases/install-and-use-docker-on-a-linux-ecs-instance)手动安装。

```bash
sudo bash -c "$(curl -fsSL https://waf.uusec.com/zh-cn/installer.sh)"
```

后续可直接执行 `bash /opt/waf/manager.sh` 来管理南墙容器，包括启动、停止、更新、卸载等。

### 快速入门

1. 登录后台：访问https://ip:4443 ，ip为安装南墙的服务器ip地址，用户名 `admin` ，密码 `#Passw0rd` 。

2. 添加站点：进入站点管理菜单，点击添加站点按钮，按提示添加站点域名与网站服务器ip。
3. 添加SSL证书：进入证书管理菜单，点击添加证书按钮，上传第二步中域名的https证书和私钥文件。若无SSL证书，可通过南墙申请Let's Encrypt免费SSL证书，并在证书到期前自动续期。
4. 修改域名DNS指向：到域名服务商管理后台把域名DNS A记录的ip地址改为南墙服务器ip地址。
5. 测试连通性：访问站点域名查看网站是否能够打开，查看返回的http header头server字段是否为uuWAF。

更多使用过程中碰到问题的解决办法请参考[常见问题](https://waf.uusec.com/#/guide/problems)。



## :sparkles: 防护效果评估

仅供参考

| 指标             | ModSecurity, 级别 1 | CloudFlare, 免费版 | UUSEC WAF, 社区版 | UUSEC WAF, 专业版 |
| ------------------ | -------------------- | ---------------- | --------------- | -------------- |
| **样本总量**      | 33669                | 33669            | 33669           | 33669          |
| **检出率**      | 69.74%               | 10.70%           | 74.77%          | **98.97%**     |
| **误报率** | 17.58%               | 0.07%            | **0.09%**       | **0.01%**      |
| **准确率**       | 82.20%               | 98.40%           | **99.42%**      | **99.95%**     |



## :1st_place_medal: 产品列表

来自我们的其它伟大产品：

[OpenResty管家](https://github.com/Safe3/openresty-manager) - 最简单易用、功能强大、漂亮的主机管理面板，OpenResty Edge 的开源替代品。

[森罗万象](https://github.com/Safe3/CVS) - 强大的网络空间测绘、资产管理、漏洞扫描等全生命漏洞周期的综合攻击面管理平台，化繁为简，以一御百。


## :gift_heart: 贡献名单

如何贡献？参照: https://waf.uusec.com/#/guide/contribute

这里感谢puhui222、Kingdom、[k4n5ha0](https://github.com/k4n5ha0)为南墙所做的贡献！

  <img src="https://waf.uusec.com/_media/sponsor.jpg" alt="捐赠"  height="300px" />




## :kissing_heart: 加入讨论

欢迎各位就 南墙 的各种bug或功能需求及使用问题，在如下渠道参与讨论

- 问题提交：https://github.com/Safe3/uusec-waf/issues

- 讨论社区：https://github.com/Safe3/uusec-waf/discussions

- 官方 QQ 群：11500614

- 官方微信群：微信扫描以下二维码加入

  <img src="https://waf.uusec.com/_media/weixin.jpg" alt="微信群"  height="200px" />

