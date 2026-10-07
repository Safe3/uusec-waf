<p align="center">
  <a target="_blank" href="https://www.uusec.com/">🏠 Home</a> &nbsp; | &nbsp;
  <a target="_blank" href="/README_CN.md">中文版</a>
  <br/><br/>
    ⭐Please help us with a star to support our continuous improvement, thank you!
</p>



# Introduction

[![GitHub stars](https://img.shields.io/github/stars/Safe3/uusec-waf.svg?label=Follow&nbsp;uusec-waf&style=for-the-badge)](https://github.com/Safe3/uusec-waf)
[![Chat](https://img.shields.io/badge/Discuss-Join-7289da.svg?style=for-the-badge)](https://github.com/Safe3/uusec-waf/discussions)

> **UUSEC WAF** Web Application Firewall is an industrial grade free, high-performance, and highly scalable web application and API security protection product that supports AI and semantic engines. It is a comprehensive website protection product launched by UUSEC Technology, which first realizes the three-layer defense function of traffic layer, system layer, and runtime layer.

![](https://github.com/Safe3/uusec-waf/blob/main/docs/_media/waf.png)



# GitHub Daily Trend
[![UUSEC WAF](https://res.cloudinary.com/marcomontalbano/image/upload/v1742432660/video_to_markdown/images/youtube--x8oHis0gzlE-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://www.youtube.com/watch?v=x8oHis0gzlE "UUSEC WAF")



## :dart: Technical advantages
:ophiuchus: Intelligent 0-day defense

UUSEC WAF innovatively applies machine learning technology, using anomaly detection algorithms to distinguish and identify HTTP normal and attack traffic, and models whitelist threats to normal traffic. By using machine learning algorithms to automatically learn the parameter characteristics of normal traffic and convert them into corresponding parameter whitelist rule libraries, it is possible to intercept attacks without adding rules when facing various sudden 0-day vulnerabilities, eliminating the pain of website managers having to work late to upgrade as soon as vulnerabilities appear.

:taurus: Ultimate CDN acceleration

UUSEC self-developed cache cleaning feature surpasses the arbitrary cache cleaning function only available in the commercial version of nginx, proxy_cache_purge. The commercial version of nginx only supports * pattern matching to clean the cache, while UUSEC WAF further supports regular expression matching URL path cache cleaning, which has higher flexibility and practicality compared to the commercial version of nginx. Users can enjoy ultimate CDN acceleration while more conveniently solving cache expiration issues.

:virgo: Powerful proactive defense

The self-developed 'HIPS' and 'RASP' functions of UUSEC WAF can achieve more powerful dual layer defense at the system layer and application runtime layer, effectively preventing zero day vulnerability attacks. Host layer active defense can intercept low-level attacks at the system kernel layer, such as restricting process network communication, process creation, file read and write, system privilege escalation, system overflow attacks, etc. Runtime application self-defense RASP is inserted into runtime engines such as Java JVM and PHP Zend to effectively track runtime context and intercept various web 0-day vulnerability attacks.

:libra: Advanced semantic engine

UUSEC WAF adopts four industry-leading semantic analysis based detection engines, namely SQL, XSS, RCE, and LFI. Combined with multiple deep decoding engines, it can truly restore HTTP content such as base64, JSON, and form data, effectively resisting various attack methods that bypass WAF. Compared with traditional regular matching, it has the characteristics of high accuracy, low false alarm rate, and high efficiency. Administrators do not need to maintain a complex rule library to intercept multiple types of attacks.

:gemini: Advanced rule engine

UUSEC WAF actively utilizes the high-performance and highly flexible features of nginx and luajit. In addition to providing a traditional rule creation mode that is user-friendly for ordinary users, it also offers a highly scalable and flexible Lua script rule writing function, allowing advanced security administrators with certain programming skills to create a series of advanced vulnerability protection rules that traditional WAF cannot achieve. Users can write a series of plugins to extend the existing functions of WAF. This makes it easier to intercept complex vulnerabilities.




## :rocket: One click Installation

UUSEC WAF provides you with a powerful and flexible API for extending and writing security rules. After being published in the management backend, all rules take effect immediately without restarting, far exceeding most free WAF products on the market such as ModSecurity. The rules are shown below:

![](http://waf.uusec.com/_media/rule.png)


🏠Please visit the official website to see more details:  https://waf.uusec.com/ 

The installation of the UUSEC WAF is very simple, usually completed within a few minutes, and the specific time depends on the network download situation.

Attention: Please try to choose a pure Linux x86_64 environment server for installation, because the UUSEC WAF adopts cloud WAF reverse proxy mode, which requires the use of ports 80 and 443 by default.

### Installation

Software dependencies: Docker CE version 20.10.14 or above, Docker Compose version 2.0.0 or above.

If you encounter the inability to automatically install Docker Engine, please install it manually.

```bash
sudo bash -c "$(curl -fsSL https://waf.uusec.com/installer.sh)"
```

Subsequently, `bash /opt/waf/manager.sh` is used to manage the UUSEC WAF container, including starting, stopping, updating, uninstalling, etc.

### Quick Start

1. Login to the management: Access https://ip:4443 ,the IP address is the server IP address for installing the UUSEC WAF, the default username is `admin`, and the default password is `#Passw0rd`.
2. Add a site: Go to the "Sites" menu, click the "Add Site" button, and follow the prompts to add the site domain name and website server IP.
3. Add SSL certificate: Go to the certificate management menu, click the "Add Certificate" button, and upload the HTTPS certificate and private key file of the domain name. If you don‘t have a SSL certificate, you can also apply for a Let's Encrypt free SSL certificate and renew it automatically before the certificate expires.
4. Change the DNS address of the domain: Go to the domain name service provider's management backend and change the IP address recorded in the DNS A of the domain name to the IP address of the UUSEC WAF server.
5. Test connectivity: Visit the site domain to see if the website can be opened, and check if the returned HTTP header server field is uuWAF.

For more solutions to problems encountered during use, please refer to [FAQ](https://waf.uusec.com/#/guide/problems).



## :sparkles: Effect Evaluation

For reference only

| Metric             | ModSecurity, Level 1 | CloudFlare, Free | UUSEC WAF, Free | UUSEC WAF, Pro |
| ------------------ | -------------------- | ---------------- | --------------- | -------------- |
| **Total Samples**      | 33669                | 33669            | 33669           | 33669          |
| **Detection**      | 69.74%               | 10.70%           | 74.77%          | **98.97%**     |
| **False Positive** | 17.58%               | 0.07%            | **0.09%**       | **0.01%**      |
| **Accuracy**       | 82.20%               | 98.40%           | **99.42%**      | **99.95%**     |



## :1st_place_medal: Product List

Other great products from us:

[OpenResty Manager](https://github.com/Safe3/openresty-manager) - The most simple, powerful and beautiful host management panel, open source alternative to OpenResty Edge.



## :gift_heart: Contribution List

How to contribute? reference: https://waf.uusec.com/#/guide/contribute

Thanks to puhui222, MCQSJ, k4n5ha0 and more for the contribution made to the UUSEC WAF!




## :kissing_heart: Join the discussion

Welcome to participate in discussions on various bugs, functional requirements, and usage issues related to the UUSEC WAF through the following channels:

- Problem submission: https://github.com/Safe3/uusec-waf/issues
- Discussion Community: https://github.com/Safe3/uusec-waf/discussions
