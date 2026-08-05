## [7.2.5](https://github.com/Safe3/uusec-waf/compare/v7.2.5...v7.2.4) (2026-08-05)

### Bug Fixes:

- Fix nginx [CVE-2026-42533](https://www.cve.org/CVERecord?id=CVE-2026-42533)  and [CVE-2026-56434](https://www.cve.org/CVERecord?id=CVE-2026-56434)  vulnerabilities.
- The maximum number of websites allowed in the ‌Community Edition‌ has been adjusted from ‌10‌ to ‌16‌.




## [7.2.4](https://github.com/Safe3/uusec-waf/compare/v7.2.4...v7.2.3) (2026-06-08)

### Bug Fixes:

- Fix the issue of certificate update failure.



## [7.2.3](https://github.com/Safe3/uusec-waf/compare/v7.2.3...v7.2.2) (2026-05-30)

### Feature Updates:

- Add the basic authentication plugin.

### Bug Fixes:

- Fix the issue that the IP threat intelligence plugin is not working.



## [7.2.2](https://github.com/Safe3/uusec-waf/compare/v7.2.2...v7.2.1) (2026-05-26)

### Bug Fixes:

- Fix nginx [CVE-2026-9256](https://www.cve.org/CVERecord?id=CVE-2026-9256) vulnerability.



## [7.2.1](https://github.com/Safe3/uusec-waf/compare/v7.2.1...v7.2.0) (2026-05-16)

### Bug Fixes:

- Fix several nginx vulnerabilities.



## [7.2.0](https://github.com/Safe3/uusec-waf/compare/v7.2.0...v7.1.2) (2026-03-18)

!> Attention: This version is incompatible with older versions and does not support direct upgrade from previous versions.

### Feature Updates:

- Supports log-only rule functionality, introducing three new rule constants: waf.RULE_BLOCK, waf.RULE_ALLOW, and waf.RULE_LOG_ONLY. When a rule returns these values, they represent block, allow, and log-only actions, respectively.



## [7.1.2](https://github.com/Safe3/uusec-waf/compare/v7.1.2...v7.1.1) (2026-03-09)

### Feature Updates:

- Added and updated more rules for latest threats.



## [7.1.1](https://github.com/Safe3/uusec-waf/compare/v7.1.1...v7.1.0) (2025-10-15)

### Feature Updates:

- Added 4 new search engine verification capabilities.

### Bug Fixes:

- Fixed an issue where search engine verification failures occurre.



## [7.1.0](https://github.com/Safe3/uusec-waf/compare/v7.1.0...v7.0.6) (2025-10-14)

### Feature Updates:

- **Enhanced plugin functionality**: Now supports setting plugin priority and controlling plugin behavior via return values. Each filter stage can return two boolean values:

    - If the **first value** is `true`, subsequent plugins in the current stage will **not be executed**.
    - If the **second value** is `true`, the system **immediately returns** and skips all subsequent security rules.

### Bug Fixes:

- Resolved an issue where **free SSL certificates failed to auto-renew**.



## [7.0.6](https://github.com/Safe3/uusec-waf/compare/v7.0.6...v7.0.5) (2025-09-13)


### Bug Fixes:

- Fixed display issues on certain screen resolutions



## [7.0.5](https://github.com/Safe3/uusec-waf/compare/v7.0.5...v7.0.4) (2025-09-10)


### Feature Updates:

- Optimized interface display, adjusted delete icon

### Bug Fixes:

- Fixed issue where cache acceleration cleanup didn't take effect in certain scenarios
- Fixed inability to use underscores in domain names when adding domains
- Fixed issue where IP threat intelligence plugin continued logging after triggering high-frequency attack rules



## [7.0.4](https://github.com/Safe3/uusec-waf/compare/v7.0.4...v7.0.3) (2025-08-19)


### Bug Fixes

- Fixed the issue of free certificate renewal failures



## [7.0.3](https://github.com/Safe3/uusec-waf/compare/v7.0.3...v7.0.2) (2025-07-18)


### Bug Fixes

- Resolved the problem that prevented viewing certain logs when the log level filter was set to 'Info'



## [7.0.2](https://github.com/Safe3/uusec-waf/compare/v7.0.2...v7.0.1) (2025-07-11)


### Bug Fixes

- Fixed slow website access caused by IP threat intelligence updates under poor network conditions
- Fixed error reporting issues with some frontend UI elements

### Improvements

- Update GEO IP database to the latest version



## [7.0.1](https://github.com/Safe3/uusec-waf/compare/v7.0.1...v7.0.0) (2025-07-05)


### Bug Fixes

- Fixed inability to modify DSL rules after adding them
- Fixed issue where HTTP/2 toggle didn't take effect
- Fixed incorrect regex pattern matching warning for cache acceleration paths



## [7.0.0](https://github.com/Safe3/uusec-waf/compare/v7.0.0...v6.8.0) (2025-07-01)


### Feature Updates  

**Interface & Management**

- Redesigned main program and management interface with improved aesthetics and usability, supports UI language switching (English/Chinese)
- Added Rule Collections functionality: Create custom rule templates for batch configuration
- Introduced whitelist rules that terminate further rule matching upon success
- UUSEC WAF Rules API intelligent suggestions during advanced rule editing
- New plugin management supporting hot-reloaded plugins to extend WAF capabilities

**Protocol & Optimization**
- Supports streaming responses for continuous data push (e.g., LLM stream outputs)
- Enables Host header modification during proxying for upstream service access
- Search engine validation: `waf.searchEngineValid(dns,ip,ua)` prevents high-frequency rules from affecting SEO indexing
- Interception log report generation (HTML/PDF exports)
- Automatic rotation of UUSEC WAF error/access logs to prevent performance issues

**Security & Infrastructure**

- Expanded free SSL certificate support: HTTP-01 & DNS-01 verification across 50+ domain providers
- Customizable advanced WAF settings: HTTP2, GZIP, HTTP Caching, SSL protocols, etc
- Cluster configuration: Manage UUSEC WAF nodes and ML servers via web UI




## [6.8.0 LTS](https://github.com/Safe3/uusec-waf/compare/v6.8.0...v6.7.0) (2025-04-18)


### Improvements

- New support for adding multiple domain names while creating new sites
- Added support for automatically creating uuwaf database structures
- Beautiful web management interface and optimized functionality

### Bugfix

- Resolve the host version authentication failure issue of reconnecting after disconnecting  database
- Fix nginx CVE-225-23419 vulnerability




## [6.7.0](https://github.com/Safe3/uusec-waf/compare/v6.7.0...v6.6.0) (2025-03-30)


### Improvements

- Added Lua advanced rule editor, supporting real-time auto-completion and code completion functions
- Added support for * certificates to wildcard all domain names, making it easier to access HTTPS content when certificates are missing
- Upgrade luajit to the latest version, enhance performance and fix bugs
- Added Tomcat RCE (CVE-2025-24813) vulnerability protection rule
- Docker version adds the UUWAF_DB_DSN environment variable to facilitate custom database connection information
- Further optimize the installation and use of Docker version scripts and configuration files
- Prevent the default rule from overwriting the custom rule, and adjust the starting value of the custom rule id range to 500



## [6.6.0](https://github.com/Safe3/uusec-waf/compare/v6.6.0...v6.5.0) (2025-02-24)


### Improvements

- Ordinary rules support organizing conditional relationships based on logical AND, OR, NOT AND, NOT OR.
- Introduce new abnormal cookie detection rule to block certain cookie attacks and prevent vulnerabilities from being bypassed.
- Enhance the webpage compatibility of the web management backend under different computer screen sizes.



## [6.5.0](https://github.com/Safe3/uusec-waf/compare/v6.5.0...v6.4.0) (2025-02-15)

### Improvements

- Support machine learning generated rules isolated by users
- Supports first level domain name extensions up to 16 characters in length

### Bugfix

- Fix the issue of misplaced display of custom regular rules in the web management
- Fix the issue where the internal network IP is displayed as empty in the attack area ranking



## [6.4.0](https://github.com/Safe3/uusec-waf/compare/v6.4.0...v6.3.0) (2025-02-03)

### Improvements

- Improve XSS security rules to reduce false positive

### Bugfix

- Fix the problem of database connection failure after system restart



## [6.3.0](https://github.com/Safe3/uusec-waf/compare/v6.3.0...v6.2.0) (2024-12-30)

### Improvements

- Upgrade command injection and SQL injection semantic detection engine to further improve detection rate and reduce false positives
- Optimize log management, add rule ID column for easy identification of specific intercepted rule numbers
- Upgrade multiple security rules to cover more security vulnerabilities and threats



## [6.2.0](https://github.com/Safe3/uusec-waf/compare/v6.2.0...v6.1.0) (2024-11-26)

### Improvements

- Fully support IPv6 network addresses and lift restrictions on upstream and IP whitelists for IPv6 addresses
- Upgrade the UUSEC WAF sliding and rotating image human-machine verification function, supporting cookie free mode and frequency limit
- Added Cloudflare Turnstile human-machine verification function, providing waf.checkTurnstile function

