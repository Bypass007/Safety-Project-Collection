### 项目介绍

这是一份开源安全项目清单，收集了一些比较优秀的开源安全项目，以帮助甲方安全从业人员构建企业安全能力。

这些开源项目，每一个都在致力于解决一些安全问题。

**项目收集的思路：**

一个是关注互联网企业/团队的安全开源项目，经企业内部实践，这些最佳实践值得借鉴。

一个是来自企业安全能力建设的需求，根据需求分类，如WAF、HIDS、Git监控等。

这个收集是一个长期的过程，我在GitHub创建了这个项目，专门用来收集一些优秀的甲方安全项目。还有很多很好的免费开源项目可供选择，下面列出的还只是其中很少的一部分，我将持续更新这个项目，欢迎Star。

### 项目内容

互联网企业/团队，如YSRC、宜信CESRC、陌陌MomoSecurity、VKSRC等。

根据企业安全能力建设的需求，大致可以分为如下几种类型：

**资产管理**

- [BlueKing CMDB](https://github.com/Tencent/bk-cmdb)：一个面向资产及应用的企业级配置管理平台。

- [OpsManage](https://github.com/bongmu/OpsManage)：一款代码部署、应用部署、计划任务、设备资产管理平台。

- [Assets View](https://github.com/Cryin/AssetsView)：资产发现、网络拓扑管理系统。

- [Ansible](https://www.ansible.com/)：一种集成 IT 系统的配置管理、应用部署、执行特定任务的开源平台。

- [Saltstack](https://docs.saltstack.com/en/latest/)：一个具备puppet与func功能为一身的集中化管理平台。

**漏洞管理**

- [insight](https://github.com/creditease-sec/insight)：洞察-宜信集应用系统资产管理、漏洞全生命周期管理、安全知识库管理三位一体的平台。

- [xunfeng](https://github.com/ysrc/xunfeng)：一款适用于企业内网的漏洞快速应急，巡航扫描系统。

- [SRCMS](https://github.com/martinzhou2015/SRCMS):企业应急响应与缺陷管理系统
。
- [laravel-src](https://github.com/233sec/laravel-src):基于 Laravel 的开源安全应急响应中心平台。

- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo):一个安全程序和漏洞管理工具。

- [Fuxi-Scanner](https://github.com/jeffzh3ng/Fuxi-Scanner)：一款开源的网络安全检测工具，适用于中小型企业对企业信息系统进行安全巡航检测。

- [SeMF](https://gitee.com/gy071089/SecurityManageFramwork)：企业内网安全管理平台，包含资产管理，漏洞管理，账号管理，知识库管、安全扫描自动化功能模块，可用于企业内部的安全管理。

**安全开发**

- [rhizobia_J](https://github.com/momosecurity/rhizobia_J)：JAVA安全SDK及编码规范。

- [rhizobia_P](https://github.com/momosecurity/rhizobia_P)：PHP安全SDK及编码规范。

**自动化代码审计**

- [fortify](http://www.fortify.net/)：静态代码扫描工具。【破解即免费】。

- [RIPS](http://rips-scanner.sourceforge.net/)：用于PHP脚本漏洞的静态源代码分析器。

- [OpenStack Bandit](https://github.com/openstack/bandit/releases/)：基于Python AST的静态分析器，用来查找Python代码中存在的通用安全问题的工具。

- [Cobra](https://github.com/WhaleShark-Team/cobra)：一款源代码安全审计工具，支持检测多种开发语言源代码中的大部分显著的安全问题和漏洞。

- [banruo](https://github.com/yingshang/banruo)：基于的fotify的自动化代码审计系统。

- [VCG：](https://sourceforge.net/projects/visualcodegrepp/)一种用于C++、C语言、VB、PHP、Java和PL/SQL的自动代码安全审查工具。

- [Find Security Bugs](https://find-sec-bugs.github.io/)：用于Java Web应用程序的安全审计。

**WAF**

- [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)：一个基于LUA-nginx的模块（openresty）的网络应用防火墙。

- [OpenRASP](https://rasp.baidu.com)：一款免费、开源的应用运行时自我保护产品。

- [ModSecurity](http://www.modsecurity.org/)：一个入侵侦测与防护引擎。

- [锦衣盾](http://www.jxwaf.com)：基于openresty(nginx+lua)开发的下一代web应用防火墙。

- [x-waf](https://github.com/xsec-lab/x-waf)：适用于中小企业的云waf 。

**堡垒机**

- [Jumpserver](https://github.com/jumpserver/jumpserver)：全球首款完全开源的堡垒机，是符合4A的专业运维审计系统。

- [teleport](https://tp4a.com/)：一款简单易用的开源堡垒机系统，支持RDP/SSH/SFTP/Telnet 协议的远程连接和审计管理。

- [CrazyEye](https://github.com/triaquae/CrazyEye)：基于Python的开发的一款简单易用的IT审计堡垒机。

- [gateone](https://github.com/liftoff/GateOne)：一款使用HTML5技术编写的网页版SSH终端模拟器。

- [JXOTP](https://github.com/jx-sec/jxotp)：一款企业SSH登陆双因素认证系统。

- [麒麟堡垒机](https://www.tosec.com.cn/)：开源版只支持一部分功能，剩下的功能需要购买。

**HIDS**

- [OSSEC](https://www.ossec.net)：一款开源的IDS检测系统，包括了日志分析、完整性检查、rook-kit检测，基于时间的警报和主动响应。

- [Wazuh](http://wazuh.com)：一个免费的，开源的企业级安全监控解决方案，用于威胁检测，完整性监控，事件响应和合规性。

- [Suricata](https://suricata-ids.org)：一个免费的开源，成熟，快速和强大的网络威胁检测引擎。

- [Snort](https://www.snort.org)：网络入侵检测和预防系统。

- [Osquery](https://osquery.io/):一个SQL驱动操作系统检测和分析工具。

- [Samhain Labs](https://www.la-samhna.de/)：用于集中式主机完整性监控的全面开源解决方案。

- [Firestorm](http://www.scaramanga.co.uk/firestorm/)：一种极高性能的网络入侵检测系统（NIDS）。

- [MozDef](https://github.com/mozilla/MozDef)：Mozilla防御平台,一套实时集成化平台，能够实现监控、反应、协作并改进相关保护功能。

- [驭龙HIDS](https://github.com/ysrc/yulong-hids)：开源的主机入侵检测系统。

- [AgentSmith-HIDS](https://github.com/DianrongSecurity/AgentSmith-HIDS)：轻量级的HIDS系统，低性能损失，使用LKM技术的HIDS工具。

- [Sobek-Hids](http://www.codeforge.cn/article/331327)：一个基于python的HostIDS系统。

- [Security Onion](https://securityonion.net/):免费开源网络安全监控系统。

- [OpenWIPS-ng](http://openwips-ng.org/)：一款开源的模块化无线IPS（Intrusion Prevention System，入侵防御系统）。

- [Moloch](https://www.dictionary.com/browse/moloch): 网络流量收集与分析。

**网络流量分析**

- [Zeek](https://www.zeek.org)：一个功能强大的网络分析框架。

- [Kismet](https://www.kismetwireless.net/)：一种无线网络和设备检测器，嗅探器，驱动工具和WIDS（无线入侵检测）框架。

**SIEM/SOC**

- [OSSIM](https://www.alienvault.com/products/ossim)：开源安全信息管理系统，它是一个开源安全信息和事件的管理系统，集成了一系列的能够帮助管理员更好的进行计算机安全，入侵检测和预防的工具。

- [Apache Metron](https://github.com/apache/metron)：一种网络安全应用程序框架，使组织能够检测网络异常并使组织能够快速响应已识别的异常情况。

- [SIEMonster](https://siemonster.com/)：以很小的成本监控整个网络。

- [w3a_SOC](https://github.com/smarttang/w3a_SOC)：Web日志审计与网络监控集合一身的平台。

- [OpenSOC](http://opensoc.github.io/)：致力于提供一个可扩展和可扩展的高级安全分析工具。

- [Prelude](https://www.prelude-siem.org/)：一个结合了其他各种开源工具的SIEM框架。

- [MozDef](https://github.com/jeffbryner/MozDef)：Mozilla防御平台,一套实时集成化平台，能够实现监控、反应、协作并改进相关保护功能。

**企业云盘**

- [KodExplorer](https://kodcloud.com/)：可道云，是基于Web技术的私有云在线文档管理解决方案。

- [Seafile](https://www.seafile.com/home/)：一款开源的企业云盘，注重可靠性和性能。

- [NextCloud](https://nextcloud.com/):一款开源网络硬盘系统。

- [owncloud](https://owncloud.com/products/)：一个基于Linux的开源云项目。

- [iBarn](http://www.godeye.org/code/ibarn)：基于PHP的开源网盘。

- [Cloudreve](http://cloudreve.org/)：以最低的成本快速搭建公私兼备的网盘系统。

- [Filebrowser](https://github.com/filebrowser/filebrowser/releases/latest)：一个基于GO的轻量级文件管理系统。

- [FileRun](https://filerun.com/)：一款强大的多功能网盘和文件管理器。

- [kiftd](https://github.com/KOHGYLW/kiftd)：一款专门面向个人、团队和小型组织的私有网盘系统。

**钓鱼网站系统**

- [HFish](https://github.com/hacklcx/HFish):一款基于 Golang 开发的跨平台多功能主动诱导型蜜罐框架系统。

- [mail_fishing](https://github.com/SecurityPaper/mail_fishing)： 基于thinkphp写的一个内部钓鱼网站系统。

- [Gophish](https://github.com/gophish/gophish)：开源钓鱼工具包。

- [BLACKEYE](https://github.com/thelinuxchoice/blackeye)：开源钓鱼工具包。

- [phishing](https://github.com/p1r06u3/phishing):甲方网络钓鱼的安全实践。

**安全运维**

- [Scout](https://github.com/HandsomeOne/Scout)： URL 监控系统。

- [OpenDnsdb](https://github.com/qunarcorp/open_dnsdb)：开源的基于Python语言的DNS管理系统 。

- [cuckoo](https://github.com/cuckoosandbox/cuckoo)：一个自动化的动态恶意软件分析系统。

- [theZoo](https://github.com/ytisf/theZoo)：一个恶意软件分析项目。

- [OpenDLP](https://code.google.com/archive/p/opendlp/)：一个免费的，开源的，基于代理和无代理的，集中管理，可大规模分发的数据丢失防护工具。

**GitHub监控**

- [GSIL](https://github.com/FeeiCN/GSIL)：GitHub敏感信息泄漏工具。

- [Hawkeye](https://github.com/0xbug/Hawkeye)：监控github代码库，及时发现员工托管公司代码到GitHub行为并预警，降低代码泄露风险。

- [x-patrol](https://github.com/MiSecurity/x-patrol)：GitHub的泄露扫描系统--MiSecurity。

- [Github-Monitor](https://github.com/VKSRC/Github-Monitor)：用于监控Github代码仓库的系统。

- [gshark](https://github.com/neal1991/gshark)：轻松有效地扫描Github中的敏感信息。

- [GitGuardian](https://www.gitguardian.com/)：实时扫描GitHub活动的解决方案。

**蜜罐技术**

- [T-Pot](https://github.com/dtag-dev-sec/tpotce/)：多蜜罐平台，可视化分析。

- [opencanary_web](https://github.com/p1r06u3/opencanary_web)：蜜罐的网络管理平台。

- [Honeyd](http://www.honeyd.org/)：一个小型守护进程，可以在网络上创建虚拟主机。

- [mhn](http://threatstream.github.io/mhn/)：现代蜜罐网络。

- [Glastopf](https://github.com/mushorg/glastopf)：Python Web应用程序蜜罐。

- [Cowrie](https://github.com/cowrie/cowrie)：一种中等交互式SSH和Telnet蜜罐，用于记录暴力攻击和攻击者执行的shell交互。

- [Kippo](https://github.com/desaster/kippo)：一个中等交互式SSH蜜罐，用于记录暴力攻击，最重要的是，攻击者执行的整个shell交互。

- [Dionaea](https://github.com/DinoTools/dionaea)：一个低交互的蜜罐，能够模拟FTP/HTTP/MSSQL/MYSQL/SMB等服务。

- [Conpot](https://github.com/mushorg/conpot)：一个ICS蜜罐，其目标是收集有关针对工业控制系统的敌人的动机和方法的情报。

- [Wordpot](https://github.com/gbrindisi/wordpot)：一个Wordpress蜜罐，可以检测用于指纹wordpress安装的插件，主题，timthumb和其他常用文件的探针。

- [elastichoney](https://github.com/jordan-wright/elastichoney)：一个简单的Elasticsearch蜜罐。

- [beeswarm](https://github.com/honeynet/beeswarm)：一个蜜罐项目，为蜜罐的配置、部署和管理提供了便利。

- [Shockpot](https://github.com/threatstream/shockpot)：一个Web应用程序蜜罐，旨在找到试图利用Bash远程代码漏洞的攻击者，CVE-2014-6271。


**风控系统**

- [TH-Nebula](https://github.com/threathunterX/nebula)：星云风控系统是一套互联网风控分析和检测平台。

- [Liudao](https://github.com/ysrc/Liudao)：六道”实时业务风控系统。

- [陌陌风控系统](https://github.com/momosecurity/aswan)：静态规则引擎，零基础简易便捷的配置多种复杂规则，实时高效管控用户异常行为。

- [Drools](https://www.drools.org)：基于java的功能强大的开源规则引擎。

------

### 学习交流

专注于网络安全，欢迎关注个人微信公众号：Bypass--，每周原创一篇技术干货。

![](https://bypass007.github.io/Emergency-Response-Notes/Summary/image/sum-erweima.jpg)
