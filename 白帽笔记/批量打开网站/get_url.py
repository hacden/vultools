#-*- coding:utf-8 -*-
from selenium import webdriver   # 导入webdriver包
import time
import requests
import threading
import queue
import random
import sys

urls = []
def open_web():
	#设置线程3
	concurrent = 15
	#生成请求对列
	req_list = queue.Queue()
	try:
		print("正在准备测试可访问的url,请等待....")
		for i in range(21):
			if i != 20:
				print(">>",end="")
			else:
				print(">>")
			sys.stdout.flush()
			time.sleep(0.2)
		with open("web.txt","r") as webs:
			for url in webs.readlines():
				url = url.strip()
				#添加进对列
				req_list.put(url)
			webs.close()
		# 生成N个采集线程
		req_thread = []
		for num in range(concurrent):
				#创造线程
				t = threading.Thread(target=get_web,args=(num,req_list))
				t.start()
				req_thread.append(t)
		for t in req_thread:
			#等待线程结束
			t.join()
	except Exception as e:
		print("web.txt文件不存在,3秒退出")
		time.sleep(3)
		exit(0)
		
		
def get_web(num,req_list):
	print("启动请求线程%d号"%(num+1))
	# 如果请求队列不为空，则无限循环从请求队列里拿请求url
	while req_list.qsize() > 0:
		try:
			url = req_list.get()
			# 防止请求频率过快，随机设置阻塞时间
			time.sleep(random.randint(1,3))
			header = {}
			header["User-Agent"]="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"
			resp = requests.get("http://%s"%url,headers=header,timeout=4)
			if int(resp.status_code) == 200 or int(resp.status_code) == 403:
				urls.append(url)
		except:
			pass

def read_file(drFirefox):
	i = 0
	for url in urls:
		if url != "":
			get_url(url.strip(),drFirefox)
			i += 1
		print("第%d个url是----> %s"%(i,"http://"+url))

def get_url(url,drFirefox):
	try:
		#新标签打开
		js = 'window.open("%s")'%('http://'+url)
		drFirefox.execute_script(js)
		time.sleep(3)
	except:
		pass
def run():
	open_web()
	if len(urls) == 0:
		print("-"*100)
		print("没有可以访问的url,3秒退出！")
		time.sleep(3)
		exit(0)
	print("------------->检测完成,即将自动打开浏览器进行访问<-------------")
	driver_path = "geckodriver.exe"
	drFirefox = webdriver.Firefox(executable_path=driver_path)  # 初始化一个火狐浏览器实例：driver
	drFirefox.set_page_load_timeout(5)
	drFirefox.set_script_timeout(5)
	read_file(drFirefox)
	
if __name__=="__main__":
	run()