# -*- coding:utf-8 -*-
#! python3
import sys
import os
try:
	a=0
	readDir = sys.argv[1]  #old
	writeDir = sys.argv[1] + "hacden" #new
	if len(sys.argv) == 2:
		lines_seen = set()
		outfile = open(writeDir, "w")
		f = open(readDir, "r",encoding='gbk',errors='ignore')
		for line in f:
			#没有在set集合中就添加进集合
			if line not in lines_seen:
				outfile.write(line)
				lines_seen.add(line)
			#有在里面就打印出重复数据
			else:
				a += 1
				sys.stdout.write("重复的数据：%s"%line)
		outfile.close()
		f.close()
		sys.stdout.write("重复了:%d"%a)
		os.remove(readDir)
		os.rename(writeDir,sys.argv[1].split('/')[-1])
except:
	sys.stdout.write("使用：%s 目标文件"%(sys.argv[0]))
