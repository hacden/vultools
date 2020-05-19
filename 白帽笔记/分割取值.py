#-*- coding:utf-8 -*-
#Written by hacden 2020/04/26
import argparse

w_names = []
def read_file(re_file,sp_arg,num):
    #接收读取的文件参数
    with open(re_file,"r") as rf:
        r_lists = rf.readlines()
        for r_name in r_lists:
            #获取分割符和地标
            w_name = r_name.strip().split('%s'%sp_arg)[num-1]
            if w_name != "":
                print(w_name)
                w_names.append(w_name)
    rf.close()
def write_file(out_file):
    with open(out_file,"w") as wf:
        for w_name in w_names:
            wf.write(w_name + "\n")
    wf.close()


def run():
    try:
        parse = argparse.ArgumentParser()
        parse.add_argument("-f",type=str,help="Please input tarket file.")
        parse.add_argument("-c",type=str,help="Please input split char.")
        parse.add_argument("-l", type=int,default=1,help="Can you input char length? default is 1.")
        parse.add_argument("-n",type=int,help="Please input num,example 1.")
        parse.add_argument("-o",type=str,help="Please input output file.")
        args = parse.parse_args()
        re_file = args.f
		#获取输入的分割字符的长度
        sp_arg = args.c*args.l
        num = args.n
        out_file = args.o
        print("The split string is \"%s\""%sp_arg)
        read_file(re_file,sp_arg,num)
        write_file(out_file)
    except:
        exit(0)
if __name__ == '__main__':
    run()
