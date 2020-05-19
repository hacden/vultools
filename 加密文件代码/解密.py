#-*- coding=utf-8 -*-
#Wirtten by Hacden 2020/3/15
import os
import random
import sys
import uuid


class DECRYPT_FILE():
    def __init__(self):
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        myaddr = "_".join([mac[e:e + 2] for e in range(0, 11, 2)])
        self.key_name = [myaddr + "_key",myaddr+"_被加密的文件.txt"]
        self.crypt_dir = "./"
        self.output_name = ".txt"
        self.exec_file = sys.argv[0].split('\\')[-1]

    # 读取秘钥文件
    def __get_key(self):
        f_key = open(self.key_name[0], 'rb')
        by_key = f_key.read()
        f_key.close()
        return by_key

    # 加密算法
    def __decrypt(self,by_key,input_name):
        #定义解密后的文件名
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
    def __get_dir_file_decode(self,by_key):
        file_list = os.listdir(self.crypt_dir)
        file_count = len(file_list)
        for i in range(file_count):
            input_d = os.path.join(self.crypt_dir, file_list[i])
            input_name = input_d.split('/')[-1]
            if input_name == self.key_name[0] or input_name == self.key_name[1] or input_name == self.exec_file:
                continue
            # 解密
            self.__decrypt(by_key,input_name)

    #重命名文件
    def __re_filename(self):
        with open(self.key_name[1], 'r') as fN:
            for fl in fN.readlines():
                fL = fl.split('/')[-1]
                ming = fL.split('.')[0].strip()
                houzhui = fL.split('.')[-1].strip()
                ffff = self.crypt_dir + ming
                if houzhui == "exe":
                    os.rename(ffff + ".txt", ffff + ".exe")
                if houzhui == "jpg":
                    os.rename(ffff + ".txt", ffff + ".jpg")
                if houzhui == "txt":
                    os.rename(ffff + ".txt", ffff + ".txt")
                if houzhui == "html":
                    os.rename(ffff + ".txt", ffff + ".html")
                if houzhui == "lnk":
                    os.rename(ffff + ".txt", ffff + ".lnk")
                if houzhui == "pdf":
                    os.rename(ffff + ".txt", ffff + ".pdf")
                if houzhui == "doc":
                    os.rename(ffff + ".txt", ffff + ".doc")
                if houzhui == "docx":
                    os.rename(ffff + ".txt", ffff + ".docx")
                if houzhui == "vbs":
                    os.rename(ffff + ".txt", ffff + ".vbs")
    def run(self):
        if os.path.exists(self.key_name[0]) and os.path.exists(self.key_name[1]):
            by_key = self.__get_key()
            self.__get_dir_file_decode(by_key)
            self.__re_filename()
            print('解密完成！')
            # 删除秘钥文件\删除被加密文件
            for dl in self.key_name:
                os.remove(dl)
            #删除自身
            os.remove(self.exec_file)
        else:
            print("%s和%s文件不存在，需要同时存在才可解密！"%(self.key_name[0],self.key_name[1]))
            exit(0)


if __name__ == '__main__':
    decrypt_file = DECRYPT_FILE()
    decrypt_file.run()
