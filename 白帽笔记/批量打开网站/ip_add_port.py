#-*-coding：utf-8-*-
#python3
#Written by hacden 2020/04/28
import os
ports = [
80,
443,
1081,
1083,
2601,
2604,
5984,
6379,
7001,
7100,
7118,
7000,
5900,
5632,
10000,
4848,
5000,
27017,
27018,
9200,
9300,
11211,
50000,
7080,
7090,
8001,
8081,
8079,
8088,
7011,
3128,
9080,
9098,
8002,
8000,
8003,
8082,
8800,
8087,
8888,
9999,
9100,
8080,
9001,
8090,
9000,
9907,
9090,
9002,
7002,
9029,
9200,
9095,
9300,
9096,
11211,
9544,
27017,
27018,
50000,
50070,
50030
]
def read_ip():
    print("正在生成ip加端口地址.....")
    with open("ip.txt","r") as rf:
        for ip_domain in rf.readlines():
            print("%s--->生成中"%str(ip_domain))
            port_add(ip_domain.strip())
        rf.close()
def port_add(ip_domain):
    for port in ports:
        ip_port = str(ip_domain) + ":" + str(port)
        write_txt(ip_port)
def write_txt(ip_port):
    with open("web.txt","a") as wf:
        wf.write(ip_port + "\n")

if __name__ == '__main__':
    os.remove("web.txt")
    read_ip()