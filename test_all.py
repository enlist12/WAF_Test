import random
from random import *
from time import *
import requests
def get_random_ip():
    '''
    get random_ip
    :return: ipv4(str)
    '''
    return '.'.join(str(randint(0, 255)) for _ in range(4))

forbidden=0
Not_found=0
abnormal=0
code:int=0

def collect(code):
    if code==200:
        global abnormal
        abnormal+=1
    elif code==404:
        global Not_found
        Not_found+=1
    elif code==403:
        global forbidden
        forbidden+=1
    else:
        print(f"out of expected code {code}")

def print_res(url,code,url_len):
    str='-'*(url_len+4+10)
    print(str)
    print(f"url:{url.ljust(url_len,' ')}status:{code}")

def ending(num):
    str='-'*61
    global forbidden,abnormal,Not_found
    print(str)
    ss=f"Sum:{num}".ljust(15,' ')+f"forbid:{forbidden}".ljust(15,' ')+f'normal:{abnormal}'.ljust(15)+f'Not_found:{Not_found}'.ljust(16)
    print(ss)

def test_keyword(is_ua,is_rand_ip,data,sleep_time,times,host):
    headers:dict={}
    if is_ua==True:
        headers['User-Agent']="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
    for i in range(times):
        if is_rand_ip == True:
            headers['X-Forwarded-For'] = get_random_ip()
        value = random.choice(data)
        url = host + f"?id={value}"
        response = requests.get(url=url, headers=headers)
        code = response.status_code
        collect(code)
        print_res(url,code,60)
        '''
        To release the pressure of nginx
        '''
        sleep(sleep_time)
    ending(times)

def test_url(is_ua,is_rand_ip,data,sleep_time,times,host):
    headers:dict={}
    if is_ua==True:
        headers['User-Agent']="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
    for i in range(times):
        if is_rand_ip == True:
            headers['X-Forwarded-For'] = get_random_ip()
        value = random.choice(data)
        url = host + value
        response = requests.get(url=url, headers=headers)
        code = response.status_code
        collect(code)
        print_res(url,code,60)
        '''
        To release the pressure of nginx
        '''
        sleep(sleep_time)
    ending(times)