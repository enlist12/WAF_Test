from random import *
import requests
import argparse
from time import *

def get_random_ip():
    return '.'.join(str(randint(0, 255)) for _ in range(4))

parser= argparse.ArgumentParser()

parser.add_argument("-s","--host",type=str,help="Host you want to attack",required=True)
#parser.add_argument("-p", "--port", type=int, help="please input port",required=True)
parser.add_argument("-m", "--mod", type=str, help="Brute mod which in (keyword,url)",required=True)
parser.add_argument("-t","--text",type=str,help="Attack data")
parser.add_argument("-n","--num",type=int,help="Attack times",default=1000)
'''
For nginx,we have no idea to make fake ip.So random_ip is for X-Forwarded-For
'''
parser.add_argument("-y","--ips",action="store_true",help="Turn on random ip")
parser.add_argument("-f","--foo",action="store_true",help="Turn on normal UA")

args=parser.parse_args()

#print(type(args))
filename=''

print('[+] Parsing arguments')

host=args.host
mod=args.mod
num=args.num

if args.text:
    filename=args.text
else:
    if mod=='url':
        filename='url/url.txt'
    elif mod=='keyword':
        filename='keyword/keyword.txt'
    else:
        print("[+] mod argument should in (keyword,url)!!!")
        exit(0)


'''
standard url
http://47.108.180.126/index.html?id=434655464
'''

with open(filename, 'r') as file:
    data = file.readlines()

data = [line.strip() for line in data]

rang=len(data)
code:int=0
ip:str=''
forbidden=0
Not_found=0
abnormal=0

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

headers:dict={}

if mod=='keyword':
    if args.foo==True:
        headers['User-Agent']="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
    for i in range(num):
        if args.ips == True:
            headers['X-Forwarded-For'] = get_random_ip()
        value = data[randint(0, rang - 1)]
        url = host + f"?id={value}"
        response = requests.get(url=url, headers=headers)
        code = response.status_code
        collect(code)
        print("--------------------------------------------------------------")
        print(f"url:{url}      status:{code}")
        '''
        To release the pressure of nginx
        '''
        sleep(0.5)
else:
    if args.foo == True:
        headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
    for i in range(num):
        if args.ips==True:
            headers['X-Forwarded-For']=get_random_ip()
        value=data[randint(0,rang-1)]
        url=host+value
        response=requests.get(url=url,headers=headers)
        code=response.status_code
        collect(code)
        print("--------------------------------------------------------------")
        print(f"url:{url}     status:{code}")
        '''
        To release the pressure of nginx
        '''
        sleep(0.5)

print("----------------------------------------------------")
print(f"test end: 200:{abnormal}     403:{forbidden}    404:{Not_found}")








