import argparse
from test_all import *

def get_filename(mod):
    return f'{mod}/{mod}.txt'


parser= argparse.ArgumentParser()

parser.add_argument("-s","--host",type=str,help="Host you want to attack",required=True)
#parser.add_argument("-p", "--port", type=int, help="please input port",required=True)
parser.add_argument("-m", "--mod", type=str, help="Brute mod which in (keyword,url)",required=True)
parser.add_argument("-f","--file",type=str,help="Attack data")
parser.add_argument("-n","--num",type=int,help="Attack times",default=1000)
'''
For nginx,we have no idea to make fake ip.So random_ip is for X-Forwarded-For
'''
parser.add_argument("-i","--ips",action="store_true",help="Turn on random ip")
parser.add_argument("-u","--ua",action="store_true",help="Turn on normal UA")
parser.add_argument('-t','--time',help="sleep time each request",default=0.1)

args=parser.parse_args()

#print(type(args))
filename=''

print('[+] Parsing arguments')

host=args.host
mod=args.mod
num=args.num
tm=args.time

if mod not in ['keyword','url']:
    print('[+] Mod not in range')
    exit(0)


if args.file:
    filename=args.text
else:
    filename=get_filename(args.file)


'''
standard url
http://47.108.180.126/index.html?id=434655464
'''

with open(filename, 'r') as file:
    data = file.readlines()

data = [line.strip() for line in data]



if mod=='keyword':
    test_keyword(data=data,sleep_time=tm,times=num,url=host,is_ua=args.ua,is_rand_ip=args.ips)
elif mod=='url':
    test_url(data=data,sleep_time=tm,times=num,url=host,is_ua=args.ua,is_rand_ip=args.ips)








