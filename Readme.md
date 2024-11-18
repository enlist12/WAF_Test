# WAF_Test

此项目用于nginx防火墙测试，waf1为普通防火墙，拥有各种指令进行URL拦截，IP拦截等(具体功能可查看源码)。

waf2为修改后的防火墙，IP地址从X-Forwarded-For字段中提取。

request.py为爆破脚本，具体配置可通过

~~~
python3 request.py -h
~~~

查看，暂时只支持URL爆破和关键词爆破。

注意，本项目用于防火墙测试，所以默认数据文件中包含很多正常请求