#!/bin/env python3
import os
import requests
from concurrent.futures.thread import ThreadPoolExecutor


def DD():
    res = requests.get("https://www.baidu.com", verify=False)
    print(res.headers)

#with ThreadPoolExecutor(3) as e:
#    for i in range(3):
#        e.submit(DD)

DD()
