#!/bin/env python3
import os
import requests
from concurrent.futures.thread import ThreadPoolExecutor


def DD():
    res = requests.get("https://www.baidu.com")
    print(res.headers)

with ThreadPoolExecutor(4) as e:
    for i in range(3):
        e.submit(DD)

