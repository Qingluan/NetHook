#!/bin/env python3
import os
import requests



res = requests.get("https://www.baidu.com")
print(res.headers)