#!/bin/python3
# -*- coding: utf-8 -*-

import urllib.request
import time
while True:
    try:
        para = urllib.parse.urlencode({'method':'writeip'});
        req = urllib.request.urlopen("http://www.after1990s.info/reportip/reportip.php?%s" % para)
        req.read()
        
        time.sleep(180)
    except Exception as e:
        pass