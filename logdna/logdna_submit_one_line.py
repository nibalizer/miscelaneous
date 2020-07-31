# This script submits a single log line to logdna
# see 'msg' below

# Heavily hacked up from github.com/logdna/python

# LICENSE: MIT
# (c) LogDNA & IBM


import requests
import time
import os

key = os.environ.get("LOGDNA_KEY")
# e.g. "https://logs.us-south.logging.cloud.ibm.com/logs/ingest"
# default is https://logs.logdna.com/logs/ingest
url = os.environ.get("LOGDNA_URL") 

options = {
          'hostname': 'pytest',
          'ip': '10.0.1.1',
          'mac': 'C0:FF:EE:C0:FF:EE',
          'url': url
         }

# Defaults to False; when True meta objects are searchable
options['index_meta'] = True
msg = '{"a": "b", "data": "yes"}'
level = "WARNING"

MAX_LINE_LENGTH = 32000

message = {
    'hostname': options['hostname'],
    'timestamp': int(time.time() * 1000),
    'line': msg,
    'level': level,
    'app': 'falco',
    'env': 'devtest'
}

msgs = [message]

data = {'e': 'ls', 'ls': msgs}



res = requests.post(
   url=url,
   json=data,
   auth=('user', key),
   params={
       'hostname': options['hostname'],
       'ip': options['ip'],
       'mac': options['mac'],
       'tags': None},
   stream=True,
   timeout=30,
   headers={'user-agent': "python/falco"} 
   )
res.raise_for_status()
print(res.status_code)
# when no RequestException happened
