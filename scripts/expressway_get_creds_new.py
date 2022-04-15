#!/usr/bin/env python3

# pip3 install requests

import requests
import sys
import argparse
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Get expressway credentials')
parser.add_argument('--domain', dest='domain', type=str, required=True,
                    help='the domain including the scheme ex https://example.com')
parser.add_argument('--telephonenumber', dest='number', type=str, required=True,
                    help='a valid telephone number on the server')

args = parser.parse_args()
domain = args.domain
number = args.number

j = requests.Session()
# get initial session
resp = j.get(f'{domain}/')
if resp is None:
    sys.exit()

number = str(number)
displayname = "⚠"


data = {"numericId": number, "passcode": ""}
resp = j.post(f'{domain}/api/lookup', json=data)
if resp is None:
    sys.exit()

if resp.status_code == 400:
    print(resp.text)
    print("Invalid telephone number provided")
    sys.exit(1)

data = {"numericId": number, "passcode": "", "trace": "false",
        "displayName": displayname, "userAgent": "stunner"}
resp = j.post(f'{domain}/api/join', json=data)
if resp is None:
    sys.exit()

x = resp.json()

for y in x["turnServers"]:
    print(y)
