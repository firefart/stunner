#!/usr/bin/env python3

# pip3 install websocket-client requests

import requests
import sys
from websocket import create_connection
import argparse
import ssl
import json
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class Jabber():

    proxies = {
        # "http": "http://localhost:8080",
        # "https": "http://localhost:8080",
    }

    def getCookies(self):
        cookie_dict = self.s.cookies.get_dict(domain=domain_no_scheme)
        found = ['%s=%s' % (name, value)
                 for (name, value) in cookie_dict.items()]
        return ';'.join(found)

    def __init__(self):
        self.base = domain
        self.s = requests.Session()

    def csrf_header(self):
        if 'CMA-XSRF-TOKEN' in self.s.cookies:
            self.s.headers.update(
                {'CSRF-Token': self.s.cookies['CMA-XSRF-TOKEN']})

    def get(self, url, params=None, header=None):
        self.csrf_header()
        resp = self.s.get(self.base + url, params=params,
                          verify=False, proxies=self.proxies, headers=header)
        if resp is None:
            return None
        # print(resp.status_code)
        # print(resp.text)
        return resp.text

    def post_plain(self, url, data):
        self.csrf_header()
        resp = self.s.post(self.base + url, data=data,
                           verify=False, proxies=self.proxies)
        if resp is None:
            return None
        # print(resp.status_code)
        # print(resp.text)
        return resp.text

    def post_json(self, url, json_in):
        self.csrf_header()
        resp = self.s.post(self.base + url, json=json_in,
                           verify=False, proxies=self.proxies)
        if resp is None:
            return None

        try:
            j = resp.json()
            return j
        except json.decoder.JSONDecodeError:
            return resp.text


parser = argparse.ArgumentParser(description='Get expressway credentials')
parser.add_argument('--domain', dest='domain', type=str, required=True,
                    help='the domain including the scheme ex https://example.com')
parser.add_argument('--telephonenumber', dest='number', type=str, required=True,
                    help='a valid telephone number on the server')

args = parser.parse_args()
domain = args.domain
domain_no_scheme = domain.replace('http://', '').replace('https://', '')
number = args.number

j = Jabber()
# get initial session
resp = j.get('/')
if resp is None:
    sys.exit()

number = str(number)
displayname = "⚠"

data = {"numericId": number, "secret": None, "passcode": None}
resp = j.post_json('/api/v1/search-guest-conference', data)
if resp is None:
    sys.exit()

if "token" not in resp:
    print(resp)
    sys.exit(1)

token = resp["token"]

data = {"numericId": number, "secret": None, "passcode": None,
        "displayName": displayname, "token": token}
resp = j.post_json('/api/v1/guest-register', data)
if resp is None:
    sys.exit()
username = resp["username"]
password = resp["password"]

data = {"username": username,
        "password": password}
resp = j.post_json('/api/v1/login', data)
if resp is None:
    sys.exit()
status = resp["result"]
if status != "success":
    sys.exit()

# debug output
# resp = j.post_json('/api/v1/session/diagnostics', {'diagnostics': 'all'})
# print(resp)

resp = j.get('/api/v1/streams')
if resp is None:
    sys.exit()

data = {"subscriptions": []}
resp = j.post_json('/api/v1/streams', data)
if resp is None:
    sys.exit()
if status != "success":
    sys.exit()
id = resp["id"]

headers = {'Sec-WebSocket-Protocol': j.s.cookies['CMA-XSRF-TOKEN']}
ws = create_connection(
    f"wss://{domain_no_scheme}/api/v1/streams/{id}/updates",
    cookie=j.getCookies(),
    header=headers,
    sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False})
ws.settimeout(2)
recv_result = ws.recv()
j = json.loads(recv_result)
ws.close()
print(j[0]['webRtcMediaConfiguration'])
