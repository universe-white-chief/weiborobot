# -*- coding: utf-8 -*-
# 登录模块

import base64
import urllib
import sys
import rsa
import binascii
import re
import json
import requests

sys.path.append("..")
import config.myConfig as con

# encode username
def get_username(user_id):
    user_id_ = urllib.quote(user_id)
    su = base64.encodestring(user_id_)[:-1]
    return su

#encode password
def get_password_rsa(USER_PSWD, PUBKEY, servertime, nonce):
    rsa_pubkey = int(PUBKEY, 16)
    key_1 = int('10001', 16)
    key = rsa.PublicKey(rsa_pubkey, key_1)
    message = str(servertime) + "\t" + str(nonce) + "\n" + str(USER_PSWD)
    passwd = rsa.encrypt(message, key)
    passwd = binascii.b2a_hex(passwd)  # to 16
    return passwd

def get_parameter():
    name = con.USERID #set by your own
    password = con.PASSWD  #set by your own
    su = get_username(name)
    url = "https://login.sina.com.cn/sso/prelogin.php?entry=openapi&callback=sinaSSOController.preloginCallBack&su=" + su + "&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.15)"
    r = requests.get(url)
    p = re.compile('\((.*)\)')
    json_data = p.search(r.text).group(1)
    data = json.loads(json_data)
    PUBKEY = data['pubkey']
    servertime = str(data['servertime'])
    nonce = data['nonce']
    rsakv = str(data['rsakv'])
    sp = get_password_rsa(password, PUBKEY, servertime, nonce)
    return servertime, nonce, rsakv, sp, su

def get_ticket():
    servertime, nonce, rsakv, sp, su = get_parameter()
    header = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip,deflate,sdch',
        'Accept-Language': 'zh,en-US;q=0.8,en;q=0.6,zh-TW;q=0.4,zh-CN;q=0.2',
        'Connection': 'keep-alive',
        'Content-Length': '565',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': 'login.sina.com.cn',
        'Origin': 'https://api.weibo.com',
        'Referer': 'https://api.weibo.com/oauth2/authorize?redirect_uri='
                   +con.CALL_BACK+'&response_type=code&client_id='+con.APP_KEY,
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36'
    }
    content = {
        'entry': 'openapi',
        'gateway': '1',
        'from': None,
        'savestate': '0',
        'useticket': '1',
        'pagerefer': None,
        'ct': '1800',
        's': '1',
        'vsnf': '1',
        'vsnval': None,
        'door': None,
        'appkey': '3hXzQr',
        'su': su,
        'service': 'miniblog',
        'servertime': servertime,
        'nonce': nonce,
        'pwencode': 'rsa2',
        'rsakv': rsakv,
        'sp': sp,
        'sr': '1280*1024',
        'encoding': 'UTF-8',
        'cdult': '2',
        'domain': 'weibo.com',
        'prelt': '603',
        'returntype': 'TEXT'
    }
    url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.15)'
    r = requests.post(url=url, headers=header, data=content)
    json_data = r.text
    data = json.loads(json_data)
    ticket = data['ticket']
    return ticket

def get_code():
    ticket = get_ticket()
    header = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'https://api.weibo.com/oauth2/authorize?redirect_uri='
                   +con.CALL_BACK+'&response_type=code&client_id='+con.APP_KEY,
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36'
    }
    content = {
        'action': 'submit',
        'display': 'default',
        'withOfficalFlag': '0',
        'quick_auth': 'null',
        'withOfficalAccount': '',
        'scope': '',
        'ticket': ticket,
        'isLoginSina': '',
        'response_type': 'code',
        'regCallback': 'https://api.weibo.com/2/oauth2/authorize?'
                       'client_id=' + con.APP_KEY +
                       '&response_type=code&display=default&redirect_uri=' +
                       con.CALL_BACK + '&from=&with_cookie=',
        'redirect_uri': con.CALL_BACK,
        'client_id': con.APP_KEY,
        'appkey62': '3hXzQr',
        'state': '',
        'verifyToken': 'null',
        'from': '',
        'switchLogin': '0',
        'userId': con.USERID,
        'passwd': ""
    }
    login_url = 'https://api.weibo.com/oauth2/authorize'
    r = requests.post(login_url, data=content, headers=header, allow_redirects=False)
    return_redirect_uri = r.headers['location']
    print return_redirect_uri
    code = return_redirect_uri[32:]
    return code

if __name__ == "__main__":
    print get_code()