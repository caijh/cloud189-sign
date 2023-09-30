import base64
import re
import requests
import rsa
import time
import argparse

argParser = argparse.ArgumentParser()
argParser.add_argument("--username", help="username")
argParser.add_argument("--password", help="password")
args = vars(argParser.parse_args())

s = requests.Session()
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0"

username = ""
password = ""
g_conf = {}


def get_input(name, txt):
    if args[name]:
        return args[name]
    else:
        input(txt)


if username == "" or password == "":
    username = get_input("username", "账号：")
    password = get_input("password", "密码：")


def main():
    msg = login(username, password)
    if msg == "error":
        return None
    else:
        pass
    rand = str(round(time.time() * 1000))
    sign_url = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
    url = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN'
    url2 = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
        "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host": "m.cloud.189.cn",
        "Accept-Encoding": "gzip, deflate",
    }
    # 签到
    response = s.get(sign_url, headers=headers)
    net_disk_bonus = response.json()['netdiskBonus']
    print(f"签到获得{net_disk_bonus}M空间")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
        "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host": "m.cloud.189.cn",
        "Accept-Encoding": "gzip, deflate",
    }
    # 第一次抽奖
    response = s.get(url, headers=headers)
    print_prize_name(response)
    # 第二次抽奖
    response = s.get(url2, headers=headers)
    print_prize_name(response)


def print_prize_name(response):
    if "prizeName" in response.text:
        prize_name = response.json()['prizeName']
        print(f"抽奖获得{prize_name}")
    else:
        try:
            if response.json()['errorCode'] == "User_Not_Chance":
                print("抽奖次数不足")
            else:
                print(response.text)
        except:
            print(str(response.status_code) + response.text)


BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")


def int2char(a):
    return BI_RM[a]


b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64_to_hex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = b64map.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d


def rsa_encode(string):
    global g_conf
    j_rsa_key = g_conf['pubKey']
    rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsa_key}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64_to_hex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
    return result


def get_encrypt():
    url = "https://open.e.189.cn/api/logbox/config/encryptConf.do"
    data = {
        "appKey": "cloud",
        "version": "2.0"
    }
    r = s.post(url, data, None, timeout=5)
    if r.json()['result'] == 0:
        print(r.json()['data'])
    else:
        print(r.json()['msg'])
        return "error"


def load_app_conf(r):
    global g_conf
    g_conf["lt"] = re.findall(r"lt=([a-zA-Z0-9]+)", r.url)[0]
    g_conf["reqId"] = re.findall(r"reqId=([a-zA-Z0-9]+)", r.url)[0]

    r = s.post(
        "https://open.e.189.cn/api/logbox/oauth2/appConf.do",
        data={
            "version": "2.0",
            "appKey": "cloud",
        },
        headers={
            "referer": f"https://open.e.189.cn/api/logbox/separate/web/index.html?appId=cloud&lt={g_conf['lt']}&reqId={g_conf['reqId']}",
            "lt": g_conf["lt"],
            "reqid": g_conf["reqId"],
            "origin": "https://open.e.189.cn",
            "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6",
        },
    ).json()
    g_conf.update(r["data"])


def load_rsa_key():
    global g_conf
    r = s.post(
        "https://open.e.189.cn/api/logbox/config/encryptConf.do", {"appId": "cloud"}
    ).json()
    g_conf["pubKey"] = r["data"]["pubKey"]


def login(username, password):
    url = "https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html?returnURL=/main.action"
    r = s.get(url)

    load_app_conf(r)

    load_rsa_key()
    _username = rsa_encode(username)
    _password = rsa_encode(password)

    url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    headers = {
        "User-Agent": ua,
        "Referer": "https://open.e.189.cn/",
        "lt": g_conf["lt"],
        "REQID": g_conf["reqId"]
    }
    data = {
        "appKey": "cloud",
        "accountType": "01",
        "version": "2.0",
        "userName": f"{{NRP}}{_username}",
        "password": f"{{NRP}}{_password}",
        "validateCode": "",
        "captchaToken": "",
        "returnUrl": g_conf["returnUrl"],
        "mailSuffix": g_conf["mailSuffix"],
        "paramId": g_conf["paramId"],
        "dynamicCheck": "FALSE",
        "clientType": "1",
        "cb_SaveName": "0",
        "isOauth2": False,
    }
    r = s.post(url, data=data, headers=headers, timeout=5)
    if r.json()['result'] == 0:
        print(r.json()['msg'])
    else:
        print(r.json()['msg'])
        return "error"
    redirect_url = r.json()['toUrl']
    r = s.get(redirect_url)
    return s


if __name__ == "__main__":
    main()
