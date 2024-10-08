import re
import time
import requests
import hashlib
import json
from time import time
from time import sleep
from hashlib import md5
from copy import deepcopy
from random import choice
import random
from urllib.parse import quote
import binascii


def GET(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
        'Accept': 'application/json, text/javascript',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    return requests.get(url, headers=headers)


def GET_h(url, ttwid, passport_csrf_token):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
        'Accept': 'application/json, text/javascript',
        'Content-Type': 'application/x-www-form-urlencoded',
        'cookie': f'ttwid={ttwid}; passport_csrf_token={passport_csrf_token};',
        'x-tt-passport-csrf-token': f'{passport_csrf_token}'
    }
    return requests.get(url, headers=headers)


def convert_escape_sequence(s):
    return s.encode().decode('unicode_escape')


def short_url(url_to_short):
    url = "https://www.tiktok.com/shorten/?aid=1988"
    payload = {
        'targets': url_to_short,
        'belong': 'tiktok-webapp-qrcode'
    }
    response = requests.post(url, data=payload)
    url_shorten_list = re.findall(r'"short_url":"(.*?)"', response.text)
    url_shorten = url_shorten_list[0] if url_shorten_list else None
    return url_shorten


def get_qrcode_url():
    url = "https://www.tiktok.com/passport/web/get_qrcode/?next=https://www.tiktok.com&aid=1459"
    response = requests.post(url)
    cookies = response.cookies

    passport_csrf_token = cookies.get('passport_csrf_token')
    ttwid = GET('https://www.tiktok.com/login/qrcode')
    ttwid = ttwid.cookies.get('ttwid')

    token_match = re.search(r'"token":"(.*?)"', response.text)
    qrcode_index_url_match = re.search(r'"qrcode_index_url":"(.*?)"', response.text)

    token = token_match.group(1) if token_match else None
    qrcode_index_url = qrcode_index_url_match.group(1) if qrcode_index_url_match else None
    qrcode_index_url = convert_escape_sequence(qrcode_index_url)

    shorten_url = short_url(qrcode_index_url)
    print("Go to this url:", f"https://api.qrserver.com/v1/create-qr-code/?&data={shorten_url}")
    return token, ttwid, passport_csrf_token, shorten_url


def get_session_id():
    try:
        token, ttwid, passport_csrf_token, shorten_url = get_qrcode_url()
        while True:
            qr_check = GET_h(
                f'https://web-va.tiktok.com/passport/web/check_qrconnect/?next=https%3A%2F%2Fwww.tiktok.com&token={token}&aid=1459',
                ttwid, passport_csrf_token)
            if "scanned" in qr_check.text:
                print("Waiting for your confirmation!")
            elif "confirmed" in qr_check.text:
                sessionid = qr_check.cookies.get('sessionid')
                break
            elif "expired" in qr_check.text:
                token, ttwid, passport_csrf_token, shorten_url = get_qrcode_url()
                print("URL has been updated!")
            sleep(0.7)

        if sessionid:
            return sessionid
        else:
            print("Failed to retrieve session ID.")
    except Exception as error:
        print(f"ERROR: {error}")


def hex_string(num):
    tmp_string = hex(num)[2:]
    if len(tmp_string) < 2:
        tmp_string = '0' + tmp_string
    return tmp_string


def RBIT(num):
    result = ''
    tmp_string = bin(num)[2:]
    while len(tmp_string) < 8:
        tmp_string = '0' + tmp_string
    for i in range(0, 8):
        result = result + tmp_string[7 - i]
    return int(result, 2)


def file_data(path):
    with open(path, 'rb') as f:
        result = f.read()
    return result


def reverse(num):
    tmp_string = hex(num)[2:]
    if len(tmp_string) < 2:
        tmp_string = '0' + tmp_string
    return int(tmp_string[1:] + tmp_string[:1], 16)


class XG:
    def __init__(self, debug):
        self.length = 0x14
        self.debug = debug
        self.hex_CE0 = [0x05, 0x00, 0x50, choice(range(0, 0xFF)), 0x47, 0x1e, 0x00, choice(range(0, 0xFF)) & 0xf0]

    def addr_BA8(self):
        tmp = ''
        hex_BA8 = []
        for i in range(0x0, 0x100):
            hex_BA8.append(i)
        for i in range(0, 0x100):
            if i == 0:
                A = 0
            elif tmp:
                A = tmp
            else:
                A = hex_BA8[i - 1]
            B = self.hex_CE0[i % 0x8]
            if A == 0x05:
                if i != 1:
                    if tmp != 0x05:
                        A = 0
            C = A + i + B
            while C >= 0x100:
                C -= 0x100
            if C < i:
                tmp = C
            else:
                tmp = ''
            D = hex_BA8[C]
            hex_BA8[i] = D
        return hex_BA8

    def initial(self, debug, hex_BA8):
        tmp_add = []
        tmp_hex = deepcopy(hex_BA8)
        for i in range(self.length):
            A = debug[i]
            if not tmp_add:
                B = 0
            else:
                B = tmp_add[-1]
            C = hex_BA8[i + 1] + B
            while C >= 0x100:
                C -= 0x100
            tmp_add.append(C)
            D = tmp_hex[C]
            tmp_hex[i + 1] = D
            E = D + D
            while E >= 0x100:
                E -= 0x100
            F = tmp_hex[E]
            G = A ^ F
            debug[i] = G
        return debug

    def calculate(self, debug):
        for i in range(self.length):
            A = debug[i]
            B = reverse(A)
            C = debug[(i + 1) % self.length]
            D = B ^ C
            E = RBIT(D)
            F = E ^ self.length
            G = ~F
            while G < 0:
                G += 0x100000000
            H = int(hex(G)[-2:], 16)
            debug[i] = H
        return debug

    def main(self):
        result_str = ''
        for item in self.calculate(self.initial(self.debug, self.addr_BA8())):
            result_str += hex_string(item)

        return '8404{}{}{}{}{}'.format(hex_string(self.hex_CE0[7]), hex_string(self.hex_CE0[3]),
                                       hex_string(self.hex_CE0[1]), hex_string(self.hex_CE0[6]), result_str)


def X_Gorgon(param, data, cookie):
    gorgon = []
    ttime = time()
    Khronos = hex(int(ttime))[2:]
    url_md5 = md5(bytearray(param, 'utf-8')).hexdigest()

    for i in range(4):
        gorgon.append(int(url_md5[2 * i:2 * i + 2], 16))

    if data:
        if isinstance(data, str):
            data = data.encode(encoding='utf-8')
            data_md5 = md5(data).hexdigest()
            for i in range(4):
                gorgon.append(int(data_md5[2 * i:2 * i + 2], 16))
    else:
        for i in range(4):
            gorgon.append(0x00)

    if cookie:
        cookie_md5 = md5(bytearray(cookie, 'utf-8')).hexdigest()
        for i in range(4):
            gorgon.append(int(cookie_md5[2 * i:2 * i + 2], 16))
    else:
        for i in range(4):
            gorgon.append(0x00)

    gorgon = gorgon + [0x01, 0x01, 0x02, 0x04]

    for i in range(4):
        gorgon.append(int(Khronos[2 * i:2 * i + 2], 16))

    return {'X-Gorgon': XG(gorgon).main(), 'X-Khronos': str(int(ttime))}


def run(param="", stub="", cookie=""):
    gorgon = []
    ttime = time()
    Khronos = hex(int(ttime))[2:]
    url_md5 = md5(bytearray(param, 'utf-8')).hexdigest()

    for i in range(4):
        gorgon.append(int(url_md5[2 * i:2 * i + 2], 16))

    if stub:
        data_md5 = stub

        for i in range(4):
            gorgon.append(int(data_md5[2 * i:2 * i + 2], 16))
    else:
        for i in range(4):
            gorgon.append(0x00)

    if cookie:
        cookie_md5 = md5(bytearray(cookie, 'utf-8')).hexdigest()

        for i in range(4):
            gorgon.append(int(cookie_md5[2 * i:2 * i + 2], 16))
    else:
        for i in range(4):
            gorgon.append(0x00)

    gorgon = gorgon + [0x01, 0x01, 0x02, 0x04]

    for i in range(4):
        gorgon.append(int(Khronos[2 * i:2 * i + 2], 16))

    return {'X-Gorgon': XG(gorgon).main(), 'X-Khronos': str(int(ttime))}


def get_stub(data):
    if isinstance(data, dict):
        data = json.dumps(data)

    if isinstance(data, str):
        data = data.encode(encoding='utf-8')

    if data == None or data == "" or len(data) == 0:
        return "00000000000000000000000000000000"

    m = hashlib.md5()
    m.update(data)
    res = m.hexdigest()
    res = res.upper()

    return res


def get_profile(session_id, device_id, iid):
    try:

        url = f"https://api.tiktokv.com/passport/account/info/v2/?id=kaa&version_code=34.0.0&language=en&app_name=lite&app_version=34.0.0&carrier_region=SA&device_id=7256623439258404357&tz_offset=10800&mcc_mnc=42001&locale=en&sys_region=SA&aid=473824&screen_width=1284&os_api=18&ac=WIFI&os_version=17.3&app_language=en&tz_name=Asia/Riyadh&carrier_region1=SA&build_number=340002&device_platform=iphone&iid=7353686754157692689&device_type=iPhone13,4"
        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": f"sessionid={session_id}",
            "sdk-version": "2",
            "user-agent": "com.zhiliaoapp.musically/432424234 (Linux; U; Android 5; en; fewfwdw; Build/PI;tt-ok/3.12.13.1)",
        }

        response = requests.get(url, headers=headers, cookies={"sessionid": session_id})
        return response.json()["data"]["username"]

    except Exception as e:

        return "None"


def check_is_changed(last_username, session_id, device_id, iid):
    return get_profile(session_id, device_id, iid) != last_username


def change_username(session_id, device_id, iid, last_username, new_username):
    data = f"aid=364225&unique_id={quote(new_username)}"
    parm = f"aid=364225&residence=&device_id={device_id}&version_name=1.1.0&os_version=17.4.1&iid={iid}&app_name=tiktok_snail&locale=en&ac=4G&sys_region=SA&version_code=1.1.0&channel=App%20Store&op_region=SA&os_api=18&device_brand=iPad&idfv=16045E07-1ED5-4350-9318-77A1469C0B89&device_platform=iPad&device_type=iPad13,4&carrier_region1=&tz_name=Asia/Riyadh&account_region=sa&build_number=11005&tz_offset=10800&app_language=en&carrier_region=&current_region=&aid=364225&mcc_mnc=&screen_width=1284&uoo=1&content_language=&language=en&cdid=B75649A607DA449D8FF2ADE97E0BC3F1&openudid=7b053588b18d61b89c891592139b68d918b44933&app_version=1.1.0"

    sig = run(parm, md5(data.encode("utf-8")).hexdigest() if data else None, None)
    url = f"https://api.tiktokv.com/aweme/v1/commit/user/?{parm}"
    headers = {
        "Connection": "keep-alive",
        "User-Agent": "Whee 1.1.0 rv:11005 (iPad; iOS 17.4.1; en_SA@calendar=gregorian) Cronet",
        "Cookie": f"sessionid={session_id}",
    }
    headers.update(sig)
    response = requests.post(url, data=data, headers=headers)
    result = response.text

    if "unique_id" in result:

        if (check_is_changed(last_username, session_id, device_id, iid)):
            return "Username change successful."

        else:
            return "Failed to change username: " + str(result)

    else:
        return "Failed to change username: " + str(result)


def main():
    device_id = str(random.randint(777777788, 999999999999))
    iid = str(random.randint(777777788, 999999999999))

    session_id = get_session_id()

    last_username = get_profile(session_id, device_id, iid)

    if last_username != "None":
        print(f"Your current TikTok username is: {last_username}")
        new_username = input("Enter the new username you wish to set: ")
        print(change_username(session_id, device_id, iid, last_username, new_username))

    else:
        print("Invalid session ID or other error.")

    print("telegram @harbi")


if __name__ == "__main__":
    main()
