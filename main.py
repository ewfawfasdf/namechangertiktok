import base64
import binascii
import hashlib
import json
import os
import random
import re
import sys
from copy import deepcopy
from time import sleep, time
from urllib.parse import quote

import requests
import qrcode
from flask import Flask, render_template, request
import flet as ft
from flet import IconButton, Page, Row, TextField, icons

domen = "api.tiktokv.com"
def hex_string(num):
    tmp_string = hex(num)[2:]
    if len(tmp_string) < 2:
        tmp_string = '0' + tmp_string
    return tmp_string

def GET(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
        'Accept': 'application/json, text/javascript',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    return requests.get(url, headers=headers)

# Function to perform a GET request with custom headers including cookies
def GET_h(url, ttwid, passport_csrf_token):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
        'Accept': 'application/json, text/javascript',
        'Content-Type': 'application/x-www-form-urlencoded',
        'cookie': f'ttwid={ttwid}; passport_csrf_token={passport_csrf_token};',
        'x-tt-passport-csrf-token': f'{passport_csrf_token}'
    }
    return requests.get(url, headers=headers)

# Function to decode escape sequences in a URL
def convert_escape_sequence(s):
    return s.encode().decode('unicode_escape')

# Function to shorten a URL using TikTok's URL shortening service
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

# Function to retrieve the QR code URL and related tokens
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
    return token, ttwid, passport_csrf_token, shorten_url

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
                C = C - 0x100
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
                C = C - 0x100
            tmp_add.append(C)
            D = tmp_hex[C]
            tmp_hex[i + 1] = D
            E = D + D
            while E >= 0x100:
                E = E - 0x100
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
        result = ''
        for item in self.calculate(self.initial(self.debug, self.addr_BA8())):
            result = result + hex_string(item)

        return '8404{}{}{}{}{}'.format(hex_string(self.hex_CE0[7]), hex_string(self.hex_CE0[3]),
                                       hex_string(self.hex_CE0[1]), hex_string(self.hex_CE0[6]), result)


def X_Gorgon(param, data, cookie):
    gorgon = []
    ttime = time()
    Khronos = hex(int(ttime))[2:]
    url_md5 = md5(bytearray(param, 'utf-8')).hexdigest()
    for i in range(0, 4):
        gorgon.append(int(url_md5[2 * i: 2 * i + 2], 16))
    if data:
        if isinstance(data, str):
            data = data.encode(encoding='utf-8')
        data_md5 = md5(data).hexdigest()
        for i in range(0, 4):
            gorgon.append(int(data_md5[2 * i: 2 * i + 2], 16))
    else:
        for i in range(0, 4):
            gorgon.append(0x0)
    if cookie:
        cookie_md5 = md5(bytearray(cookie, 'utf-8')).hexdigest()
        for i in range(0, 4):
            gorgon.append(int(cookie_md5[2 * i: 2 * i + 2], 16))
    else:
        for i in range(0, 4):
            gorgon.append(0x0)
    gorgon = gorgon + [0x1, 0x1, 0x2, 0x4]
    for i in range(0, 4):
        gorgon.append(int(Khronos[2 * i: 2 * i + 2], 16))
    return {'X-Gorgon': XG(gorgon).main(), 'X-Khronos': str(int(ttime))}


def run(param="", stub="", cookie=""):
    gorgon = []
    ttime = time()
    Khronos = hex(int(ttime))[2:]
    url_md5 = md5(bytearray(param, 'utf-8')).hexdigest()
    for i in range(0, 4):
        gorgon.append(int(url_md5[2 * i: 2 * i + 2], 16))
    if stub:
        data_md5 = stub
        for i in range(0, 4):
            gorgon.append(int(data_md5[2 * i: 2 * i + 2], 16))
    else:
        for i in range(0, 4):
            gorgon.append(0x0)
    if cookie:
        cookie_md5 = md5(bytearray(cookie, 'utf-8')).hexdigest()
        for i in range(0, 4):
            gorgon.append(int(cookie_md5[2 * i: 2 * i + 2], 16))
    else:
        for i in range(0, 4):
            gorgon.append(0x0)
    gorgon = gorgon + [0x1, 0x1, 0x2, 0x4]
    for i in range(0, 4):
        gorgon.append(int(Khronos[2 * i: 2 * i + 2], 16))
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
    """Retrieve the current TikTok username for a given session, device, and iid."""
    try:
        data = None
        parm = (
            f"device_id={device_id}&iid={iid}&id=kaa&version_code=34.0.0&language=en"
            "&app_name=lite&app_version=34.0.0&carrier_region=SA&tz_offset=10800&mcc_mnc=42001"
            "&locale=en&sys_region=SA&aid=473824&screen_width=1284&os_api=18&ac=WIFI&os_version=17.3"
            "&app_language=en&tz_name=Asia/Riyadh&carrier_region1=SA&build_number=340002&device_platform=iphone"
            "&device_type=iPhone13,4"
        )
        url = f"https://{domen}/aweme/v1/user/profile/self/?{parm}"
        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": f"sessionid={session_id}",
            "sdk-version": "2",
            "user-agent": "com.zhiliaoapp.musically/432424234 (Linux; U; Android 5; en; fewfwdw; Build/PI;tt-ok/3.12.13.1)",

        }
        response = requests.get(url, headers=headers, cookies={"sessionid": session_id})
        return response.json()["user"]["unique_id"]
    except Exception as e:
        return "None"


def check_is_changed(last_username, session_id, device_id, iid):
    """Check if the username has been changed in the TikTok profile."""
    return get_profile(session_id, device_id, iid) != last_username


def change_username(session_id, device_id, iid, last_username, new_username):
    """Attempt to change a TikTok username."""
    data = f"aid=364225&unique_id={quote(new_username)}"
    parm = f"aid=364225&residence=&device_id={device_id}&version_name=1.1.0&os_version=17.4.1&iid={iid}&app_name=tiktok_snail&locale=en&ac=4G&sys_region=SA&version_code=1.1.0&channel=App%20Store&op_region=SA&os_api=18&device_brand=iPad&idfv=16045E07-1ED5-4350-9318-77A1469C0B89&device_platform=iPad&device_type=iPad13,4&carrier_region1=&tz_name=Asia/Riyadh&account_region=sa&build_number=11005&tz_offset=10800&app_language=en&carrier_region=&current_region=&aid=364225&mcc_mnc=&screen_width=1284&uoo=1&content_language=&language=en&cdid=B75649A607DA449D8FF2ADE97E0BC3F1&openudid=7b053588b18d61b89c891592139b68d918b44933&app_version=1.1.0"


    sig = run(parm, md5(data.encode("utf-8")).hexdigest() if data else None,None)
    url = f"https://{domen}/aweme/v1/commit/user/?{parm}"
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "DELETE, POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
        "Connection": "keep-alive",
        "User-Agent": "Whee 1.1.0 rv:11005 (iPad; iOS 17.4.1; en_SA@calendar=gregorian) Cronet",


        "Cookie": f"sessionid={session_id}",
    }
    headers.update(sig)
    response = requests.post(url, data=data, headers=headers)
    result = response.text
    if "unique_id" in result and check_is_changed(
        last_username, session_id, device_id, iid
    ):
        return result
    else:
        return result


def main(page):
    def check_qr_connect(token, ttwid, passport_csrf_token):
        """Function to continuously check the status of QR Code connection."""
        while True:
            qr_check = GET_h(
                f'https://web-va.tiktok.com/passport/web/check_qrconnect/?next=https%3A%2F%2Fwww.tiktok.com&token={token}&aid=1459',
                ttwid,
                passport_csrf_token
            )
            if "confirmed" in qr_check.text:
                sessionid = qr_check.cookies.get('sessionid')
                qrcodelogined(sessionid)
                qrcodeimg.src_base64 = qrcreate()
                break
            elif "expired" in qr_check.text:
                token, ttwid, passport_csrf_token, shorten_url = get_qrcode_url()
                print("URL has been updated!")
            sleep(0.7)
    def logadd(e):
        # Добавляем новую строку в текстовое поле логов
        new_log = f"{datetime.datetime.now().strftime('%H:%M:%S')} "+e+" \n"
        log_field.value += new_log
        log_field.update()

    def tgbutton(a):
        if sys.platform.startswith('win'):
            os.system(f'start https://t.me/ttrussianaccounts')

        else:
            os.system(f'xdg-open https://t.me/ttrussianaccounts')
    def addinvisymbl(a):

        newname.value = newname.value+"\u200D"
        newname.update()
    def qrcodelogined(a):
        qrtoggle.value = False
        sesid.visible = True
        qrcodeimg.visible = False
        sesid.value = a
        page.update()
    page.adaptive = True
    def ddchanged(a):
        domen = domenchange.value
    page.appbar = ft.AppBar(
        title=ft.Text("Name changer"),
        actions=[
            ft.IconButton(ft.icons.TELEGRAM, style=ft.ButtonStyle(padding=0),on_click=tgbutton)
        ],
    )
    def qrtoggled(a):
        sesid.visible = not qrtoggle.value
        qrcodeimg.visible = qrtoggle.value
        sesid.update()
        qrcodeimg.update()

    def qrcreate():
        token, ttwid, passport_csrf_token, shorten_url = get_qrcode_url()
        qr_thread = threading.Thread(target=check_qr_connect, args=(token, ttwid, passport_csrf_token))
        qr_thread.start()

        img = qrcode.make(shorten_url)
        buffered = io.BytesIO()
        img.save(buffered)
        img_bytes = buffered.getvalue()
        string = base64.b64encode(img_bytes)
        base64_string = string.decode('utf-8')
        return base64_string

    def changnameclicked(e):
        device_id = str(random.randint(777777788, 999999999999))
        iid = str(random.randint(777777788, 999999999999))
        ftbutton.visible = False
        page.update()
        session_id = sesid.value

        user = get_profile(session_id, device_id, iid)
        if user != "None":
            logadd(f"Your name: {user}")
            new_username = newname.value
            ch = change_username(session_id, device_id, iid, user, new_username)
            sleep(5)
            newnm = get_profile(session_id, device_id, iid)
            if new_username == newnm:
                logadd(f"Name Changed: {newnm}")
                ftbutton.visible = True
                page.update()
            else:
                logadd(f"Couldn't change the name")
                ftbutton.visible = True
                if json.loads(ch)["status_code"] == 2160:
                    logadd("Slow down you are editing to fast, try it on another account")
                page.update()
        else:
            logadd("Invalid session ID or other error.")
            ftbutton.visible = True
            page.update()

    sesid = ft.TextField(max_length=32,label="Session id",keyboard_type=ft.KeyboardType.TEXT, password=True, can_reveal_password=True)
    newname = ft.TextField(max_length=50,label="New Name",prefix_text="https://www.tiktok.com/@", keyboard_type=ft.KeyboardType.TEXT)
    log_field = ft.TextField(
        label="Logs",
        multiline=True,
        width=400,
        height=200,
        text_align=ft.TextAlign.LEFT,
        read_only=True
    )
    domenchange = ft.Dropdown(value=domen,options=[
        ft.dropdown.Option("api.tiktokv.com"),
        ft.dropdown.Option("api16-normal-c-alisg.tiktokv.com"),
        ft.dropdown.Option("api19-normal-useast1a.tiktokv.com"),
        ft.dropdown.Option("api16-normal-c-alisg.tiktokv.com"),
        ft.dropdown.Option("api16-normal-c-useast1a.tiktokv.com"),
        ft.dropdown.Option("api16-normal-c-useast2a.tiktokv.com"),
        ft.dropdown.Option("api16-normal-v4.tiktokv.com"),
        ft.dropdown.Option("api16-normal-v6.tiktokv.com"),
        ft.dropdown.Option("api16-va.tiktokv.com"),
    ], on_change=ddchanged)
    ftbutton = ft.FilledButton(content=ft.Text("Change"),on_click=changnameclicked)
    qrtoggle = ft.Switch(label="QR code login", value=False,on_change=qrtoggled)
    qrcodeimg = ft.Image(src_base64=qrcreate(),visible=False)
    page.add(
        ft.SafeArea(
            ft.Column(
                [
                    qrtoggle,
                    qrcodeimg,
                    sesid,
                    newname,
                    ftbutton,
                    ft.FilledButton(content=ft.Text("Add invisible symbol"), on_click=addinvisymbl),
                    log_field,
                    domenchange,
                ]
            )
        )
    )
ft.app(target=main,assets_dir="assets")
