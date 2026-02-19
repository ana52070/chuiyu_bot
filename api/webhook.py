"""
webhook.py - 异步处理版本
收到消息立即返回200，后台线程处理RAG并主动推送结果
"""

import os
import sys
import time
import threading
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(__file__))
from wxwork import WXBizMsgCrypt
from rag import query as rag_query

CORP_ID     = os.environ.get("WXWORK_CORP_ID", "")
AGENT_ID    = os.environ.get("WXWORK_AGENT_ID", "")
CORP_SECRET = os.environ.get("WXWORK_SECRET", "")
WX_TOKEN    = os.environ.get("WXWORK_TOKEN", "")
WX_AES_KEY  = os.environ.get("WXWORK_AES_KEY", "")

crypt = WXBizMsgCrypt(WX_TOKEN, WX_AES_KEY, CORP_ID)


def get_access_token() -> str:
    import requests
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORP_ID}&corpsecret={CORP_SECRET}"
    resp = requests.get(url, timeout=10)
    return resp.json().get("access_token", "")


def send_message(to_user: str, content: str):
    import requests
    token = get_access_token()
    if not token:
        return
    url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={token}"
    payload = {
        "touser": to_user,
        "msgtype": "text",
        "agentid": int(AGENT_ID),
        "text": {"content": content},
    }
    requests.post(url, json=payload, timeout=30)


def process_and_reply(user_id: str, question: str):
    """后台线程：执行RAG查询并主动推送结果"""
    try:
        answer = rag_query(question)
        send_message(user_id, answer)
    except Exception as e:
        send_message(user_id, f"处理出错：{str(e)}")


def parse_xml(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    return {child.tag: child.text for child in root}


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        msg_signature = params.get("msg_signature", [""])[0]
        timestamp     = params.get("timestamp", [""])[0]
        nonce         = params.get("nonce", [""])[0]
        echostr       = params.get("echostr", [""])[0]

        if crypt.verify_signature(msg_signature, timestamp, nonce, echostr):
            decrypted = crypt.decrypt(echostr)
            self._respond(200, decrypted)
        else:
            self._respond(403, "Forbidden")

    def do_POST(self):
        params = parse_qs(urlparse(self.path).query)
        msg_signature = params.get("msg_signature", [""])[0]
        timestamp     = params.get("timestamp", [""])[0]
        nonce         = params.get("nonce", [""])[0]

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8")

        try:
            root      = ET.fromstring(body)
            encrypted = root.find("Encrypt").text
        except Exception:
            self._respond(400, "Bad Request")
            return

        if not crypt.verify_signature(msg_signature, timestamp, nonce, encrypted):
            self._respond(403, "Forbidden")
            return

        xml_str = crypt.decrypt(encrypted)
        msg     = parse_xml(xml_str)

        if msg.get("MsgType") == "text":
            user_id  = msg.get("FromUserName", "")
            question = msg.get("Content", "").strip()

            # 立即返回200，避免微信超时重试
            self._respond(200, "success")

            # 后台线程处理RAG并推送结果
            t = threading.Thread(target=process_and_reply, args=(user_id, question))
            t.daemon = True
            t.start()
        else:
            self._respond(200, "success")

    def _respond(self, code: int, body: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        pass