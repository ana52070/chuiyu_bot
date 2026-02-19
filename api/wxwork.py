"""
wxwork.py - 企业微信加解密（使用 cryptography 标准库）
"""

import hashlib
import base64
import struct
import time
import random
import string

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class WXBizMsgCrypt:
    def __init__(self, token: str, encoding_aes_key: str, corp_id: str):
        self.token = token
        self.key = base64.b64decode(encoding_aes_key + "=")
        self.corp_id = corp_id

    def _pkcs7_decode(self, data: bytes) -> bytes:
        pad = data[-1]
        return data[:-pad]

    def _pkcs7_encode(self, data: bytes) -> bytes:
        pad = 32 - len(data) % 32
        return data + bytes([pad] * pad)

    def _aes_decrypt(self, data: bytes) -> bytes:
        iv = self.key[:16]
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def _aes_encrypt(self, data: bytes) -> bytes:
        iv = self.key[:16]
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def verify_signature(self, signature: str, timestamp: str, nonce: str, data: str = "") -> bool:
        items = sorted([self.token, timestamp, nonce, data])
        s = hashlib.sha1("".join(items).encode()).hexdigest()
        return s == signature

    def decrypt(self, encrypted: str) -> str:
        data = base64.b64decode(encrypted)
        decrypted = self._pkcs7_decode(self._aes_decrypt(data))
        # 去掉前16字节随机串，读4字节消息长度
        content = decrypted[16:]
        msg_len = struct.unpack(">I", content[:4])[0]
        return content[4:4 + msg_len].decode("utf-8")

    def encrypt(self, reply_msg: str) -> str:
        random_str = "".join(random.choices(string.ascii_letters, k=16)).encode()
        msg = reply_msg.encode()
        msg_len = struct.pack(">I", len(msg))
        corp_id = self.corp_id.encode()
        plain = self._pkcs7_encode(random_str + msg_len + msg + corp_id)
        return base64.b64encode(self._aes_encrypt(plain)).decode()

    def make_reply_xml(self, encrypted: str, timestamp: str, nonce: str) -> str:
        sign_items = sorted([self.token, timestamp, nonce, encrypted])
        signature = hashlib.sha1("".join(sign_items).encode()).hexdigest()
        return (
            f"<xml>"
            f"<Encrypt><![CDATA[{encrypted}]]></Encrypt>"
            f"<MsgSignature><![CDATA[{signature}]]></MsgSignature>"
            f"<TimeStamp>{timestamp}</TimeStamp>"
            f"<Nonce><![CDATA[{nonce}]]></Nonce>"
            f"</xml>"
        )