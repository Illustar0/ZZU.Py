"""工具函数库"""

import hashlib
import re
import socket
from functools import wraps
from typing import Dict
from urllib.parse import parse_qs

import gmalg

from zzupy.exception import NotLoggedInError


def get_sign(dynamic_secret: str, params: str) -> str:
    """获取sign值

    Args:
        dynamic_secret (str): login 后自动获取，来自 login-token 请求
        params (str): URL 请求参数

    Returns:
        str: sign 值
    """
    parsed_params: Dict[str, str] = {k: v[0] for k, v in parse_qs(params).items()}

    timestamp = parsed_params.pop("timestamp", "")
    random = parsed_params.pop("random", "")

    sorted_values = [v for k, v in sorted(parsed_params.items())]

    parts_to_sign = [dynamic_secret] + sorted_values + [timestamp, random]
    original_string = "|".join(parts_to_sign)

    sign = hashlib.md5(original_string.encode("utf-8")).hexdigest().upper()
    return sign


def pkcs7_unpad(padded_data: bytes, block_size: int) -> bytes:
    """去除数据中的PKCS#7填充。

    Args:
        padded_data (bytes): 带填充的数据
        block_size (int): 用于填充的块大小

    Returns:
        bytes: 去除填充后的数据

    Raises:
        ValueError: 如果填充无效
    """
    if not padded_data or len(padded_data) % block_size != 0:
        raise ValueError("无效的填充数据长度")

    # 从最后一个字节获取填充长度
    padding_len = padded_data[-1]

    # 检查填充长度是否有效
    if padding_len > block_size or padding_len == 0:
        raise ValueError("无效的填充长度")

    # 检查所有填充字节是否正确
    for i in range(1, padding_len + 1):
        if padded_data[-i] != padding_len:
            raise ValueError("无效的填充")

    # 返回去除填充后的数据
    return padded_data[:-padding_len]


def sm4_decrypt_ecb(ciphertext: bytes, key: bytes) -> str:
    """SM4 解密，ECB模式

    Args:
        ciphertext (bytes): 密文
        key (bytes): 密钥

    Returns:
        明文 Hex
    """
    sm4 = gmalg.SM4(key)
    block_size = 16
    decrypted_padded = b""
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        decrypted_padded += sm4.decrypt(block)
    decrypted = pkcs7_unpad(decrypted_padded, block_size)
    return decrypted.decode()


def get_local_ip(target: str = "8.8.8.8") -> str | None:
    """
    获取用于连接到特定目标IP的本地IP地址。

    Args:
        target: 目标主机名或IP地址。默认为 '8.8.8.8'。

    Returns:
        str: 用于到达目标的本地IP地址
        None: 如果发生网络错误
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except socket.error:
        return None


class XorCipher:
    """一个使用异或 (XOR) 算法进行简单加密和解密的类。"""

    def __init__(self, key_string: str = ""):
        self._key: int = self._generate_key(key_string)

    @staticmethod
    def _generate_key(s: str) -> int:
        """根据输入字符串计算异或密钥。"""
        ret = 0
        for char in s:
            ret ^= ord(char)
        return ret

    @property
    def key(self) -> int:
        return self._key

    def encrypt(self, string: str) -> str:
        """将明文与实例密钥进行异或运算，并转为十六进制字符串。

        Args:
            string: 明文
        """
        if len(string) > 512:
            return "-1"

        encrypted_output = []
        for char in string:
            ch = ord(char) ^ self._key
            hex_str = format(ch, "02x")
            encrypted_output.append(hex_str)

        return "".join(encrypted_output)

    def decrypt(self, hex_string: str) -> str:
        """将十六进制字符串解密回原始密码。

        Args:
            hex_string: 十六进制字符串

        Raises:
            ValueError: 如果十六进制字符串格式错误
        """
        if len(hex_string) % 2 != 0:
            raise ValueError("十六进制字符串长度必须为偶数")

        original_password = []
        for i in range(0, len(hex_string), 2):
            hex_pair = hex_string[i : i + 2]
            decimal_value = int(hex_pair, 16)
            # 与实例密钥进行异或
            original_char = chr(decimal_value ^ self._key)
            original_password.append(original_char)

        return "".join(original_password)


class JsonPParser:
    """JsonP 格式数据解析器"""

    _pattern = re.compile(r"^\s*(\w+)\((.*)\);?\s*$")

    def __init__(self, text: str):
        self.text = text
        self._callback = None
        self._data = None
        self._parse()

    def _parse(self):
        match = self._pattern.match(self.text)
        if not match:
            raise ValueError("Invalid text format.")

        self._callback = match.group(1)
        self._data = match.group(2)

    @property
    def callback(self) -> str:
        return self._callback

    @property
    def data(self) -> str:
        return self._data


def require_auth(func):
    """装饰器：确保调用方法前已登录

    Raises:
        NotLoggedInError: 如果未登录
    """

    @wraps(func)
    async def async_wrapper(self, *args, **kwargs):
        if not self._logged_in:
            raise NotLoggedInError("需要登录")
        return await func(self, *args, **kwargs)

    @wraps(func)
    def sync_wrapper(self, *args, **kwargs):
        if not self._logged_in:
            raise NotLoggedInError("需要登录")
        return func(self, *args, **kwargs)

    import asyncio

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper
