import hashlib
import re
import socket

import gmalg
import ifaddr


def get_sign(dynamicSecret, params):
    """
    获取sign值

    :param str dynamicSecret: login后自动获取，来自 login-token 请求
    :param str params: URL请求参数
    :return: sign值
    :rtype: str
    """
    paramsDict = {}
    for param in params.split("&"):
        if param.split("=")[0] == "timestamp":
            timestamp = param.split("=")[1]
        elif param.split("=")[0] == "random":
            random = param.split("=")[1]
        else:
            paramsDict[param.split("=")[0]] = param.split("=")[1]
    paramsDict = dict(sorted(paramsDict.items()))
    original = f"{dynamicSecret}|"
    for key in paramsDict:
        original += f"{paramsDict[key]}|"
    original += f"{timestamp}|{random}"
    sign = hashlib.md5(original.encode("utf-8")).hexdigest().upper()
    return sign


def _kget(kwargs, key, default=None):
    return kwargs[key] if key in kwargs else default


def get_ip_by_interface(interface):
    """
    获取指定网卡的IP地址

    :param interface: 网卡名称
    :return: 给定王卡的 IP 地址
    """
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        if adapter.name == interface:
            for ip in adapter.ips:
                # 只返回IPv4地址
                if isinstance(ip.ip, str):
                    return ip.ip
    return None


def pkcs7_unpad(padded_data: bytes, block_size: int) -> bytes:
    """
    去除数据中的PKCS#7填充。

    :param bytes padded_data: 带填充的数据
    :param int block_size: 用于填充的块大小
    :return: 去除填充后的数据
    :rtype: bytes
    :raises ValueError: 如果填充无效
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


def sm4_decrypt_ecb(ciphertext: bytes, key: bytes):
    """
    SM4 解密，ECB模式

    :param bytes ciphertext: 密文
    :param bytes key: 密钥
    :return: 明文 Hex
    :rtype: str
    """
    sm4 = gmalg.SM4(key)
    block_size = 16
    decrypted_padded = b""
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        decrypted_padded += sm4.decrypt(block)
    decrypted = pkcs7_unpad(decrypted_padded, block_size)
    return decrypted.decode()


def check_permission(self):
    """
    检查用户是否登录

    :param self:
    """
    if self.is_logged_in:
        pass
    else:
        raise PermissionError("需要登录")


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("119.29.29.29", 80))
        local_ip = s.getsockname()[0]
        return local_ip
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_interface_by_ip(target_ip):
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        for ip in adapter.ips:
            if ip.is_IPv4:
                if ip.ip == target_ip:
                    return adapter.name
            else:
                if isinstance(ip.ip, str):
                    ip_addr = ip.ip.split("%")[0] if "%" in ip.ip else ip.ip
                    if ip_addr == target_ip:
                        return adapter.name
                elif isinstance(ip.ip, tuple):
                    ip_addr = ip.ip[0] if len(ip.ip) > 0 else None
                    if ip_addr == target_ip:
                        return adapter.name
    return None


class XorCipher:
    """
    一个使用异或 (XOR) 算法进行简单加密和解密的类。
    """

    def __init__(self, key_string: str = ""):
        self._key: int = self._generate_key(key_string)

    @staticmethod
    def _generate_key(s: str) -> int:
        """
        根据输入字符串计算异或密钥。
        """
        ret = 0
        for char in s:
            ret ^= ord(char)
        return ret

    @property
    def key(self) -> int:
        return self._key

    def encrypt(self, string: str) -> str:
        """
        将明文与实例密钥进行异或运算，并转为十六进制字符串。
        :param string: 明文
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
        """
        将十六进制字符串解密回原始密码。

        :param hex_string: 十六进制字符串
        :raise ValueError: 如果十六进制字符串格式错误
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
