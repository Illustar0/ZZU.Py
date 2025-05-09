import asyncio
import hashlib
import socket
from functools import wraps

import gmalg
import ifaddr
from Crypto.Util.Padding import unpad


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
    decrypted = unpad(decrypted_padded, block_size)
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


def sync_wrapper(async_func):
    """
    将异步方法包装为同步方法的装饰器
    """

    @wraps(async_func)
    def wrapper(*args, **kwargs):
        try:
            # 尝试获取当前事件循环
            loop = asyncio.get_event_loop()
            new_loop = False
        except RuntimeError:
            # 如果没有事件循环，创建一个新的
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            new_loop = True

        try:
            return loop.run_until_complete(async_func(*args, **kwargs))
        finally:
            # 只有当我们创建了新的事件循环时才关闭它
            if new_loop:
                loop.close()

    return wrapper


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


# 以下代码来自 https://github.com/zidou-kiyn/share_zzu_wlan
# 窝就是 Ctrl + CV 领域大神，哈哈
def get_key(ip: str = "") -> int:
    """计算输入字符串的异或密钥"""
    ret = 0
    for char in ip:
        ret ^= ord(char)
    return ret


def enc_pwd(pass_in: str, key: int) -> str:
    """加密函数：将密码与密钥进行异或运算，并转为十六进制字符串"""
    if len(pass_in) > 512:
        return "-1"

    pass_out = ""
    for char in pass_in:
        ch = ord(char) ^ key
        hex_str = format(ch, "02x")
        pass_out += hex_str

    return pass_out


def dec_pwd(hex_string: str, key: int) -> str:
    """解密函数：将十六进制字符串解密回原始密码"""
    if len(hex_string) % 2 != 0:
        return "错误：十六进制字符串长度必须为偶数"

    original_password = ""
    for i in range(0, len(hex_string), 2):
        hex_pair = hex_string[i : i + 2]
        decimal_value = int(hex_pair, 16)
        original_char = chr(decimal_value ^ key)
        original_password += original_char

    return original_password
