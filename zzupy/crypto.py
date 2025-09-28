"""纯 Python 实现的轻量级 RSA 加密"""

import base64
import hashlib
import os
from typing import Tuple


class RSAPublicKey:
    """轻量级 RSA 公钥实现"""

    def __init__(self, modulus: int, exponent: int):
        """初始化 RSA 公钥

        Args:
            modulus: RSA 模数 (n)
            exponent: RSA 公开指数 (e)，通常是 65537
        """
        self.modulus = modulus
        self.exponent = exponent
        self.key_size_bits = modulus.bit_length()
        self.key_size_bytes = (self.key_size_bits + 7) // 8

    def encrypt(self, data: bytes, padding_scheme=None) -> bytes:
        """使用 PKCS#1 v1.5 填充进行 RSA 加密

        Args:
            data: 要加密的数据
            padding_scheme: 填充方案（保留接口兼容性，实际使用 PKCS#1 v1.5）

        Returns:
            加密后的字节数据
        """
        # PKCS#1 v1.5 填充
        # 格式: 0x00 || 0x02 || PS || 0x00 || M
        # PS 是随机非零字节，长度至少为 8

        max_message_length = self.key_size_bytes - 11  # 预留给填充的空间

        if len(data) > max_message_length:
            raise ValueError(f"消息太长，最大长度为 {max_message_length} 字节")

        # 构建填充
        padding_length = self.key_size_bytes - len(data) - 3

        # 生成随机非零填充字节
        padding = bytearray()
        while len(padding) < padding_length:
            random_bytes = os.urandom(padding_length - len(padding))
            # 移除零字节
            for byte in random_bytes:
                if byte != 0:
                    padding.append(byte)
                if len(padding) >= padding_length:
                    break

        # 构建完整的填充消息
        padded_message = bytearray([0x00, 0x02])
        padded_message.extend(padding)
        padded_message.append(0x00)
        padded_message.extend(data)

        # 转换为整数并进行 RSA 加密
        m = int.from_bytes(padded_message, byteorder="big")

        # RSA 加密: c = m^e mod n
        c = pow(m, self.exponent, self.modulus)

        # 转换回字节，确保长度正确
        encrypted = c.to_bytes(self.key_size_bytes, byteorder="big")

        return encrypted

    def verify_rs512(self, message: bytes, signature: bytes) -> bool:
        """验证 RS512 (RSA-SHA512) 签名

        Args:
            message: 原始消息
            signature: RSA 签名

        Returns:
            签名是否有效
        """
        # 计算消息的 SHA-512 哈希
        message_hash = hashlib.sha512(message).digest()

        # RSA 验证: m = s^e mod n
        s = int.from_bytes(signature, byteorder="big")
        m = pow(s, self.exponent, self.modulus)
        decrypted = m.to_bytes(self.key_size_bytes, byteorder="big")

        # 验证 PKCS#1 v1.5 填充格式
        # 格式: 0x00 || 0x01 || PS || 0x00 || DigestInfo
        if decrypted[0] != 0x00 or decrypted[1] != 0x01:
            return False

        # 查找 0x00 分隔符
        separator_index = decrypted.find(b"\x00", 2)
        if separator_index == -1:
            return False

        # DigestInfo 结构 (SHA-512)
        # SHA-512 的 DigestInfo 前缀
        sha512_digest_info = bytes.fromhex(
            "3051"  # SEQUENCE
            "300d"  # AlgorithmIdentifier SEQUENCE
            "0609"  # OID (9 bytes)
            "608648016503040203"  # SHA-512 OID
            "0500"  # NULL
            "0440"  # OCTET STRING (64 bytes)
        )

        digest_info_start = separator_index + 1
        digest_info = decrypted[digest_info_start:]

        # 验证 DigestInfo 结构
        expected_digest_info = sha512_digest_info + message_hash

        return digest_info == expected_digest_info


def load_pem_public_key(pem_data: bytes) -> RSAPublicKey:
    """从 PEM 格式加载 RSA 公钥

    Args:
        pem_data: PEM 格式的公钥数据

    Returns:
        RSAPublicKey 对象
    """
    # 转换为字符串
    if isinstance(pem_data, bytes):
        pem_str = pem_data.decode("utf-8")
    else:
        pem_str = pem_data

    # 清理 PEM 头尾和空白字符
    pem_str = pem_str.strip()
    pem_str = pem_str.replace("-----BEGIN PUBLIC KEY-----", "")
    pem_str = pem_str.replace("-----END PUBLIC KEY-----", "")
    pem_str = pem_str.replace("-----BEGIN RSA PUBLIC KEY-----", "")
    pem_str = pem_str.replace("-----END RSA PUBLIC KEY-----", "")
    pem_str = pem_str.replace("\n", "")
    pem_str = pem_str.replace("\r", "")
    pem_str = pem_str.replace(" ", "")

    # Base64 解码得到 DER 格式数据
    der_bytes = base64.b64decode(pem_str)

    # 解析 DER 格式获取模数和指数
    modulus, exponent = _parse_der_public_key(der_bytes)

    return RSAPublicKey(modulus, exponent)


def _parse_der_public_key(der_data: bytes) -> Tuple[int, int]:
    """解析 DER 编码的 RSA 公钥

    支持两种格式：
    1. PKCS#1 RSAPublicKey (常见于 OpenSSL)
    2. X.509 SubjectPublicKeyInfo (标准格式)

    Args:
        der_data: DER 编码的公钥数据

    Returns:
        (modulus, exponent) 元组
    """

    def read_length(data: bytes, pos: int) -> Tuple[int, int]:
        """读取 ASN.1 长度编码"""
        if data[pos] & 0x80 == 0:
            # 短格式
            return data[pos], pos + 1
        else:
            # 长格式
            num_bytes = data[pos] & 0x7F
            pos += 1
            length = int.from_bytes(data[pos : pos + num_bytes], "big")
            return length, pos + num_bytes

    def read_integer(data: bytes, pos: int) -> Tuple[int, int]:
        """读取 ASN.1 INTEGER"""
        if data[pos] != 0x02:
            raise ValueError(f"期望 INTEGER (0x02)，得到 {hex(data[pos])}")
        pos += 1
        length, pos = read_length(data, pos)
        value = int.from_bytes(data[pos : pos + length], "big")
        return value, pos + length

    pos = 0

    # 检查是否是 SEQUENCE
    if der_data[pos] != 0x30:
        raise ValueError("无效的 DER 格式：期望 SEQUENCE")
    pos += 1

    seq_length, pos = read_length(der_data, pos)

    # 检查下一个元素
    if pos < len(der_data) and der_data[pos] == 0x30:
        # X.509 SubjectPublicKeyInfo 格式
        # 跳过算法标识符
        pos += 1
        algo_length, pos = read_length(der_data, pos)
        pos += algo_length

        # BIT STRING 包含实际的公钥
        if der_data[pos] != 0x03:
            raise ValueError("期望 BIT STRING")
        pos += 1

        bit_string_length, pos = read_length(der_data, pos)

        # 跳过未使用的位数标记
        if der_data[pos] != 0x00:
            raise ValueError("期望未使用位数为 0")
        pos += 1

        # 现在应该是另一个 SEQUENCE（RSAPublicKey）
        if der_data[pos] != 0x30:
            raise ValueError("期望内部 SEQUENCE")
        pos += 1

        inner_seq_length, pos = read_length(der_data, pos)

    # 读取模数
    modulus, pos = read_integer(der_data, pos)

    # 读取公开指数
    exponent, pos = read_integer(der_data, pos)

    return modulus, exponent


# 兼容性类和函数
class padding:
    """填充方案命名空间（兼容 cryptography）"""

    class PKCS1v15:
        """PKCS#1 v1.5 填充方案"""

        pass


class serialization:
    """序列化命名空间（兼容 cryptography）"""

    @staticmethod
    def load_pem_public_key(data: bytes) -> RSAPublicKey:
        """加载 PEM 格式公钥（兼容 cryptography 接口）"""
        return load_pem_public_key(data)
