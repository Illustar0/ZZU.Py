import base64
import json
from typing import Final

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from loguru import logger

from zzupy.app.interfaces import ICASClient
from zzupy.exception import LoginError, ParsingError, NetworkError


class CASClient(ICASClient):
    """
    统一认证系统 (CAS) App 客户端。
    """

    APP_VERSION: Final = "SWSuperApp/1.1.1"
    APP_ID: Final = "com.supwisdom.zzu"
    OS_TYPE: Final = "android"

    PUBLIC_KEY_URL: Final = "https://cas.s.zzu.edu.cn/token/jwt/publicKey"
    LOGIN_URL: Final = "https://token.s.zzu.edu.cn/password/passwordLogin"

    JWT_ALGORITHMS: Final = ["RS512"]

    def __init__(
        self,
        user_token: str | None = None,
        refresh_token: str | None = None,
    ) -> None:
        """
        初始化认证服务。
        :param user_token: userToken; 对豫在郑大 APP 抓包获取。
        :param refresh_token: refreshToken; 对豫在郑大 APP 抓包获取。
        """
        self._client = httpx.Client()
        self._user_token: str | None = user_token
        self._refresh_token: str | None = refresh_token
        self._public_key = self._get_public_key()

    def __enter__(self) -> "CASClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @property
    def user_token(self) -> str | None:
        return self._user_token

    @property
    def refresh_token(self) -> str | None:
        return self._refresh_token

    def _validate_jwt(self) -> bool:
        if self._user_token is None or self._refresh_token is None:
            logger.debug("userToken 或 refreshToken 不存在，使用账密登录")
            return False

        try:
            jwt.decode(
                self._user_token, self._public_key, algorithms=self.JWT_ALGORITHMS
            )
        except jwt.ExpiredSignatureError:
            logger.error("userToken 已过期，请使用账密登录并更新 userToken")
            return False
        except jwt.InvalidTokenError:
            logger.error("userToken 无效，请使用账密登录并更新 userToken")
            return False

        try:
            jwt.decode(
                self._refresh_token, self._public_key, algorithms=self.JWT_ALGORITHMS
            )
        except jwt.ExpiredSignatureError:
            logger.error("refreshToken 已过期，请使用账密登录并更新 refreshToken")
            return False
        except jwt.InvalidTokenError:
            logger.error("refreshToken 无效，请使用账密登录并更新 refreshToken")
            return False

        logger.info("userToken 和 refreshToken 有效")
        return True

    def _get_public_key(self) -> RSAPublicKey:
        """
        从 CAS 服务器获取 RSA 公钥。
        """
        logger.debug("正在从 {} 获取公钥...", self.PUBLIC_KEY_URL)
        headers = {"User-Agent": "okhttp/3.12.1"}
        try:
            response = self._client.get(self.PUBLIC_KEY_URL, headers=headers)
            response.raise_for_status()
            public_key_pem = response.content
            return serialization.load_pem_public_key(public_key_pem)
        except httpx.RequestError as exc:
            logger.error("获取公钥失败，网络请求异常: {}", exc)
            raise NetworkError("获取公钥失败，无法连接到认证服务器。") from exc
        except Exception as exc:
            logger.error("解析公钥失败: {}", exc)
            raise ParsingError("认证服务公钥格式无效") from exc

    @staticmethod
    def _encrypt_and_encode(data: str, public_key: RSAPublicKey) -> str:
        """
        使用公钥加密数据，进行 Base64 编码，并添加 '__RSA__' 前缀。
        """
        encrypted_bytes = public_key.encrypt(data.encode("utf-8"), padding.PKCS1v15())
        encoded_bytes = base64.b64encode(encrypted_bytes)
        return f"__RSA__{encoded_bytes.decode('utf-8')}"

    def login(self, account: str, password: str) -> None:
        """
        通过账号和密码登录。

        成功后，userToken 和 refreshToken 会被存储在实例中，

        :param account: 账户
        :param password: 密码
        :raise LoginError: 如果登录失败
        :raise PraisingError: 如果服务器响应无法解析
        :raise NetworkError: 如果出现网络错误
        """
        if self._validate_jwt():
            logger.debug("userToken 和 refreshToken 已设置且有效，跳过账密登录")
            return

        encrypted_account = self._encrypt_and_encode(account, self._public_key)
        encrypted_password = self._encrypt_and_encode(password, self._public_key)

        headers = {"User-Agent": f"{self.APP_VERSION}()"}
        params = {
            "username": encrypted_account,
            "password": encrypted_password,
            "appId": self.APP_ID,
            "osType": self.OS_TYPE,
            "geo": "",
            "deviceId": "",
            "clientId": "",
            "mfaState": "",
        }

        try:
            logger.debug("正在向 {} 发送登录请求...", self.LOGIN_URL)
            response = self._client.post(self.LOGIN_URL, params=params, headers=headers)
            response.raise_for_status()

            logger.debug("/passwordLogin 请求响应体: {}", response.text)

            data = response.json()

            if data.get("code") != 0:
                error_message = data.get("message", "未知错误")
                logger.error("登录请求失败: {}", error_message)
                raise LoginError(f"登录失败: {error_message}")

            token_data = data["data"]
            self._user_token = token_data["idToken"]
            self._refresh_token = token_data["refreshToken"]

            logger.info("登录成功，已获取 Token。")

        except httpx.HTTPStatusError as exc:
            logger.error("登录请求返回失败状态码: {}", exc.response.status_code)
            raise LoginError(f"服务器返回错误状态 {exc.response.status_code}") from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从 /passwordLogin 响应中提取 token 失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("登录网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    def logout(self) -> None:
        """登出账户，会清除 Cookie 但不会清除连接池"""
        self._client.cookies.clear()
        self._client.headers.clear()
        self._user_token = None
        self._refresh_token = None

    def close(self) -> None:
        """清除 Cookie 和连接池"""
        self._client.cookies.clear()
        self._client.headers.clear()
        self._client.close()
        self._user_token = None
        self._refresh_token = None
