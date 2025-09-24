"""统一认证"""

import asyncio
import base64
import json
from datetime import datetime
from typing import Final

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from loguru import logger

from zzupy.app.interfaces import ICASClient
from zzupy.exception import LoginError, ParsingError, NetworkError
from zzupy.utils import require_auth


class CASClient(ICASClient):
    """统一认证系统 (CAS) App 客户端。"""

    APP_VERSION: Final = "SWSuperApp/1.1.1"
    APP_ID: Final = "com.supwisdom.zzu"
    OS_TYPE: Final = "android"

    PUBLIC_KEY_URL: Final = "https://cas.s.zzu.edu.cn/token/jwt/publicKey"
    LOGIN_URL: Final = "https://cas.s.zzu.edu.cn/token/password/passwordLogin"

    JWT_ALGORITHMS: Final = ["RS512"]

    def __init__(
        self,
        account: str,
        password: str,
    ) -> None:
        """初始化认证服务。

        Args:
            account: 账号
            password: 密码
        """
        self._client = httpx.AsyncClient()
        self._account = account
        self._password = password
        self._public_key: RSAPublicKey | None = None
        self._user_token: str | None = None
        self._refresh_token: str | None = None
        self._logged_in: bool = False
        self._refresh_task: asyncio.Task | None = None

    async def __aenter__(self) -> "CASClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    def set_token(self, user_token: str, refresh_token: str) -> None:
        """设置统一认证 Token。

        Args:
            user_token: `userToken`。对豫见郑大 APP 抓包获取，或账密登录后访问 [`user_token`][zzupy.app.auth.CASClient.user_token] 获取
            refresh_token: `refreshToken`。对豫见郑大 APP 抓包获取，或账密登录后访问 [`refresh_token`][zzupy.app.auth.CASClient.refresh_token] 获取
        """
        self._user_token = user_token
        self._refresh_token = refresh_token

    @property
    def user_token(self) -> str | None:
        """当前会话的 `userToken`，约一个月有效期"""
        return self._user_token

    @property
    def refresh_token(self) -> str | None:
        """当前会话的 `refreshToken`，约两个月有效期"""
        return self._refresh_token

    @property
    def logged_in(self) -> bool:
        """当前会话是否已登录"""
        return self._logged_in

    def _validate_jwt(self, pre_set_token: bool = False) -> bool:
        if pre_set_token:
            try:
                user_token_plain: dict = jwt.decode(
                    self._user_token, self._public_key, algorithms=self.JWT_ALGORITHMS
                )
                expire_date = datetime.fromtimestamp(user_token_plain.get("exp"))
                now = datetime.now()
                time_to_expire = (expire_date - now).total_seconds()

                if time_to_expire <= 900:  # 提前 15 分钟
                    logger.error(
                        "userToken 即将过期或已过期，将使用账密登录并更新 userToken"
                    )
                    return False

                # 在过期前 15 分钟自动刷新
                refresh_delay = time_to_expire - 900
                if refresh_delay > 0:

                    async def refresh_task():
                        await asyncio.sleep(refresh_delay)
                        await self.login(force_login=True)

                    self._refresh_task = asyncio.create_task(refresh_task())
                    logger.debug(
                        f"已设置自动刷新任务，将在 {refresh_delay:.0f} 秒后刷新 Token"
                    )

            except jwt.InvalidTokenError:
                logger.error("userToken 无效，将使用账密登录并更新 userToken")
                return False

            try:
                jwt.decode(
                    self._refresh_token,
                    self._public_key,
                    algorithms=self.JWT_ALGORITHMS,
                )
            except jwt.ExpiredSignatureError:
                logger.error("refreshToken 已过期，将使用账密登录并更新 refreshToken")
                return False
            except jwt.InvalidTokenError:
                logger.error("refreshToken 无效，将使用账密登录并更新 refreshToken")
                return False
        else:
            try:
                jwt.decode(
                    self._user_token, self._public_key, algorithms=self.JWT_ALGORITHMS
                )
            except jwt.InvalidTokenError:
                raise LoginError(
                    "登录失败，下发的 userToken 无效。这是意料之外的行为，请前往 Issue 报告此错误。"
                )

            try:
                jwt.decode(
                    self._refresh_token,
                    self._public_key,
                    algorithms=self.JWT_ALGORITHMS,
                )
            except jwt.InvalidTokenError:
                raise LoginError(
                    "登录失败，下发的 refreshToken 无效。这是意料之外的行为，请前往 Issue 报告此错误。"
                )

        logger.info("userToken 和 refreshToken 有效")
        return True

    async def _get_public_key(self) -> RSAPublicKey:
        """从 CAS 服务器获取 RSA 公钥。"""
        logger.debug("正在从 {} 获取公钥...", self.PUBLIC_KEY_URL)
        headers = {"User-Agent": "okhttp/3.12.1"}
        try:
            response = await self._client.get(self.PUBLIC_KEY_URL, headers=headers)
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
        """使用公钥加密数据，进行 Base64 编码，并添加 '__RSA__' 前缀。"""
        encrypted_bytes = public_key.encrypt(data.encode("utf-8"), padding.PKCS1v15())
        encoded_bytes = base64.b64encode(encrypted_bytes)
        return f"__RSA__{encoded_bytes.decode('utf-8')}"

    async def login(self, force_login: bool = False) -> None:
        """登录统一认证。

        成功后，[`userToken`][zzupy.app.auth.CASClient.user_token] 和 [`refreshToken`][zzupy.app.auth.CASClient.refresh_token] 会被存储在实例中.

        若 [`user_token`][zzupy.app.auth.CASClient.user_token] 和 [`refresh_token`][zzupy.app.auth.CASClient.refresh_token] 已通过 [`set_token`][zzupy.app.auth.CASClient.set_token] 设置且有效，则会跳过账密登录。

        Args:
            force_login: 强制使用账密登录

        Raises:
            LoginError: 如果登录失败
            ParsingError: 如果服务器响应无法解析
            NetworkError: 如果出现网络错误
        """
        if self._public_key is None:
            self._public_key = await self._get_public_key()
        if not force_login:
            if self._user_token is None or self._refresh_token is None:
                logger.debug("userToken 或 refreshToken 不存在，使用账密登录")
            else:
                if self._validate_jwt(True):
                    logger.debug("userToken 和 refreshToken 已设置且有效，跳过账密登录")
                    self._logged_in = True
                    return
        else:
            logger.info("强制使用账密登录")

        encrypted_account = self._encrypt_and_encode(self._account, self._public_key)
        encrypted_password = self._encrypt_and_encode(self._password, self._public_key)

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
            response = await self._client.post(
                self.LOGIN_URL, params=params, headers=headers
            )
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
            self._validate_jwt()
            self._logged_in = True

            logger.info("统一认证登录成功")

        except httpx.HTTPStatusError as exc:
            logger.error("登录请求返回失败状态码: {}", exc.response.status_code)
            raise LoginError(f"服务器返回错误状态 {exc.response.status_code}") from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从 /passwordLogin 响应中提取 token 失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("登录网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    @require_auth
    def logout(self) -> None:
        """登出账户，清除 Cookie 但保留连接池"""
        self._client.cookies.clear()
        self._client.headers.clear()
        self._user_token = None
        self._refresh_token = None
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            self._refresh_task = None
        self._logged_in = False

    async def close(self) -> None:
        """清除 Cookie 和连接池"""
        if self._logged_in:
            self.logout()
        await self._client.aclose()
