"""统一认证"""

import base64
import json
import threading
from datetime import datetime
from typing import Final

import httpx2
import jwt
from pydantic import ValidationError

from zzupy.app.interfaces import ICASClient
from zzupy.crypto import RSAPublicKey, padding, serialization
from zzupy.exception import (
    LoginError,
    ParsingError,
    NetworkError,
    OperationError,
    MFAError,
)
from zzupy.logging import build_http_event_hooks, log_http_response_body, logger
from zzupy.model.auth import PersonalInfo, PersonalInfoModel, PersonalInfoCardModel
from zzupy.utils import require_auth


class CASClient(ICASClient):
    """统一认证系统 (CAS) App 客户端。"""

    APP_VERSION: Final = "SWSuperApp/1.1.1"
    APP_ID: Final = "com.supwisdom.zzu"
    OS_TYPE: Final = "android"

    PUBLIC_KEY_URL: Final = "https://cas.s.zzu.edu.cn/token/jwt/publicKey"
    LOGIN_URL: Final = "https://cas.s.zzu.edu.cn/token/password/passwordLogin"
    PERSONAL_INFO_URL: Final = (
        "https://authx-service.s.zzu.edu.cn/personal/api/v1/personal/me/user"
    )
    PERSONAL_INFO_CARD_URL: Final = "https://info.s.zzu.edu.cn/portal-api/v1/thrid-adapter/get-person-info-card-list"
    MFA_DETECT_URL: Final = "https://cas.s.zzu.edu.cn/token/mfa/detect"
    MFA_SECURE_PHONE_INIT_URL: Final = (
        "https://cas.s.zzu.edu.cn/token/mfa/initByType/securephone"
    )
    MFA_ATTEST_SERVER_URL: Final = "https://cas.s.zzu.edu.cn/attest/api/guard"

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
        self._client = httpx2.Client(event_hooks=build_http_event_hooks())
        self._account = account
        self._password = password
        self._public_key: RSAPublicKey | None = None
        self._user_token: str | None = None
        self._refresh_token: str | None = None
        self._logged_in: bool = False
        self._refresh_timer: threading.Timer | None = None
        self._device_id = "ZZU.Py"
        self.mfa = self.MFAClient(self)

    def __enter__(self) -> "CASClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def set_token(self, user_token: str, refresh_token: str) -> None:
        """设置统一认证 Token。

        Args:
            user_token: `userToken`。对豫见郑大 APP 抓包获取，或账密登录后访问 [`user_token`][zzupy.app.auth.CASClient.user_token] 获取
            refresh_token: `refreshToken`。对豫见郑大 APP 抓包获取，或账密登录后访问 [`refresh_token`][zzupy.app.auth.CASClient.refresh_token] 获取
        """
        self._user_token = user_token
        self._refresh_token = refresh_token

    def set_device(self, device_id: str) -> None:
        """设置认证请求使用的设备标识。

        Args:
            device_id: 登录和 MFA 检测请求中的 `deviceId`。
        """
        self._device_id = device_id
        self.mfa.reset()

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
        user_token = self._user_token
        refresh_token = self._refresh_token
        if user_token is None or refresh_token is None:
            if pre_set_token:
                return False
            raise LoginError("登录失败，认证服务未返回完整 Token。")

        if pre_set_token:
            try:
                user_token_plain: dict = jwt.decode(
                    user_token, options={"verify_signature": False}
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
                    self._refresh_timer = threading.Timer(
                        refresh_delay,
                        self.login,
                        kwargs={"force_login": True},
                    )
                    self._refresh_timer.daemon = True
                    self._refresh_timer.start()
                    logger.debug(
                        f"已设置自动刷新定时器，将在 {refresh_delay:.0f} 秒后刷新 Token"
                    )

            except jwt.InvalidTokenError:
                logger.error("userToken 无效，将使用账密登录并更新 userToken")
                return False

            try:
                jwt.decode(refresh_token, options={"verify_signature": False})
            except jwt.ExpiredSignatureError:
                logger.error("refreshToken 已过期，将使用账密登录并更新 refreshToken")
                return False
            except jwt.InvalidTokenError:
                logger.error("refreshToken 无效，将使用账密登录并更新 refreshToken")
                return False
        else:
            try:
                jwt.decode(user_token, options={"verify_signature": False})
            except jwt.InvalidTokenError:
                raise LoginError(
                    "登录失败，下发的 userToken 无效。这是意料之外的行为，请前往 Issue 报告此错误。"
                )

            try:
                jwt.decode(refresh_token, options={"verify_signature": False})
            except jwt.InvalidTokenError:
                raise LoginError(
                    "登录失败，下发的 refreshToken 无效。这是意料之外的行为，请前往 Issue 报告此错误。"
                )

        logger.info("userToken 和 refreshToken 有效")
        return True

    def _get_public_key(self) -> RSAPublicKey:
        """从 CAS 服务器获取 RSA 公钥。"""
        logger.debug("正在从 {} 获取公钥...", self.PUBLIC_KEY_URL)
        headers = {"User-Agent": "okhttp/3.12.1"}
        try:
            response = self._client.get(self.PUBLIC_KEY_URL, headers=headers)
            response.raise_for_status()
            public_key_pem = response.content
            return serialization.load_pem_public_key(public_key_pem)
        except httpx2.RequestError as exc:
            logger.error("获取公钥失败，网络请求异常: {}", exc)
            raise NetworkError.from_exception(
                exc,
                "获取公钥失败，无法连接到认证服务器。",
                context={"url": self.PUBLIC_KEY_URL},
            ) from exc
        except Exception as exc:
            logger.error("解析公钥失败: {}", exc)
            raise ParsingError.from_exception(
                exc,
                "认证服务公钥格式无效",
                context={"url": self.PUBLIC_KEY_URL},
            ) from exc

    @staticmethod
    def _encrypt_and_encode(data: str, public_key: RSAPublicKey) -> str:
        """使用公钥加密数据，进行 Base64 编码，并添加 '__RSA__' 前缀。"""
        encrypted_bytes = public_key.encrypt(data.encode("utf-8"), padding.PKCS1v15())
        encoded_bytes = base64.b64encode(encrypted_bytes)
        return f"__RSA__{encoded_bytes.decode('utf-8')}"

    class MFAClient:
        """统一认证 MFA 辅助客户端。

        本客户端由 [`CASClient`][zzupy.app.auth.CASClient] 自动创建，通常通过
        [`CASClient.mfa`][zzupy.app.auth.CASClient.mfa] 访问。它负责检测 MFA
        状态、发送手机号验证码并校验验证码。
        """

        def __init__(self, cas: "CASClient") -> None:
            """初始化 MFA 辅助客户端。

            Args:
                cas: 所属的统一认证客户端。
            """
            self._cas = cas
            self._client = self._cas._client
            self.state = ""
            self.gid = ""
            self.attest_server_url = ""
            self.required = False
            self.secure_phone_available = False
            self.verified = False

        def reset(self) -> None:
            """清除当前 MFA 流程状态。"""
            self.state = ""
            self.gid = ""
            self.attest_server_url = ""
            self.required = False
            self.secure_phone_available = False
            self.verified = False

        def _app_headers(self) -> dict[str, str]:
            """构造 MFA 请求头。"""
            return {"User-Agent": f"{self._cas.APP_VERSION}()"}

        def _ensure_public_key(self) -> RSAPublicKey:
            """确保统一认证客户端已获取 RSA 公钥。"""
            if self._cas._public_key is None:
                self._cas._public_key = self._cas._get_public_key()
            return self._cas._public_key

        def _attest_url(self, path: str) -> str:
            """拼接 MFA 校验服务 URL。"""
            base_url = self.attest_server_url or self._cas.MFA_ATTEST_SERVER_URL
            return f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        def is_required(self) -> bool:
            """检测当前环境是否需要 MFA 验证

            Returns:
                是否需要 MFA 验证

            Raises:
                OperationError: 如果检测失败。
                ParsingError: 如果服务器响应无法解析。
                NetworkError: 如果出现网络错误。

            """
            public_key = self._ensure_public_key()
            encrypted_account = self._cas._encrypt_and_encode(
                self._cas._account, public_key
            )
            encrypted_password = self._cas._encrypt_and_encode(
                self._cas._password, public_key
            )

            params = {
                "username": encrypted_account,
                "password": encrypted_password,
                "deviceId": self._cas._device_id,
            }

            try:
                logger.debug("正在向 {} 发送 MFA 检测请求...", self._cas.MFA_DETECT_URL)
                response = self._client.post(
                    self._cas.MFA_DETECT_URL,
                    params=params,
                    headers=self._app_headers(),
                )
                response.raise_for_status()

                log_http_response_body(
                    self._cas.MFA_DETECT_URL,
                    response.text,
                    content_type=response.headers.get("content-type"),
                    level="DEBUG",
                )

                data: dict = response.json()

                if data.get("code") != 0:
                    error_message = data.get("message", "未知错误")
                    logger.error("MFA 检测请求失败: {}", error_message)
                    raise LoginError(f"MFA 检测失败: {error_message}")

                mfa_data = data["data"]
                self.state = mfa_data["state"]
                self.gid = ""
                self.attest_server_url = ""
                self.required = bool(mfa_data["need"])
                self.secure_phone_available = bool(
                    mfa_data.get("mfaTypeSecurePhone", False)
                )
                self.verified = False
                logger.info("MFA 检测成功")
                return self.required

            except httpx2.HTTPStatusError as exc:
                logger.error("MFA 检测请求返回失败状态码: {}", exc.response.status_code)
                raise OperationError.from_http_status(
                    exc,
                    "服务器返回错误状态",
                    context={"url": self._cas.MFA_DETECT_URL},
                ) from exc
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.error("从 /mfa/detect 响应中提取 MFA 状态失败: {}", exc)
                raise ParsingError.from_exception(
                    exc,
                    "服务器响应格式不正确",
                    context={"url": self._cas.MFA_DETECT_URL},
                ) from exc
            except httpx2.RequestError as exc:
                logger.error("MFA 检测网络请求失败: {}", exc)
                raise NetworkError.from_exception(
                    exc,
                    "网络连接异常",
                    context={"url": self._cas.MFA_DETECT_URL},
                ) from exc

        def _init_secure_phone(self) -> None:
            """初始化手机号 MFA。

            Raises:
                LoginError: 如果当前登录不需要 MFA 验证。
                OperationError: 如果当前账号不支持手机号 MFA，或初始化失败。
                ParsingError: 如果服务器响应无法解析。
                NetworkError: 如果出现网络错误。
            """
            if not self.state:
                if not self.is_required():
                    raise LoginError("当前登录不需要 MFA 验证。")
            elif not self.required:
                raise LoginError("当前登录不需要 MFA 验证。")

            if not self.secure_phone_available:
                raise OperationError("当前账号不支持手机号 MFA。")

            params = {"state": self.state}
            try:
                logger.debug(
                    "正在向 {} 发送手机号 MFA 初始化请求...",
                    self._cas.MFA_SECURE_PHONE_INIT_URL,
                )
                response = self._client.get(
                    self._cas.MFA_SECURE_PHONE_INIT_URL,
                    params=params,
                    headers=self._app_headers(),
                )
                response.raise_for_status()
                log_http_response_body(
                    self._cas.MFA_SECURE_PHONE_INIT_URL,
                    response.text,
                    content_type=response.headers.get("content-type"),
                    level="DEBUG",
                )

                data: dict = response.json()
                if data.get("code") != 0:
                    error_message = data.get("message", "未知错误")
                    logger.error("手机号 MFA 初始化失败: {}", error_message)
                    raise OperationError(f"手机号 MFA 初始化失败: {error_message}")

                mfa_data = data["data"]
                self.gid = mfa_data["gid"]
                self.attest_server_url = mfa_data.get("attestServerUrl") or ""
                logger.info("手机号 MFA 初始化成功")

            except httpx2.HTTPStatusError as exc:
                logger.error(
                    "手机号 MFA 初始化返回失败状态码: {}", exc.response.status_code
                )
                raise OperationError.from_http_status(
                    exc,
                    "服务器返回错误状态",
                    context={"url": self._cas.MFA_SECURE_PHONE_INIT_URL},
                ) from exc
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.error(
                    "从 /mfa/initByType/securephone 响应中提取数据失败: {}", exc
                )
                raise ParsingError.from_exception(
                    exc,
                    "服务器响应格式不正确",
                    context={"url": self._cas.MFA_SECURE_PHONE_INIT_URL},
                ) from exc
            except httpx2.RequestError as exc:
                logger.error("手机号 MFA 初始化网络请求失败: {}", exc)
                raise NetworkError.from_exception(
                    exc,
                    "网络连接异常",
                    context={"url": self._cas.MFA_SECURE_PHONE_INIT_URL},
                ) from exc

        def request_sms_code(self) -> None:
            """发送 MFA 短信验证码。

            如果尚未初始化手机号 MFA，会自动调用内部初始化流程。

            Raises:
                LoginError: 如果当前登录不需要 MFA 验证。
                OperationError: 如果短信发送失败。
                ParsingError: 如果服务器响应无法解析。
                NetworkError: 如果出现网络错误。
            """
            if not self.gid:
                self._init_secure_phone()

            url = self._attest_url("api/guard/securephone/send")
            try:
                logger.debug("正在向 {} 发送 MFA 短信验证码请求...", url)
                response = self._client.post(
                    url,
                    json={"gid": self.gid},
                    headers=self._app_headers(),
                )
                response.raise_for_status()
                log_http_response_body(
                    url,
                    response.text,
                    content_type=response.headers.get("content-type"),
                    level="DEBUG",
                )

                data: dict = response.json()
                if data.get("code") != 0:
                    error_message = data.get("message", "未知错误")
                    logger.error("MFA 短信验证码发送失败: {}", error_message)
                    raise OperationError(f"MFA 短信验证码发送失败: {error_message}")

                data["data"]["result"]
                logger.info("MFA 短信验证码发送成功")
                return None

            except httpx2.HTTPStatusError as exc:
                logger.error(
                    "MFA 短信验证码发送返回失败状态码: {}", exc.response.status_code
                )
                raise OperationError.from_http_status(
                    exc,
                    "服务器返回错误状态",
                    context={"url": url},
                ) from exc
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.error(
                    "从 /api/guard/securephone/send 响应中提取数据失败: {}", exc
                )
                raise ParsingError.from_exception(
                    exc,
                    "服务器响应格式不正确",
                    context={"url": url},
                ) from exc
            except httpx2.RequestError as exc:
                logger.error("MFA 短信验证码发送网络请求失败: {}", exc)
                raise NetworkError.from_exception(
                    exc,
                    "网络连接异常",
                    context={"url": url},
                ) from exc

        def send_sms(self) -> None:
            """[`request_sms_code()`][zzupy.app.auth.CASClient.MFAClient.request_sms_code] 的别名。"""
            self.request_sms_code()

        def verify_sms_code(self, code: str) -> str:
            """校验 MFA 短信验证码。

            调用前必须先发送 MFA 短信验证码。
            校验成功后，[`CASClient.login()`][zzupy.app.auth.CASClient.login]
            会使用当前 MFA state 完成登录。

            Args:
                code: 短信验证码。

            Returns:
                可用于登录的 MFA state。

            Raises:
                MFAError: 如果尚未发送 MFA 短信验证码。
                LoginError: 如果验证码校验失败。
                OperationError: 如果服务器返回失败状态。
                ParsingError: 如果服务器响应无法解析。
                NetworkError: 如果出现网络错误。
            """
            if not self.gid:
                raise MFAError("MFA 状态错误，请先发送短信验证码。")

            url = self._attest_url("api/guard/securephone/valid")
            try:
                logger.debug("正在向 {} 发送 MFA 短信验证码校验请求...", url)
                response = self._client.post(
                    url,
                    json={"gid": self.gid, "code": code},
                    headers=self._app_headers(),
                )
                response.raise_for_status()
                log_http_response_body(
                    url,
                    response.text,
                    content_type=response.headers.get("content-type"),
                    level="DEBUG",
                )

                data: dict = response.json()
                if data.get("code") != 0:
                    error_message = data.get("message", "未知错误")
                    logger.error("MFA 短信验证码校验失败: {}", error_message)
                    raise LoginError(f"MFA 短信验证码校验失败: {error_message}")

                mfa_data = data["data"]
                if mfa_data.get("status") != 2:
                    logger.error(
                        "MFA 短信验证码校验失败，状态码: {}", mfa_data.get("status")
                    )
                    raise LoginError("MFA 短信验证码校验失败。")

                mfa_data["result"]
                self.verified = True
                logger.info("MFA 短信验证码校验成功")
                return self.state

            except httpx2.HTTPStatusError as exc:
                logger.error(
                    "MFA 短信验证码校验返回失败状态码: {}", exc.response.status_code
                )
                raise OperationError.from_http_status(
                    exc,
                    "服务器返回错误状态",
                    context={"url": url},
                ) from exc
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                logger.error(
                    "从 /api/guard/securephone/valid 响应中提取数据失败: {}", exc
                )
                raise ParsingError.from_exception(
                    exc,
                    "服务器响应格式不正确",
                    context={"url": url},
                ) from exc
            except httpx2.RequestError as exc:
                logger.error("MFA 短信验证码校验网络请求失败: {}", exc)
                raise NetworkError.from_exception(
                    exc,
                    "网络连接异常",
                    context={"url": url},
                ) from exc

        def verify_sms(self, code: str) -> str:
            """[`verify_sms_code()`][zzupy.app.auth.CASClient.MFAClient.verify_sms_code] 的别名。"""
            return self.verify_sms_code(code)

    def login(self, force_login: bool = False) -> None:
        """登录统一认证。

        成功后，[`userToken`][zzupy.app.auth.CASClient.user_token] 和 [`refreshToken`][zzupy.app.auth.CASClient.refresh_token] 会被存储在实例中.

        若 [`user_token`][zzupy.app.auth.CASClient.user_token] 和 [`refresh_token`][zzupy.app.auth.CASClient.refresh_token] 已通过 [`set_token`][zzupy.app.auth.CASClient.set_token] 设置且有效，则会跳过账密登录。

        Args:
            force_login: 强制使用账密登录

        Raises:
            LoginError: 如果登录失败。
            ParsingError: 如果服务器响应无法解析。
            NetworkError: 如果出现网络错误。
        """
        if self._public_key is None:
            self._public_key = self._get_public_key()

        if self.mfa.state:
            mfa_state_invalid = self.mfa.required and not self.mfa.verified
        else:
            mfa_state_invalid = not self.mfa.is_required()
        if mfa_state_invalid:
            raise MFAError("MFA 状态错误，当前会话可能需要 MFA 验证")

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
            "deviceId": self._device_id,
            "clientId": "",
            "mfaState": self.mfa.state,
        }

        try:
            logger.debug("正在向 {} 发送登录请求...", self.LOGIN_URL)
            response = self._client.post(self.LOGIN_URL, params=params, headers=headers)
            response.raise_for_status()

            log_http_response_body(
                self.LOGIN_URL,
                response.text,
                content_type=response.headers.get("content-type"),
                level="DEBUG",
            )

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

        except httpx2.HTTPStatusError as exc:
            logger.error("登录请求返回失败状态码: {}", exc.response.status_code)
            raise LoginError.from_http_status(
                exc,
                "服务器返回错误状态",
                context={"url": self.LOGIN_URL},
            ) from exc
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("从 /passwordLogin 响应中提取 token 失败: {}", exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": self.LOGIN_URL},
            ) from exc
        except httpx2.RequestError as exc:
            logger.error("登录网络请求失败: {}", exc)
            raise NetworkError.from_exception(
                exc,
                "网络连接异常",
                context={"url": self.LOGIN_URL},
            ) from exc

    @require_auth
    def get_user_info(self) -> PersonalInfo:
        """获取当前用户的聚合个人信息。

        返回学号、姓名、身份类型、学院、邮箱未读数、一卡通余额和科研信息数量。

        Returns:
            当前用户的个人信息

        Raises:
            OperationError: 如果服务端返回失败结果。
            ParsingError: 如果响应解析失败。
            NetworkError: 如果网络请求失败。
        """
        url = f"{self.PERSONAL_INFO_URL}"
        try:
            headers = {"X-Id-Token": self._user_token}
            response = self._client.get(url, headers=headers)
            response.raise_for_status()
            log_http_response_body(
                url,
                response.text,
                content_type=response.headers.get("content-type"),
            )

            response_data = response.json()

        except httpx2.HTTPStatusError as exc:
            logger.error("{}请求返回失败状态码: {}", url, exc.response.status_code)
            raise OperationError.from_http_status(
                exc,
                "服务器返回错误状态",
                context={"url": url},
            ) from exc
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("从 {} 响应中提取数据失败: {}", url, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": url},
            ) from exc
        except httpx2.RequestError as exc:
            logger.error("{} 请求失败: {}", url, exc)
            raise NetworkError.from_exception(
                exc,
                "网络连接异常",
                context={"url": url},
            ) from exc

        if response_data["code"] != 0:
            logger.error("服务器返回消息 {}", response_data["message"])
            raise OperationError(f"服务器返回消息 {response_data['message']}")

        try:
            personal_info_data = PersonalInfoModel.model_validate(response_data)
        except ValidationError as exc:
            logger.error("从 {} 响应中解析数据失败: {}", url, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": url},
            ) from exc

        url = f"{self.PERSONAL_INFO_CARD_URL}"
        try:
            headers = {"X-Id-Token": self._user_token}
            response = self._client.get(url, headers=headers)
            response.raise_for_status()
            log_http_response_body(
                url,
                response.text,
                content_type=response.headers.get("content-type"),
            )

            response_data = response.json()

        except httpx2.HTTPStatusError as exc:
            logger.error("{}请求返回失败状态码: {}", url, exc.response.status_code)
            raise OperationError.from_http_status(
                exc,
                "服务器返回错误状态",
                context={"url": url},
            ) from exc
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("从 {} 响应中提取数据失败: {}", url, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": url},
            ) from exc
        except httpx2.RequestError as exc:
            logger.error("{} 请求失败: {}", url, exc)
            raise NetworkError.from_exception(
                exc,
                "网络连接异常",
                context={"url": url},
            ) from exc

        if response_data["code"] != 0:
            logger.error("服务器返回消息 {}", response_data["message"])
            raise OperationError(f"服务器返回消息 {response_data['message']}")

        try:
            personal_info_card_data = PersonalInfoCardModel.model_validate(
                response_data
            )
        except ValidationError as exc:
            logger.error("从 {} 响应中解析数据失败: {}", url, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": url},
            ) from exc

        return PersonalInfo(
            uid=personal_info_data.data.attributes.user_uid,
            name=personal_info_data.data.attributes.user_name,
            student_type=personal_info_data.data.attributes.identity_type_name,
            student_type_id=personal_info_data.data.attributes.identity_type_id,
            college=personal_info_data.data.attributes.organization_name,
            college_id=personal_info_data.data.attributes.organization_id,
            unread_email_count=int(personal_info_card_data.data[0].amount),
            balance=float(personal_info_card_data.data[1].amount),
            research_count=int(personal_info_card_data.data[2].amount),
        )

    @require_auth
    def logout(self) -> None:
        """登出账户，清除 Cookie 但保留连接池"""
        self._client.cookies.clear()
        self._client.headers.clear()
        self._user_token = None
        self._refresh_token = None
        self.mfa.reset()
        if self._refresh_timer is not None:
            self._refresh_timer.cancel()
            self._refresh_timer = None
        self._logged_in = False

    def close(self) -> None:
        """清除 Cookie 和连接池"""
        if self._logged_in:
            self.logout()
        self._client.close()
