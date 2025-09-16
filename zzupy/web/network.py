import base64
import json
import random
import time

import httpx
from bs4 import BeautifulSoup
from pydantic import ValidationError

from zzupy.exception import LoginError, ParsingError, NetworkError, NotLoggedInError
from zzupy.models import OnlineDevices, AuthResult
from zzupy.utils import (
    get_local_ip,
    get_key,
    enc_pwd,
    JsonPParser,
)


class EPortalClient:


    def __init__(
        self,
        base_url: str,
        bind_address: str | None = None,
        force_bind: bool = False,
    ) -> None:
        """
        初始化一个 Portal 客户端

        :param base_url: Portal 服务器的 Base URL
        :param bind_address: 绑定的本地 IP
        :param force_bind: 即便 IP 绑定失败也在请求参数中使用该 IP
        """
        self._base_url = base_url
        self._client = httpx.Client()
        if bind_address is None:
            self._bind_address = get_local_ip()
        else:
            self._bind_address = bind_address
        self._bind_address_key = get_key(self._bind_address)
        if force_bind:
            try:
                transport = httpx.HTTPTransport(local_address=bind_address)
            except httpx.ConnectError:
                transport = httpx.HTTPTransport()
        else:
            transport = httpx.AsyncHTTPTransport(local_address=bind_address)
        self._client = httpx.Client(
            transport=transport,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "_client") and not self._client.is_closed:
            self._client.close()

    def portal_auth(
        self,
        account: str,
        password: str,
        encrypt: bool = False,
    ) -> AuthResult:
        """
        auth() 的底层实现，允许完全自定义账户

        :param account: 账户
        :param password: 密码
        :param encrypt: 是否启用加密
        :return: 认证结果
        :rtype: AuthResult
        :raises ParsingError: 如果无法解析 API 响应。
        :raises NetworkError: 如果发生网络错误。
        """
        if encrypt:
            params = [
                ("callback", enc_pwd("dr1003", self._bind_address_key)),
                ("login_method", enc_pwd("1", self._bind_address_key)),
                ("user_account", enc_pwd(f",0,{account}", self._bind_address_key)),
                (
                    "user_password",
                    enc_pwd(
                        base64.b64encode(password.encode()).decode(),
                        self._bind_address_key,
                    ),
                ),
                ("wlan_user_ip", enc_pwd(self._bind_address, self._bind_address_key)),
                ("wlan_user_ipv6", ""),
                ("wlan_user_mac", enc_pwd("000000000000", self._bind_address_key)),
                ("wlan_vlan_id", enc_pwd("0", self._bind_address_key)),
                ("wlan_ac_ip", ""),
                ("wlan_ac_name", ""),
                ("authex_enable", ""),
                ("jsVersion", enc_pwd("4.2.2", self._bind_address_key)),
                ("terminal_type", enc_pwd("3", self._bind_address_key)),
                ("lang", enc_pwd("zh-cn", self._bind_address_key)),
                ("encrypt", "1"),
                ("v", str(random.randint(500, 10499))),
                ("lang", "zh"),
            ]
        else:
            params = [
                ("callback", "dr1003"),
                ("login_method", "1"),
                ("user_account", f",0,{account}"),
                (
                    "user_password",
                    base64.b64encode(password.encode()).decode(),
                ),
                ("wlan_user_ip", self._bind_address),
                ("wlan_user_ipv6", ""),
                ("wlan_user_mac", "000000000000"),
                ("wlan_vlan_id", "0"),
                ("wlan_ac_ip", ""),
                ("wlan_ac_name", ""),
                ("authex_enable", ""),
                ("jsVersion", "4.2.2"),
                ("terminal_type", "3"),
                ("lang", "zh-cn"),
                ("v", str(random.randint(500, 10499))),
                ("lang", "zh"),
            ]
        try:
            response = self._client.get(
                f"{self._base_url}/eportal/portal/login", params=params
            )
            response.raise_for_status()
            res_json = json.loads(JsonPParser(response.text).data)
            return AuthResult.model_validate(res_json)
        except httpx.RequestError as e:
            raise NetworkError(f"发生网络错误: {e}") from e
        except (json.JSONDecodeError, ValueError, ValidationError) as e:
            raise ParsingError(f"无法解析的 API 响应: {e}") from e

    def auth(
        self, account: str, password: str, isp_suffix: str = None, encrypt: bool = False
    ) -> AuthResult:
        """
        进行 Portal 认证

        :param account: 账户
        :param password: 密码
        :param isp_suffix: 运营商后缀
        :param encrypt: 是否启用加密
        :return: 认证结果
        :rtype: AuthResult
        """
        return self.portal_auth(f"{account}{isp_suffix or ''}", password, encrypt)


class SelfServiceSystem:
    def __init__(self, base_url: str):
        self._client = httpx.Client(base_url=base_url)
        self.logged = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "_client") and not self._client.is_closed:
            self._client.close()

    def login(self, account: str, password: str) -> None:
        """
        登录

        :param str account: 账号
        :param str password: 密码
        :raises LoginError: 如果登录失败。
        :raises ParsingError: 如果无法解析登录页面。
        :raises NetworkError: 如果发生网络错误。
        """
        try:
            response = self._client.get(
                f"/Self/login/",
                follow_redirects=False,
            )
            response.raise_for_status()

            # 提取checkcode
            soup = BeautifulSoup(response.text, features="html.parser")
            checkcode_inputs = soup.find_all("input", attrs={"name": "checkcode"})
            if not checkcode_inputs:
                raise ParsingError(
                    "解析 HTML 失败，无法在登录页面上找到 'checkcode'。页面结构可能已更改。"
                )
            checkcode = checkcode_inputs[0]["value"]

            # 不能少
            self._client.get(
                f"/Self/login/randomCode",
                params={"t": str(random.random())},
            )

            data = {
                "foo": "",  # 笑死我了😆
                "bar": "",
                "checkcode": checkcode,
                "account": account,
                "password": password,
                "code": "",
            }

            response = self._client.post(
                "/Self/login/verify", data=data, follow_redirects=True
            )
            # 你妈教你这么设计 API 的？
            if "dashboard" not in response.url.path:
                raise LoginError("登录失败。这可能是因为账户和密码不正确。")
            self.logged = True
            return None
        except httpx.RequestError as e:
            raise NetworkError(f"发生网络错误: {e}") from e

    def get_online_devices(self) -> OnlineDevices:
        """
        获取当前在线设备

        :return: 在线设备列表
        :rtype: OnlineDevices
        :raise NotLoggedInError: 如果未登录。
        :raise ParsingError: 如果无法解析 API 返回数据。
        :raise NetworkError: 如果发生网络错误。
        """
        if not self.logged:
            raise NotLoggedInError("需要登录。")

        params = {
            "t": str(random.random()),
            "order": "asc",
            "_": str(int(time.time())),
        }
        try:
            response = self._client.get(
                f"/Self/dashboard/getOnlineList",
                params=params,
            )
            response.raise_for_status()
            return OnlineDevices.from_list(json.loads(response.text))
        except httpx.RequestError as e:
            raise NetworkError(f"发生网络错误: {e}") from e
        except json.JSONDecodeError as e:
            raise ParsingError(f"无法解析的 API 响应: {e}") from e

    def kick_device(self, session_id: str):
        """
        将设备踢下线

        :param session_id: Session ID
        :raise NotLoggedInError: 如果未登录
        """
        if not self.logged:
            raise NotLoggedInError("需要登录。")
        params = {
            "t": str(random.random()),
            "sessionid": session_id,
        }
        response = self._client.get(
            f"/Self/dashboard/tooffline",
            params=params,
        )
        response.raise_for_status()

    def logout(self):
        """
        登出

        :raise NotLoggedInError: 如果未登录
        """
        if not self.logged:
            raise NotLoggedInError("需要登录。")
        self._client.get(
            "/Self/login/logout",
        )
