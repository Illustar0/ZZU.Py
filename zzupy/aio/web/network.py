"""校园网模块"""

import base64
import json
import random
import re
import time
import urllib.parse
from typing import List
from urllib.parse import parse_qs

import httpx
import ifaddr
from bs4 import BeautifulSoup
from pydantic import ValidationError

from zzupy.exception import LoginError, ParsingError, NetworkError, NotLoggedInError
from zzupy.models import AuthResult, OnlineDevice, PortalInfo
from zzupy.utils import (
    get_local_ip,
    JsonPParser,
    XorCipher,
    require_auth,
)


async def discover_portal_info() -> PortalInfo | None:
    """自动发现校园网Portal认证信息

    Returns:
        PortalInfo | None: Portal信息，如果未检测到则返回None

    Raises:
        NetworkError: 如果网络错误或校园网已认证
        ParsingError: 如果响应格式异常
    """

    def _parse_portal_redirect(html_content: str) -> str | None:
        """解析Portal重定向链接"""
        soup = BeautifulSoup(html_content, features="html.parser")
        a_tag = soup.find("a")
        if a_tag is None or a_tag.get("href") is None:
            raise ParsingError("无法解析网页认证 URL")
        return a_tag.get("href")

    def _extract_user_ip(portal_url: str) -> str:
        """从Portal URL提取用户IP"""
        parsed = urllib.parse.urlparse(portal_url)
        query_params = parse_qs(parsed.query)

        user_ips = query_params.get("userip", [])
        if not user_ips:
            raise ParsingError("无法从Portal URL获取用户IP")
        return user_ips[0]

    def _extract_auth_url(portal_url: str) -> str:
        """提取网页认证 URL"""
        parsed = urllib.parse.urlparse(portal_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    async def _get_portal_server_url(client: httpx.AsyncClient, auth_url: str) -> str:
        """获取 Portal 服务器 URL"""
        DEFAULT_HTTP_PORT = 801
        DEFAULT_HTTPS_PORT = 802

        try:
            response = await client.get(f"{auth_url}/a41.js")
            js_params = _parse_js_config(response.text)

            hostname = urllib.parse.urlparse(auth_url).hostname

            if js_params.get("enableHttps") == 0:
                port = js_params.get("epHTTPPort", DEFAULT_HTTP_PORT)
                return f"http://{hostname}:{port}"
            else:
                port = js_params.get("enHTTPSPort", DEFAULT_HTTPS_PORT)
                return f"https://{hostname}:{port}"

        except Exception:
            # 降级到默认配置
            hostname = urllib.parse.urlparse(auth_url).hostname
            return f"http://{hostname}:{DEFAULT_HTTP_PORT}"

    def _parse_js_config(js_content: str) -> dict[str, int]:
        """解析 JavaScript 配置参数"""
        pattern = r"var\s+(\w+)\s*=\s*(\d+);"
        matches = re.findall(pattern, js_content)
        return {key: int(value) for key, value in matches}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get("http://bilibili.com", follow_redirects=True)

            if str(response.url).startswith("https://"):
                raise NetworkError("未被 MITM，请检查校园网是否已认证")

            portal_url = _parse_portal_redirect(response.text)

            user_ip = _extract_user_ip(portal_url)

            auth_url = _extract_auth_url(portal_url)
            portal_server_url = await _get_portal_server_url(client, auth_url)

            return PortalInfo(
                auth_url=auth_url, portal_server_url=portal_server_url, user_ip=user_ip
            )

    except httpx.RequestError as e:
        raise NetworkError(f"网络请求失败: {e}")
    except Exception as e:
        raise NetworkError(f"Portal信息发现失败: {e}")


class EPortalClient:
    """Portal 认证客户端 / 校园网认证客户端"""

    def __init__(
        self,
        base_url: str,
        bind_address: str | None = None,
        force_bind: bool = False,
    ) -> None:
        """初始化一个 Portal 客户端

        Args:
            base_url: Portal 服务器的 Base URL
            bind_address: 绑定的本地 IP
            force_bind: 即便 IP 绑定失败也在请求参数中使用该 IP。

                如果你在路由器后使用本方法，则需要把 `bind_address` 填写为路由器分配的内网 IP 并启用 `force_bind`
        """
        self._base_url = base_url
        self._client = httpx.AsyncClient()
        if bind_address is None:
            self._bind_address = get_local_ip()
        else:
            self._bind_address = bind_address
        self._xor_cipher = XorCipher(self._bind_address)
        if force_bind:
            local_ips = [
                ip.ip for adapter in ifaddr.get_adapters() for ip in adapter.ips
            ]

            if self._bind_address in local_ips:
                transport = httpx.HTTPTransport(local_address=bind_address)
            else:
                transport = httpx.HTTPTransport()

        else:
            transport = httpx.HTTPTransport(local_address=bind_address)
        self._client = httpx.AsyncClient(
            transport=transport,
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "_client") and not self._client.is_closed:
            await self._client.aclose()

    async def portal_auth(
        self,
        account: str,
        password: str,
        encrypt: bool = False,
    ) -> AuthResult:
        """[`auth()`][zzupy.web.EPortalClient.auth] 的底层实现，允许完全自定义账户

        Args:
            account: 账户
            password: 密码
            encrypt: 是否启用加密

        Returns:
            AuthResult: 认证结果

        Raises:
            ParsingError: 如果无法解析 API 响应。
            NetworkError: 如果发生网络错误。
        """
        if encrypt:
            params = [
                ("callback", self._xor_cipher.encrypt("dr1003")),
                ("login_method", self._xor_cipher.encrypt("1")),
                ("user_account", self._xor_cipher.encrypt(f",0,{account}")),
                (
                    "user_password",
                    self._xor_cipher.encrypt(
                        base64.b64encode(password.encode()).decode(),
                    ),
                ),
                ("wlan_user_ip", self._xor_cipher.encrypt(self._bind_address)),
                ("wlan_user_ipv6", ""),
                ("wlan_user_mac", self._xor_cipher.encrypt("000000000000")),
                ("wlan_vlan_id", self._xor_cipher.encrypt("0")),
                ("wlan_ac_ip", ""),
                ("wlan_ac_name", ""),
                ("authex_enable", ""),
                ("jsVersion", self._xor_cipher.encrypt("4.2.2")),
                ("terminal_type", self._xor_cipher.encrypt("3")),
                ("lang", self._xor_cipher.encrypt("zh-cn")),
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
            response = await self._client.get(
                f"{self._base_url}/eportal/portal/login", params=params
            )
            response.raise_for_status()
            res_json = json.loads(JsonPParser(response.text).data)
            return AuthResult.model_validate(res_json)
        except httpx.RequestError as e:
            raise NetworkError(f"发生网络错误: {e}") from e
        except (json.JSONDecodeError, ValueError, ValidationError) as e:
            raise ParsingError(f"无法解析的 API 响应: {e}") from e

    async def auth(
        self, account: str, password: str, isp_suffix: str = None, encrypt: bool = False
    ) -> AuthResult:
        """进行 Portal 认证

        Args:
            account: 账户
            password: 密码
            isp_suffix: 运营商后缀
            encrypt: 是否启用加密

        Returns:
            AuthResult: 认证结果
        """
        return await self.portal_auth(f"{account}{isp_suffix or ''}", password, encrypt)


class SelfServiceSystem:
    """自助服务系统"""

    def __init__(self, base_url: str):
        self._client = httpx.AsyncClient(base_url=base_url)
        self._logged_in = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def login(self, account: str, password: str) -> None:
        """登录

        Args:
            account (str): 账号
            password (str): 密码

        Raises:
            LoginError: 如果登录失败。
            ParsingError: 如果无法解析登录页面。
            NetworkError: 如果发生网络错误。
        """
        try:
            response = await self._client.get(
                "/Self/login/",
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
            await self._client.get(
                "/Self/login/randomCode",
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

            response = await self._client.post(
                "/Self/login/verify", data=data, follow_redirects=True
            )
            # 你妈教你这么设计 API 的？
            if "dashboard" not in response.url.path:
                raise LoginError("登录失败。这可能是因为账户和密码不正确。")
            self._logged_in = True
            return None
        except httpx.RequestError as e:
            raise NetworkError(f"发生网络错误: {e}") from e

    @require_auth
    async def get_online_devices(self) -> List[OnlineDevice]:
        """获取当前在线设备

        Returns:
            List[OnlineDevice]: 在线设备列表

        Raises:
            NotLoggedInError: 如果未登录。
            ParsingError: 如果无法解析 API 返回数据。
            NetworkError: 如果发生网络错误。
        """
        params = {
            "t": str(random.random()),
            "order": "asc",
            "_": str(int(time.time())),
        }
        try:
            response = await self._client.get(
                "/Self/dashboard/getOnlineList",
                params=params,
            )
            response.raise_for_status()
            response_data = response.json()
            return [OnlineDevice(**device) for device in response_data]
        except httpx.RequestError as e:
            raise NetworkError(f"发生网络错误: {e}") from e
        except json.JSONDecodeError as e:
            raise ParsingError(f"无法解析的 API 响应: {e}") from e

    @require_auth
    async def kick_device(self, session_id: str):
        """将设备踢下线

        Args:
            session_id: Session ID

        Raises:
            NotLoggedInError: 如果未登录
        """
        if not self._logged_in:
            raise NotLoggedInError("需要登录。")
        params = {
            "t": str(random.random()),
            "sessionid": session_id,
        }
        response = await self._client.get(
            "/Self/dashboard/tooffline",
            params=params,
        )
        response.raise_for_status()

    @require_auth
    async def logout(self):
        """登出

        Raises:
            NotLoggedInError: 如果未登录
        """
        if not self._logged_in:
            raise NotLoggedInError("需要登录。")
        await self._client.get(
            "/Self/login/logout",
        )
        self._logged_in = False

    @require_auth
    async def close(self):
        await self.logout()
        await self._client.aclose()
