import base64
import json
import random
import re
import time
from typing import List, Tuple

import httpx
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

from zzupy.models import OnlineDevices
from zzupy.utils import (
    get_ip_by_interface,
    sync_wrapper,
    get_local_ip,
    get_interface_by_ip,
    get_key,
    enc_pwd,
)


class Network:
    def __init__(self, parent):
        """
        初始化网络管理类

        :param parent: 父对象，通常是ZZUPy实例
        """
        self._parent = parent
        self.account = self._parent._usercode
        self._JSessionID: str = ""
        self._checkcode: str = ""
        self.system_ua: str = ""
        self.system_loginurl: str = ""
        # 默认请求头
        self._default_headers = {
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "keep-alive",
        }

    def portal_auth(
        self,
        interface: str = None,
        authurl: str = "http://10.2.7.8:801",
        ua: str = None,
        isp: str = "campus",
    ) -> Tuple[str, bool, str]:
        """
        进行校园网认证

        :param str interface: 网络接口名
        :param str authurl: PortalAuth 服务器。根据情况修改
        :param str ua: User-Agent，默认随机生成
        :param str isp: 运营商。可选项：campus,cm,ct,cu
        :returns: Tuple[str, bool, str]

            - **interface** (str) – 本次认证调用的网络接口。
            - **success** (bool) – 认证是否成功。(不可信，有时失败仍可正常上网)
            - **msg** (str) – 服务端返回信息。
        :rtype: Tuple[str,bool,str]
        """
        return sync_wrapper(self.portal_auth_async)(interface, authurl, ua, isp)

    async def portal_auth_async(
        self,
        interface: str = None,
        authurl: str = "http://10.2.7.8:801",
        ua: str = None,
        isp: str = "campus",
    ) -> Tuple[str, bool, str]:
        """
        异步进行校园网认证

        :param str interface: 网络接口名
        :param str authurl: PortalAuth 服务器。根据情况修改
        :param str ua: User-Agent，默认随机生成
        :param str isp: 运营商。可选项：campus,cm,ct,cu
        :returns: Tuple[str, bool, str]

            - **interface** (str) – 本次认证调用的网络接口。
            - **success** (bool) – 认证是否成功。(不可信，有时失败仍可正常上网)
            - **msg** (str) – 服务端返回信息。
        :rtype: Tuple[str,bool,str]
        """
        if ua is None:
            ua = UserAgent().random

        # 设置账号格式
        if isp == "campus":
            self.account = self._parent._usercode
        elif isp == "ct":
            self.account = f"{self._parent._usercode}@cmcc"
        elif isp == "cu":
            self.account = f"{self._parent._usercode}@cmcc"
        elif isp == "cm":
            self.account = f"{self._parent._usercode}@cmcc"
        else:
            self.account = f"{self._parent._usercode}"

        # 创建带有本地IP的异步客户端
        if interface is not None:
            transport = httpx.AsyncHTTPTransport(
                local_address=get_ip_by_interface(interface)
            )
        else:
            local_ip = get_local_ip()
            interface = get_interface_by_ip(local_ip)
            transport = httpx.AsyncHTTPTransport(local_address=local_ip)
        async with httpx.AsyncClient(transport=transport) as local_client:
            return await self._auth_async(local_client, interface, authurl, ua)

    async def _auth_async(
        self,
        client: httpx.AsyncClient,
        interface: str,
        baseURL: str,
        ua: str,
    ) -> Tuple[str, bool, str]:
        """
        异步执行认证请求

        :param client: httpx异步客户端
        :param interface: 网络接口
        :param baseURL: 认证服务器基础URL
        :param ua: User-Agent
        :return: 认证结果元组
        """
        ip = get_ip_by_interface(interface)
        key = get_key(ip)
        headers = {
            **self._default_headers,
            "Accept": "*/*",
            "Referer": "http://10.2.7.8/",
            "User-Agent": ua,
        }

        params = [
            ("callback", enc_pwd("dr1003", key)),
            ("login_method", enc_pwd("1", key)),
            ("user_account", enc_pwd(f",0,{self.account}", key)),
            (
                "user_password",
                enc_pwd(
                    base64.b64encode(self._parent._password.encode()).decode(), key
                ),
            ),
            ("wlan_user_ip", enc_pwd(ip, key)),
            ("wlan_user_ipv6", ""),
            ("wlan_user_mac", enc_pwd("000000000000", key)),
            ("wlan_ac_ip", ""),
            ("wlan_ac_name", ""),
            ("jsVersion", enc_pwd("4.2.1", key)),
            ("terminal_type", enc_pwd("1", key)),
            ("lang", enc_pwd("zh-cn", key)),
            ("encrypt", "1"),
            ("v", str(random.randint(500, 10499))),
            ("lang", "zh"),
        ]

        try:
            response = await client.get(
                f"{baseURL}/eportal/portal/login", params=params, headers=headers
            )
            res_json = json.loads(re.findall(r"dr1003\((.*?)\);", response.text)[0])
            success = res_json["result"] != 0
            return interface, success, res_json["msg"]
        except Exception as e:
            return interface, False, f"认证请求失败: {str(e)}"

    def login(self, loginurl: str = "http://10.2.7.16:8080", ua: str = None) -> bool:
        """
        登录自助服务平台

        :param str loginurl: 自助服务平台的登录 URL
        :param str ua: User Agent，默认随机生成
        :return: 登录是否成功
        :rtype: bool
        """
        return sync_wrapper(self.login_async)(loginurl, ua)

    async def login_async(
        self, loginurl: str = "http://10.2.7.16:8080", ua: str = None
    ) -> bool:
        """
        异步登录自助服务平台

        :param str loginurl: 自助服务平台的登录 URL
        :param str ua: User Agent，默认随机生成
        :return: 登录是否成功
        :rtype: bool
        """
        if ua is None:
            ua = UserAgent().random

        self.system_ua = ua
        self.system_loginurl = loginurl

        # 第一步：获取登录页面和JSESSIONID
        headers = {
            **self._default_headers,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.system_ua,
        }

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.system_loginurl}/Self/login/",
                    headers=headers,
                    follow_redirects=False,
                )

                if response.status_code != 200:
                    return False

                # 提取JSESSIONID
                self._JSessionID = (
                    response.headers.get("set-cookie", "").split("=")[1].split(";")[0]
                )

                # 提取checkcode
                soup = BeautifulSoup(response.text, features="html.parser")
                checkcode_inputs = soup.find_all("input", attrs={"name": "checkcode"})
                if not checkcode_inputs:
                    return False
                self._checkcode = checkcode_inputs[0]["value"]

                # 第二步：获取验证码图片（可能不是必需的，但保留原有逻辑）
                cookies = {"JSESSIONID": self._JSessionID}
                headers = {
                    **self._default_headers,
                    "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
                    "Referer": f"{self.system_loginurl}/Self/login/",
                    "User-Agent": self.system_ua,
                }

                params = {"t": str(random.random())}

                await client.get(
                    f"{self.system_loginurl}/Self/login/randomCode",
                    params=params,
                    cookies=cookies,
                    headers=headers,
                )

                # 第三步：提交登录表单
                headers = {
                    **self._default_headers,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"{self.system_loginurl}",
                    "Referer": f"{self.system_loginurl}/Self/login/",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": self.system_ua,
                }

                data = {
                    "foo": "",
                    "bar": "",
                    "checkcode": self._checkcode,
                    "account": self._parent._usercode,
                    "password": self._parent._password,
                    "code": "",
                }

                response = await client.post(
                    f"{self.system_loginurl}/Self/login/verify;jsessionid={self._JSessionID}",
                    cookies=cookies,
                    headers=headers,
                    data=data,
                )

                # 检查登录是否成功
                return "dashboard" in response.url.path

        except Exception as e:
            print(f"登录失败: {str(e)}")
            return False

    def get_online_devices(self) -> "OnlineDevices":
        """
        获取全部在线设备

        :return: 在线设备列表
        :rtype: OnlineDevices
        """
        return sync_wrapper(self.get_online_devices_async)()

    async def get_online_devices_async(self) -> "OnlineDevices":
        """
        异步获取全部在线设备

        :return: 在线设备列表
        :rtype: OnlineDevices
        """
        cookies = {"JSESSIONID": self._JSessionID}
        headers = {
            **self._default_headers,
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json",
            "Referer": f"{self.system_loginurl}/Self/dashboard",
            "User-Agent": self.system_ua,
            "X-Requested-With": "XMLHttpRequest",
        }

        params = {
            "t": str(random.random()),
            "order": "asc",
            "_": str(int(time.time())),
        }

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.system_loginurl}/Self/dashboard/getOnlineList",
                    params=params,
                    cookies=cookies,
                    headers=headers,
                )

                if response.status_code == 200:
                    return OnlineDevices.from_list(json.loads(response.text))
                return OnlineDevices()
        except Exception:
            return OnlineDevices()

    def get_total_traffic(self) -> int:
        """
        获取消耗的流量

        :return: 消耗的流量，单位为 MB
        :rtype: int
        """
        return sync_wrapper(self.get_total_traffic_async)()

    async def get_total_traffic_async(self) -> int:
        """
        异步获取消耗的流量

        :return: 消耗的流量，单位为 MB
        :rtype: int
        """
        dashboard_data = await self._get_dashboard_data_async()
        if dashboard_data and len(dashboard_data) > 1:
            try:
                return int(dashboard_data[1].text.strip().split()[0])
            except (ValueError, IndexError):
                return 0
        return 0

    def get_used_time(self) -> int:
        """
        获取使用时间

        :return: 使用时间，单位为 分钟
        :rtype: int
        """
        return sync_wrapper(self.get_used_time_async)()

    async def get_used_time_async(self) -> int:
        """
        异步获取使用时间

        :return: 使用时间，单位为 分钟
        :rtype: int
        """
        dashboard_data = await self._get_dashboard_data_async()
        if dashboard_data and len(dashboard_data) > 0:
            try:
                return int(dashboard_data[0].text.strip().split()[0])
            except (ValueError, IndexError):
                return 0
        return 0

    async def _get_dashboard_data_async(self) -> List:
        """
        异步获取仪表盘数据

        :return: BeautifulSoup找到的dt元素列表
        """
        cookies = {"JSESSIONID": self._JSessionID}
        headers = {
            **self._default_headers,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Referer": f"{self.system_loginurl}/Self/login/",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.system_ua,
        }

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.system_loginurl}/Self/dashboard",
                    cookies=cookies,
                    headers=headers,
                )

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, features="html.parser")
                    return soup.find_all("dt")
                return []
        except Exception:
            return []

    def logout_device(self, sessionid: str) -> bool:
        """
        注销指定设备

        :param str sessionid: sessionid,可通过 get_online_devices() 获取
        :return: 成功或失败
        :rtype: bool
        """
        return sync_wrapper(self.logout_device_async)(sessionid)

    async def logout_device_async(self, sessionid: str) -> bool:
        """
        异步注销指定设备

        :param str sessionid: sessionid,可通过 get_online_devices_async() 获取
        :return: 成功或失败
        :rtype: bool
        """
        if not sessionid:
            return False

        cookies = {"JSESSIONID": self._JSessionID}
        headers = {
            **self._default_headers,
            "Accept": "*/*",
            "Referer": f"{self.system_loginurl}/Self/dashboard",
            "User-Agent": self.system_ua,
            "X-Requested-With": "XMLHttpRequest",
        }

        params = {
            "t": str(random.random()),
            "sessionid": sessionid,
        }

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.system_loginurl}/Self/dashboard/tooffline",
                    params=params,
                    cookies=cookies,
                    headers=headers,
                )

                if response.status_code == 200:
                    result = json.loads(response.text)
                    return result.get("success", False)
                return False
        except Exception:
            return False
