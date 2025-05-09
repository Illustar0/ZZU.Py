import base64
import json
import random
import time
from http.cookies import SimpleCookie
from typing import Optional, TypedDict, Final, Dict, Any

import httpx
from loguru import logger
from typing_extensions import Unpack

from zzupy.ecard import eCard
from zzupy.exception import LoginException
from zzupy.models import DeviceParams
from zzupy.network import Network
from zzupy.supwisdom import Supwisdom
from zzupy.utils import get_sign, _kget, sync_wrapper

# 常量定义
DEFAULT_APP_VERSION: Final = "SWSuperApp/1.0.39"
DEFAULT_APP_ID: Final = "com.supwisdom.zzu"
DEFAULT_OS_TYPE: Final = "android"
DEFAULT_DYNAMIC_SECRET: Final = "supwisdom_eams_app_secret"


class UserInfo(TypedDict):
    usercode: str
    name: str


class ZZUPy:
    def __init__(
        self, usercode: str, password: str, cookie: Optional[SimpleCookie] = None
    ) -> None:
        """
        初始化一个 ZZUPy 对象

        :param str usercode: 学号
        :param str password: 密码
        :param SimpleCookie cookie: 统一认证 Cookie。目前必须包含 'userToken'，否则会抛出 ValueError
        :raises ValueError: Cookie 中缺少 'userToken' 时抛出
        """
        self._userToken: str = ""
        self._dynamicSecret: str = DEFAULT_DYNAMIC_SECRET
        self._dynamicToken: str = ""
        self._refreshToken: str = ""
        self._name: str = ""
        self._isLogged: bool = False
        self._DeviceParams = DeviceParams(
            deviceName="",
            deviceId="",
            deviceInfo="",
            deviceInfos="",
            userAgentPrecursor="",
        )
        self._usercode: str = usercode
        self._password: str = password

        logger.debug(f"已配置账户 {usercode}")

        # 初始化 HTTPX
        self._client = httpx.AsyncClient(follow_redirects=True)

        if isinstance(cookie, SimpleCookie):
            self._setup_cookies(cookie)

        logger.debug("已配置 HTTPX 实例")

        # 初始化子模块
        self.Network = Network(self)
        self.eCard = eCard(self)
        self.Supwisdom = Supwisdom(self)

        logger.debug("已配置类")
        logger.info(f"账户 {usercode} 初始化完成")

    def _setup_cookies(self, cookie: SimpleCookie) -> None:
        """设置 cookies 并提取 userToken"""
        for key, morsel in cookie.items():
            self._client.cookies.set(
                key, morsel.value, morsel["domain"], morsel["path"]
            )
            if key == "userToken":
                self._userToken = morsel.value

        if self._userToken == "":
            raise ValueError("Cookie 中缺少 'userToken'")

    @property
    def is_logged_in(self) -> bool:
        """判断是否已登录"""
        return self._isLogged

    def set_device_params(self, **kwargs: Unpack[Dict[str, Any]]) -> None:
        """
        设置设备参数。这些参数都需要抓包获取，但其实可有可无，因为目前并没有观察到相关风控机制

        :param str deviceName: 设备名 ，位于 "passwordLogin" 请求的 User-Agent 中，组成为 '{appVersion}({deviceName})'
        :param str deviceId: 设备 ID ，
        :param str deviceInfo: 设备信息，位于名为 "X-Device-Info" 的请求头中
        :param str deviceInfos: 设备信息，位于名为 "X-Device-Infos" 的请求头中
        :param str userAgentPrecursor: 设备 UA 前体 ，只需要包含 "SuperApp" 或 "uni-app Html5Plus/1.0 (Immersed/38.666668)" 前面的部分
        """
        for key in (
            "deviceName",
            "deviceId",
            "deviceInfo",
            "deviceInfos",
            "userAgentPrecursor",
        ):
            setattr(self._DeviceParams, key, _kget(kwargs, key, ""))

        # 处理 userAgentPrecursor 的尾部空格
        if not self._DeviceParams.userAgentPrecursor.endswith(" "):
            self._DeviceParams.userAgentPrecursor += " "

        logger.info("已配置设备参数")

    def login(
        self,
        app_version: str = DEFAULT_APP_VERSION,
        app_id: str = DEFAULT_APP_ID,
        os_type: str = DEFAULT_OS_TYPE,
    ) -> UserInfo:
        """
        登录

        :param str app_version: APP 版本 ，一般类似 "SWSuperApp/1.0.39" ，可自行更新版本号。
        :param str app_id: APP 包名，一般不需要修改
        :param str os_type: 系统类型，一般不需要修改
        :returns: Tuple[str, str]

            - **usercode** (str) – 学号
            - **name** (str) – 姓名
        :rtype: Tuple[str,str]
        :raises LoginException: 登录失败时抛出
        """
        return sync_wrapper(self.login_sync)(app_version, app_id, os_type)

    async def login_sync(
        self,
        app_version: str = DEFAULT_APP_VERSION,
        app_id: str = DEFAULT_APP_ID,
        os_type: str = DEFAULT_OS_TYPE,
    ) -> UserInfo:
        """
        登录

        :param str app_version: APP 版本 ，一般类似 "SWSuperApp/1.0.39" ，可自行更新版本号。
        :param str app_id: APP 包名，一般不需要修改
        :param str os_type: 系统类型，一般不需要修改
        :returns: Tuple[str, str]

            - **usercode** (str) – 学号
            - **name** (str) – 姓名
        :rtype: Tuple[str,str]
        :raises LoginException: 登录失败时抛出
        """
        logger.info(f"尝试登录账户 {self._usercode}")

        if self._client.cookies.get("userToken") is None:
            await self._password_login(app_version, app_id, os_type)
        else:
            logger.info("userToken 已设置，跳过帐密登录")

        await self._token_login()

        # 使用异步方式初始化eCard
        await self.eCard._start_token_refresh_async()
        self._isLogged = True
        logger.info(f"账户 {self._usercode} 登录成功")

        return {"usercode": self._usercode, "name": self._name}

    async def _password_login(
        self, app_version: str, app_id: str, os_type: str
    ) -> None:
        """执行密码登录流程"""
        headers = {
            "User-Agent": f"{app_version}({self._DeviceParams.deviceName})",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
        }

        response = await self._client.post(
            "https://token.s.zzu.edu.cn/password/passwordLogin",
            params={
                "username": self._usercode,
                "password": self._password,
                "appId": app_id,
                "geo": "",
                "deviceId": self._DeviceParams.deviceId,
                "osType": os_type,
                "clientId": "",
                "mfaState": "",
            },
            headers=headers,
        )

        logger.debug(f"/passwordLogin 请求响应体: {response.text}")

        try:
            data = response.json()["data"]
            self._userToken = data["idToken"]
            self._refreshToken = data["refreshToken"]
            self._client.cookies.set("userToken", self._userToken, ".zzu.edu.cn", "/")
        except Exception as exc:
            logger.error("从 /passwordLogin 请求中提取 token 失败")
            raise LoginException("登录失败，请查看 DEBUG 日志获取详细信息") from exc

    async def _token_login(self) -> None:
        """执行 token 登录流程"""
        headers = {
            "User-Agent": f"{self._DeviceParams.userAgentPrecursor}SuperApp",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/x-www-form-urlencoded",
            "sec-ch-ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Android WebView";v="126"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Origin": "https://jw.v.zzu.edu.cn",
            "X-Requested-With": "com.supwisdom.zzu",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://jw.v.zzu.edu.cn/app-web/",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        timestamp = int(round(time.time() * 1000))
        random_num = int(random.uniform(10000, 99999))

        data = {
            "random": random_num,
            "timestamp": timestamp,
            "userToken": self._userToken,
        }

        # 计算签名
        params = "&".join(f"{k}={v}" for k, v in data.items())
        data["sign"] = get_sign(self._dynamicSecret, params)

        response = await self._client.post(
            "https://jw.v.zzu.edu.cn/app-ws/ws/app-service/super/app/login-token",
            headers=headers,
            data=data,
        )

        logger.debug(f"/login-token 请求响应体: {response.text}")

        try:
            business_data = json.loads(
                base64.b64decode(response.json()["business_data"])
            )
            self._dynamicSecret = business_data["secret"]
            self._dynamicToken = business_data["token"]
            self._name = business_data["user_info"]["user_name"]
            self.Supwisdom.biz_type_id = business_data["user_info"]["biz_type_infos"][
                0
            ]["id"]
        except Exception as exc:
            logger.error("从 /login-token 请求中提取数据失败")
            raise LoginException("登录失败，请查看 DEBUG 日志获取详细信息") from exc
        try:
            self.Supwisdom.current_semester_id = (
                await self.Supwisdom.get_semester_data_async(self.Supwisdom.biz_type_id)
            ).cur_semester_id
        except Exception as exc:
            logger.error("获取默认学期失败")
            raise LoginException("获取默认学期失败") from exc

    def get_user_token(self) -> str:
        """获取本次会话的 userToken"""
        return self._userToken
