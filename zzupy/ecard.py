import base64
import json
import threading
import time
import warnings
from urllib.parse import urlparse, parse_qs

import gmalg
from loguru import logger
from typing_extensions import Tuple

from zzupy.exception import DefaultRoomException, ECardTokenException
from zzupy.utils import sm4_decrypt_ecb, check_permission, sync_wrapper


class eCard:
    def __init__(self, parent):
        """
        初始化 eCard 实例

        :param parent: 父对象
        """
        self._parent = parent
        self._eCardAccessToken: str = ""
        self._eCardRefreshToken: str = ""
        self._JSessionID: str = ""
        self._tid: str = ""
        self._orgId: str = ""
        self._timer = None
        # 不再自动启动token刷新定时器，由login方法负责启动

    async def init_async(self):
        """
        异步初始化 eCard 实例
        """
        self._JSessionID, self._tid, self._orgId = await self._get_jsession_id()
        (
            self._eCardAccessToken,
            self._eCardRefreshToken,
        ) = await self._get_ecard_access_token()
        return self

    def _start_token_refresh_timer(self):
        """
        启动定时器，定时刷新 token
        """
        import asyncio

        # 检查当前是否在事件循环中运行
        try:
            loop = asyncio.get_running_loop()
            # 如果能获取到当前运行的事件循环，说明我们在异步环境中
            # 使用异步方式初始化token
            asyncio.create_task(self._start_token_refresh_async())
            return  # 在异步环境中，定时器由_start_token_refresh_async启动
        except RuntimeError:
            # 如果没有运行中的事件循环，说明我们在同步环境中
            # 创建一个新的事件循环来运行异步函数
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                # 运行异步函数并获取结果
                self._JSessionID, self._tid, self._orgId = loop.run_until_complete(
                    self._get_jsession_id()
                )
                self._eCardAccessToken, self._eCardRefreshToken = (
                    loop.run_until_complete(self._get_ecard_access_token())
                )
            finally:
                # 关闭事件循环
                loop.close()

        # 每 45 分钟（2700 秒）执行一次
        self._timer = threading.Timer(2700, self._start_token_refresh_timer)
        self._timer.daemon = True
        self._timer.start()

    async def _get_jsession_id(self) -> Tuple[str, str, str]:
        """
        获取 JSESSIONID, tid 和 orgId

        :returns: Tuple[str, str, str]

            - **JSESSIONID** (str) – JSESSIONID
            - **tid** (str) – tid
            - **orgId** (str) – orgId
        :rtype: Tuple[str,str, str]
        :raises ECardTokenException: 获取 JSESSIONID, tid 或 orgId 失败时抛出
        """
        headers = {
            "User-Agent": self._parent._DeviceParams.userAgentPrecursor + "SuperApp",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "sec-ch-ua": '"Android WebView";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Upgrade-Insecure-Requests": "1",
            "x-id-token": self._parent._userToken,
            "X-Requested-With": "com.supwisdom.zzu",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        params = {
            "host": "11",
            "org": "2",
            "token": self._parent._userToken,
        }
        logger.debug("尝试获取 JSessionID 和 tid")
        logger.debug(f"/auth/host/open 请求头：{headers}")
        response = await self._parent._client.get(
            "https://ecard.v.zzu.edu.cn/server/auth/host/open",
            params=params,
            headers=headers,
            follow_redirects=False,
        )
        logger.debug(f"/auth/host/open 请求响应体：{response.text}")
        logger.debug(f"/auth/host/open 请求响应头：{response.headers}")
        try:
            return (
                response.cookies.get("JSESSIONID"),
                parse_qs(urlparse(response.headers["location"]).query)["tid"][0],
                parse_qs(urlparse(response.headers["location"]).query)["orgId"][0],
            )
        except Exception as exc:
            logger.error("获取 JSESSIONID 和 tid 失败")
            raise ECardTokenException(
                "获取 JSESSIONID 和 tid 失败, 通过 DEBUG 日志获得更多信息"
            ) from exc

    async def _get_ecard_access_token(self):
        """
        获取 ecard access token
        """
        headers = {
            "User-Agent": self._parent._DeviceParams.userAgentPrecursor + "SuperApp",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "sec-ch-ua-platform": '"Android"',
            "sec-ch-ua": '"Android WebView";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
            "sec-ch-ua-mobile": "?1",
            "Origin": "https://ecard.v.zzu.edu.cn",
            "X-Requested-With": "com.supwisdom.zzu",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": f"https://ecard.v.zzu.edu.cn/?tid={self._tid}&{self._orgId}",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        data = {
            "tid": self._tid,
        }
        logger.debug(headers)
        response = await self._parent._client.post(
            "https://ecard.v.zzu.edu.cn/server/auth/getToken",
            headers=headers,
            json=data,
        )
        logger.debug(f"/auth/getToken 请求响应体：{response.text}")
        try:
            return json.loads(response.text)["resultData"]["accessToken"], json.loads(
                response.text
            )["resultData"]["refreshToken"]
        except Exception as exc:
            logger.error("获取 eCardAccessToken 失败")
            raise ECardTokenException(
                "获取 eCardAccessToken 失败, 通过 DEBUG 日志获得更多信息"
            ) from exc

    def get_default_room(self) -> str:
        """
        获取账户默认房间

        :returns: 默认的房间
        """
        return sync_wrapper(self.get_default_room_async)()

    async def get_default_room_async(self) -> str:
        """
        异步获取账户默认房间

        :returns: 默认的房间
        """
        check_permission(self._parent)
        logger.debug("尝试获取默认 room")
        headers = {
            "User-Agent": self._parent._DeviceParams.userAgentPrecursor + "SuperApp",
            "Content-Type": "application/json",
            "sec-ch-ua-platform": '"Android"',
            "Authorization": self._eCardAccessToken,
            "sec-ch-ua": '"Not(A:Brand";v="99", "Android WebView";v="133", "Chromium";v="133"',
            "sec-ch-ua-mobile": "?1",
            "Origin": "https://ecard.v.zzu.edu.cn",
            "X-Requested-With": "com.supwisdom.zzu",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": f"https://ecard.v.zzu.edu.cn/?tid={self._tid}&{self._orgId}",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        data = {
            "utilityType": "electric",
        }

        response = await self._parent._client.post(
            "https://ecard.v.zzu.edu.cn/server/utilities/config",
            headers=headers,
            json=data,
        )
        try:
            room = json.loads(response.text)["resultData"]["location"]["room"]
            logger.debug(f"默认 room 为 {room}")
            return room
        except Exception as exc:
            logger.error("获取默认 room 失败")
            raise DefaultRoomException(
                "获取默认 room 失败, 通过 DEBUG 日志获得更多信息"
            ) from exc

    def recharge_energy(
        self, payment_password: str, amt: int, room: str | None = None
    ) -> Tuple[bool, str]:
        """
        为 room 充值电费

        :param str room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过 get_room_dict() 获取
        :param str payment_password: 支付密码
        :param int amt: 充值金额
        :returns: Tuple[bool, str]

            - **success** (bool) – 充值是否成功
            - **msg** (str) – 服务端返回信息。
        :rtype: Tuple[bool,str]
        """
        return sync_wrapper(self.recharge_energy_async)(payment_password, amt, room)

    async def recharge_energy_async(
        self, payment_password: str, amt: int, room: str | None = None
    ) -> Tuple[bool, str]:
        """
        异步为 room 充值电费

        :param str room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过 get_room_dict() 获取
        :param str payment_password: 支付密码
        :param int amt: 充值金额
        :returns: Tuple[bool, str]

            - **success** (bool) – 充值是否成功
            - **msg** (str) – 服务端返回信息。
        :rtype: Tuple[bool,str]
        """
        check_permission(self._parent)
        room = await self.get_default_room_async() if room is None else room

        headers = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Authorization": self._eCardAccessToken,
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Origin": "https://ecard.v.zzu.edu.cn",
            "Pragma": "no-cache",
            "Referer": f"https://ecard.v.zzu.edu.cn/?tid={self._tid}&{self._orgId}",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
        response = await self._parent._client.post(
            "https://ecard.v.zzu.edu.cn/server/auth/getEncrypt",
            headers=headers,
        )
        pay_id = json.loads(response.text)["resultData"]["id"]
        encrypted_public_key = json.loads(response.text)["resultData"]["publicKey"]
        # 解密被加密的公钥
        public_key = sm4_decrypt_ecb(
            base64.b64decode(encrypted_public_key),
            bytes.fromhex("773638372d392b33435f48266a655f35"),
        )
        # 请求体明文
        json_data = {
            "utilityType": "electric",
            "payCode": "06",
            "password": payment_password,
            "amt": str(amt),
            "timestamp": int(round(time.time() * 1000)),
            "bigArea": "",
            "area": room.split("--")[0].split("-")[0],
            "building": room.split("--")[0].split("-")[1],
            "unit": "",
            "level": room.split("--")[1].split("-")[0],
            "room": room,
            "subArea": "",
            "customfield": {},
        }
        json_string = json.dumps(json_data, separators=(",", ":"))
        # 加密 params
        sm2 = gmalg.SM2(pk=bytes.fromhex(public_key))
        encrypted_params = sm2.encrypt(json_string.encode())
        data = {"id": pay_id, "params": (encrypted_params.hex())[2:]}
        response = await self._parent._client.post(
            "https://ecard.v.zzu.edu.cn/server/utilities/pay",
            headers=headers,
            json=data,
        )
        return (
            json.loads(response.text)["success"],
            json.loads(response.text)["message"],
        )

    def get_balance(self) -> float:
        """
        获取校园卡余额

        :return: 校园卡余额
        :rtype: float
        """
        return sync_wrapper(self.get_balance_async)()

    async def get_balance_async(self) -> float:
        """
        异步获取校园卡余额

        :return: 校园卡余额
        :rtype: float
        """
        check_permission(self._parent)

        headers = {
            "User-Agent": self._parent._DeviceParams.userAgentPrecursor
            + "uni-app Html5Plus/1.0 (Immersed/38.666668)",
            "Connection": "Keep-Alive",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Device-Info": self._parent._DeviceParams.deviceInfo,
            "X-Device-Infos": self._parent._DeviceParams.deviceInfos,
            "X-Id-Token": self._parent._userToken,
            "X-Terminal-Info": "app",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        response = await self._parent._client.get(
            "https://info.s.zzu.edu.cn/portal-api/v1/thrid-adapter/get-person-info-card-list",
            headers=headers,
        )
        return float(json.loads(response.text)["data"][1]["amount"])

    def get_room_dict(self, id: str) -> dict:
        """
        获取房间的字典

        :param str id: 已知房间 ID 。例如: '', '99', '99-12', '99-12--33'
        :return: 对应的字典
        :rtype: dict
        """
        return sync_wrapper(self.get_room_dict_async)(id)

    async def get_room_dict_async(self, id: str) -> dict:
        """
        异步获取房间的字典

        :param str id: 已知房间 ID 。例如: '', '99', '99-12', '99-12--33'
        :return: 对应的字典
        :rtype: dict
        """
        check_permission(self._parent)
        num = id.count("-")
        if num == 0 and id == "":
            area = building = level = ""
            location_type = "bigArea"
        elif num == 0 and id != "":
            building = level = ""
            area = id
            location_type = "building"
        elif num == 1:
            area, building = id.split("-")
            level = ""
            location_type = "unit"
        elif num == 3:
            area, building = id.split("--")[0].split("-")
            level = id.split("--")[1]
            location_type = "room"
        else:
            raise ValueError("参数不合法")

        headers = {
            "User-Agent": self._parent._DeviceParams.userAgentPrecursor + "SuperApp",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "sec-ch-ua-platform": '"Android"',
            "Authorization": self._eCardAccessToken,
            "sec-ch-ua": '"Android WebView";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
            "sec-ch-ua-mobile": "?1",
            "Origin": "https://ecard.v.zzu.edu.cn",
            "X-Requested-With": "com.supwisdom.zzu",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": f"https://ecard.v.zzu.edu.cn/?tid={self._tid}&{self._orgId}",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        data = {
            "utilityType": "electric",
            "locationType": location_type,
            "bigArea": "",
            "area": area,
            "building": building,
            "unit": "",
            "level": level,
            "room": "",
            "subArea": "",
        }

        response = await self._parent._client.post(
            "https://ecard.v.zzu.edu.cn/server/utilities/location",
            headers=headers,
            json=data,
        )
        RoomDict = {}
        for i in range(len(json.loads(response.text)["resultData"]["locationList"])):
            RoomDict[
                json.loads(response.text)["resultData"]["locationList"][i]["id"]
            ] = json.loads(response.text)["resultData"]["locationList"][i]["name"]
        return RoomDict

    def get_remaining_energy(self, room: str | None = None) -> float:
        """
        获取剩余电量

        :param str room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过 get_room_dict() 获取
        :return: 剩余能源
        :rtype: float
        """
        return sync_wrapper(self.get_remaining_energy_async)(room)

    async def get_remaining_energy_async(self, room: str | None = None) -> float:
        """
        异步获取剩余电量

        :param str room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过 get_room_dict() 获取
        :return: 剩余能源
        :rtype: float
        """
        check_permission(self._parent)
        room = await self.get_default_room_async() if room is None else room

        headers = {
            "User-Agent": self._parent._DeviceParams.userAgentPrecursor + "SuperApp",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "sec-ch-ua-platform": '"Android"',
            "Authorization": self._eCardAccessToken,
            "sec-ch-ua": '"Android WebView";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
            "sec-ch-ua-mobile": "?1",
            "Origin": "https://ecard.v.zzu.edu.cn",
            "X-Requested-With": "com.supwisdom.zzu",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": f"https://ecard.v.zzu.edu.cn/?tid={self._tid}&{self._orgId}",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        data = {
            "utilityType": "electric",
            "bigArea": "",
            "area": room.split("--")[0].split("-")[0],
            "building": room.split("--")[0].split("-")[1],
            "unit": "",
            "level": room.split("--")[1].split("-")[0],
            "room": room,
            "subArea": "",
        }

        response = await self._parent._client.post(
            "https://ecard.v.zzu.edu.cn/server/utilities/account",
            headers=headers,
            json=data,
        )
        return float(
            json.loads(response.text)["resultData"]["templateList"][3]["value"]
        )

    def get_remaining_power(self, room: str | None = None) -> float:
        """
        获取剩余电量

        已被废弃，请使用 get_remaining_energy()

        :param str room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过 get_room_dict() 获取
        :return: 剩余能源
        :rtype: float
        """
        logger.warning("get_remaining_power() 已废弃，请使用 get_remaining_energy()")
        warnings.warn(
            "get_remaining_power() is deprecated, please use get_remaining_energy()",
            DeprecationWarning,
        )
        return self.get_remaining_energy(room)

    def recharge_electricity(
        self, payment_password: str, amt: int, room: str | None = None
    ) -> Tuple[bool, str]:
        """
        为 room 充值电费

        已被废弃，请使用 recharge_energy()

        :param str room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过 get_room_dict() 获取
        :param str payment_password: 支付密码
        :param int amt: 充值金额
        :returns: Tuple[bool, str]

            - **success** (bool) – 充值是否成功
            - **msg** (str) – 服务端返回信息。
        :rtype: Tuple[bool,str]
        """
        logger.warning("recharge_electricity() 已废弃，请使用 recharge_energy()")
        warnings.warn(
            "recharge_electricity() is deprecated, please use recharge_energy()",
            DeprecationWarning,
        )
        return self.recharge_energy(payment_password, amt, room)

    async def recharge_electricity_async(
        self, payment_password: str, amt: int, room: str | None = None
    ) -> Tuple[bool, str]:
        """
        异步为 room 充值电费

        已被废弃，请使用 recharge_energy_async()

        :param str room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过 get_room_dict() 获取
        :param str payment_password: 支付密码
        :param int amt: 充值金额
        :returns: Tuple[bool, str]

            - **success** (bool) – 充值是否成功
            - **msg** (str) – 服务端返回信息。
        :rtype: Tuple[bool,str]
        """
        logger.warning(
            "recharge_electricity_async() 已废弃，请使用 recharge_energy_async()"
        )
        warnings.warn(
            "recharge_electricity_async() is deprecated, please use recharge_energy_async()",
            DeprecationWarning,
        )
        return await self.recharge_energy_async(payment_password, amt, room)

    async def _start_token_refresh_async(self):
        """
        异步启动 token 刷新
        """
        self._JSessionID, self._tid, self._orgId = await self._get_jsession_id()
        (
            self._eCardAccessToken,
            self._eCardRefreshToken,
        ) = await self._get_ecard_access_token()

        # 每 45 分钟（2700 秒）执行一次
        self._timer = threading.Timer(2700, self._start_token_refresh_timer)
        self._timer.daemon = True
        self._timer.start()

    async def start_token_refresh_loop(self):
        """
        启动异步的 token 刷新循环
        """
        import asyncio

        while True:
            # 刷新 token
            await self._start_token_refresh_async()
            # 等待 45 分钟（2700 秒）
            await asyncio.sleep(2700)
