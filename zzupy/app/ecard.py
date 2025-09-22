"""一卡通"""

import base64
import json
import threading
import time
from typing import Final
from urllib.parse import urlparse, parse_qs

import gmalg
import httpx
from loguru import logger

from zzupy.app.interfaces import ICASClient
from zzupy.exception import (
    NetworkError,
    OperationError,
    ParsingError,
    NotLoggedInError,
)
from zzupy.utils import sm4_decrypt_ecb, require_auth


class ECardClient:
    """一卡通客户端"""

    TID_URL: Final = "https://ecard.v.zzu.edu.cn/server/auth/host/open"
    TOKEN_URL: Final = "https://ecard.v.zzu.edu.cn/server/auth/getToken"
    CONFIG_URL: Final = "https://ecard.v.zzu.edu.cn/server/utilities/config"
    ENCRYPT_URL: Final = "https://ecard.v.zzu.edu.cn/server/auth/getEncrypt"
    PAY_URL: Final = "https://ecard.v.zzu.edu.cn/server/utilities/pay"
    LOCATION_URL: Final = "https://ecard.v.zzu.edu.cn/server/utilities/location"
    ACCOUNT_URL: Final = "https://ecard.v.zzu.edu.cn/server/utilities/account"
    BALANCE_URL: Final = "https://info.s.zzu.edu.cn/portal-api/v1/thrid-adapter/get-person-info-card-list"

    SM4_KEY: Final = bytes.fromhex("773638372d392b33435f48266a655f35")
    TOKEN_REFRESH_INTERVAL: Final = 2700  # 45分钟

    def __init__(self, cas_client: ICASClient) -> None:
        """初始化 ECardClient 实例

        Args:
            cas_client: 已登录的 CASClient 实例
        """
        if not cas_client.logged_in:
            raise NotLoggedInError("CASClient 必须已经登录")

        self._client = httpx.Client()
        self._cas_client = cas_client
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._tid: str | None = None
        self._default_room: str | None = None
        self._logged_in: bool = False
        self._refresh_timer: threading.Timer | None = None

    def __enter__(self) -> "ECardClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _get_tid(self) -> None:
        """获取 tid

        Raises:
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
        """
        params = {
            "host": "11",
            "org": "2",
            "token": self._cas_client.user_token,
        }

        try:
            logger.debug("正在向 {} 发送请求获取 tid...", self.TID_URL)
            response = self._client.get(
                self.TID_URL,
                params=params,
                follow_redirects=False,
            )

            logger.debug("/auth/host/open 请求响应头: {}", response.headers)

            if "location" not in response.headers:
                logger.error("响应中缺少 location 头")
                raise ParsingError("服务器响应格式不正确，缺少重定向信息")

            parsed_url = urlparse(response.headers["location"])
            query_params = parse_qs(parsed_url.query)

            if "tid" not in query_params:
                logger.error("重定向URL中缺少 tid 参数")
                raise ParsingError("服务器响应格式不正确，缺少 tid 参数")

            self._tid = query_params["tid"][0]
            logger.info("成功获取 tid")

        except httpx.HTTPStatusError as exc:
            logger.error("获取 tid 请求返回失败状态码: {}", exc.response.status_code)
            raise NetworkError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (KeyError, IndexError) as exc:
            logger.error("从响应中提取 tid 失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取 tid 网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    def login(self) -> None:
        """登录到校园卡系统

        Raises:
            LoginError: 如果登录失败
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
        """
        logger.debug("开始登录校园卡系统")
        self._get_tid()
        self._get_tokens()
        self._logged_in = True
        self._schedule_token_refresh()
        logger.info("校园卡系统登录成功")

    def _get_tokens(self) -> None:
        """获取 ecard access token

        Raises:
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
        """
        if not self._tid:
            logger.error("尝试获取 token 但 tid 未设置")
            raise NotLoggedInError("必须先获取 tid")

        data = {"tid": self._tid}

        try:
            logger.debug("正在向 {} 发送请求获取 token...", self.TOKEN_URL)
            response = self._client.post(
                self.TOKEN_URL,
                json=data,
            )
            response.raise_for_status()

            logger.debug("/auth/getToken 请求响应体: {}", response.text)

            response_data = response.json()

            if "resultData" not in response_data:
                logger.error("响应中缺少 resultData")
                raise ParsingError("服务器响应格式不正确")

            result_data = response_data["resultData"]
            self._access_token = result_data.get("accessToken")
            self._refresh_token = result_data.get("refreshToken")

            if not self._access_token or not self._refresh_token:
                logger.error("未能从响应中获取 token")
                raise ParsingError("服务器未返回有效的 token")

            logger.info("成功获取 accessToken 和 refreshToken")

        except httpx.HTTPStatusError as exc:
            logger.error("获取 token 请求返回失败状态码: {}", exc.response.status_code)
            raise NetworkError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从 /auth/getToken 响应中提取 token 失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取 token 网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    def _schedule_token_refresh(self) -> None:
        """安排token刷新定时器

        每45分钟执行一次token刷新
        """
        if self._refresh_timer is not None:
            self._refresh_timer.cancel()

        self._refresh_timer = threading.Timer(
            self.TOKEN_REFRESH_INTERVAL, self._refresh_tokens
        )
        self._refresh_timer.daemon = True
        self._refresh_timer.start()
        logger.debug(
            "已安排 token 刷新定时器，将在{}秒后执行", self.TOKEN_REFRESH_INTERVAL
        )

    def _refresh_tokens(self) -> None:
        """刷新tokens

        重新执行login流程来更新tid和tokens
        """
        try:
            logger.info("开始执行 token 自动刷新")
            self._get_tid()
            self._get_tokens()
            self._schedule_token_refresh()  # 重新安排下次刷新
            logger.info("token 自动刷新完成")
        except Exception as exc:
            logger.error("token 自动刷新失败: {}", exc)
            # 如果刷新失败，仍然重新安排下次刷新
            self._schedule_token_refresh()

    @require_auth
    def get_default_room(self) -> str:
        """获取账户默认房间

        Returns:
            默认的房间

        Raises:
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
        """

        if self._default_room is not None:
            return self._default_room

        headers = {"Authorization": self._access_token}
        data = {"utilityType": "electric"}

        try:
            logger.debug("正在向 {} 发送请求获取默认房间...", self.CONFIG_URL)
            response = self._client.post(
                self.CONFIG_URL,
                headers=headers,
                json=data,
            )
            response.raise_for_status()

            logger.debug("/utilities/config 请求响应体: {}", response.text)

            response_data = response.json()

            if "resultData" not in response_data:
                logger.error("响应中缺少 resultData")
                raise ParsingError("服务器响应格式不正确")

            room = response_data["resultData"]["location"]["room"]
            logger.info("获取默认房间成功: {}", room)
            self._default_room = room
            return room

        except httpx.HTTPStatusError as exc:
            logger.error("获取默认房间请求返回失败状态码: {}", exc.response.status_code)
            raise NetworkError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从 /utilities/config 响应中提取房间信息失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取默认房间网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    @require_auth
    def recharge_energy(self, payment_password: str, amt: int, room: str) -> None:
        """为 room 充值电费

        Args:
            payment_password: 支付密码
            amt: 充值金额
            room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过
                [`get_room_dict()`][zzupy.app.ecard.ECardClient.get_room_dict] 获取

        Raises:
            OperationError: 如果充值失败
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
        """

        if amt <= 0:
            logger.error("充值金额必须大于0")
            raise ValueError("充值金额必须大于0")

        logger.debug("准备为房间 {} 充值 {} 元", room, amt)

        headers = {"Authorization": self._access_token}

        try:
            # 获取加密信息
            logger.debug("正在向 {} 发送请求获取加密信息...", self.ENCRYPT_URL)
            response = self._client.post(
                self.ENCRYPT_URL,
                headers=headers,
            )
            response.raise_for_status()

            response_data = response.json()

            if "resultData" not in response_data:
                logger.error("响应中缺少 resultData")
                raise ParsingError("服务器响应格式不正确")

            pay_id = response_data["resultData"]["id"]
            encrypted_public_key = response_data["resultData"]["publicKey"]

            logger.debug("开始解密公钥")
            # 解密被加密的公钥
            public_key = sm4_decrypt_ecb(
                base64.b64decode(encrypted_public_key),
                self.SM4_KEY,
            )

            # 解析房间信息
            try:
                area, building = room.split("--")[0].split("-")
                level = room.split("--")[1].split("-")[0]
            except (IndexError, ValueError) as exc:
                logger.error("房间格式不正确: {}", room)
                raise ValueError(f"房间格式不正确: {room}") from exc

            # 构建请求体
            json_data = {
                "utilityType": "electric",
                "payCode": "06",
                "password": payment_password,
                "amt": str(amt),
                "timestamp": int(round(time.time() * 1000)),
                "bigArea": "",
                "area": area,
                "building": building,
                "unit": "",
                "level": level,
                "room": room,
                "subArea": "",
                "customfield": {},
            }
            json_string = json.dumps(json_data, separators=(",", ":"))

            logger.debug("开始加密支付信息")
            # 加密 params
            sm2 = gmalg.SM2(pk=bytes.fromhex(public_key))
            encrypted_params = sm2.encrypt(json_string.encode())
            data = {"id": pay_id, "params": (encrypted_params.hex())[2:]}

            logger.debug("正在向 {} 发送充值请求...", self.PAY_URL)
            response = self._client.post(
                self.PAY_URL,
                headers=headers,
                json=data,
            )
            response.raise_for_status()

            logger.debug("/utilities/pay 请求响应体: {}", response.text)

            response_data = response.json()
            if response_data.get("success") is False:
                error_msg = response_data.get("message", "充值失败")
                logger.error("充值失败: {}", error_msg)
                raise OperationError(error_msg)

            logger.info("成功为房间 {} 充值 {} 元", room, amt)

        except httpx.HTTPStatusError as exc:
            logger.error("充值请求返回失败状态码: {}", exc.response.status_code)
            raise NetworkError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从充值响应中提取数据失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("充值网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    @require_auth
    def get_balance(self) -> float:
        """获取校园卡余额

        Returns:
            校园卡余额

        Raises:
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
        """
        headers = {"X-Id-Token": self._cas_client.user_token}

        try:
            logger.debug("正在向 {} 发送请求获取校园卡余额...", self.BALANCE_URL)
            response = self._client.get(
                self.BALANCE_URL,
                headers=headers,
            )
            response.raise_for_status()

            logger.debug("/get-person-info-card-list 请求响应体: {}", response.text)

            response_data = response.json()

            if "data" not in response_data or len(response_data["data"]) < 2:
                logger.error("响应数据格式不正确")
                raise ParsingError("服务器响应格式不正确")

            balance = float(response_data["data"][1]["amount"])
            logger.info("获取校园卡余额成功: {} 元", balance)
            return balance

        except httpx.HTTPStatusError as exc:
            logger.error("获取余额请求返回失败状态码: {}", exc.response.status_code)
            raise NetworkError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError, IndexError, ValueError) as exc:
            logger.error("从余额响应中提取数据失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取余额网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    @require_auth
    def get_room_dict(self, room_id: str) -> dict:
        """获取房间的字典

        Args:
            room_id: 已知房间 ID 。例如: '', '99', '99-12', '99-12--33'

        Returns:
            对应的字典

        Raises:
            ValueError: 如果参数格式不正确
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
        """

        logger.debug("正在获取房间列表，room_id: {}", room_id)

        # 解析房间ID
        num = room_id.count("-")
        if num == 0 and room_id == "":
            area = building = level = ""
            location_type = "bigArea"
        elif num == 0 and room_id != "":
            building = level = ""
            area = room_id
            location_type = "building"
        elif num == 1:
            area, building = room_id.split("-")
            level = ""
            location_type = "unit"
        elif num == 3:
            try:
                area, building = room_id.split("--")[0].split("-")
                level = room_id.split("--")[1]
                location_type = "room"
            except (IndexError, ValueError) as exc:
                logger.error("房间ID格式不正确: {}", room_id)
                raise ValueError(f"房间ID格式不正确: {room_id}") from exc
        else:
            logger.error("房间ID格式不合法: {}", room_id)
            raise ValueError(f"房间ID格式不合法: {room_id}")

        headers = {"Authorization": self._access_token}
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

        try:
            logger.debug("正在向 {} 发送请求获取房间列表...", self.LOCATION_URL)
            response = self._client.post(
                self.LOCATION_URL,
                headers=headers,
                json=data,
            )
            response.raise_for_status()

            logger.debug("/utilities/location 请求响应体: {}", response.text)

            response_data = response.json()

            if "resultData" not in response_data:
                logger.error("响应中缺少 resultData")
                raise ParsingError("服务器响应格式不正确")

            location_list = response_data["resultData"].get("locationList", [])

            room_dict = {}
            for location in location_list:
                room_dict[location["id"]] = location["name"]

            logger.info("成功获取房间列表，共 {} 个房间", len(room_dict))
            return room_dict

        except httpx.HTTPStatusError as exc:
            logger.error("获取房间列表请求返回失败状态码: {}", exc.response.status_code)
            raise NetworkError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从房间列表响应中提取数据失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取房间列表网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    @require_auth
    def get_remaining_energy(self, room: str | None = None) -> float:
        """获取剩余电量

        Args:
            room: 房间 ID 。格式应为 'areaid-buildingid--unitid-roomid'，可通过
                [`get_room_dict()`][zzupy.app.ecard.ECardClient.get_room_dict] 获取

        Returns:
            剩余电量

        Raises:
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
        """
        room = self.get_default_room() if room is None else room
        logger.debug("正在获取房间 {} 的剩余电量", room)

        # 解析房间信息
        try:
            area, building = room.split("--")[0].split("-")
            level = room.split("--")[1].split("-")[0]
        except (IndexError, ValueError) as exc:
            logger.error("房间格式不正确: {}", room)
            raise ValueError(f"房间格式不正确: {room}") from exc

        headers = {"Authorization": self._access_token}
        data = {
            "utilityType": "electric",
            "bigArea": "",
            "area": area,
            "building": building,
            "unit": "",
            "level": level,
            "room": room,
            "subArea": "",
        }

        try:
            logger.debug("正在向 {} 发送请求获取剩余电量...", self.ACCOUNT_URL)
            response = self._client.post(
                self.ACCOUNT_URL,
                headers=headers,
                json=data,
            )
            response.raise_for_status()

            logger.debug("/utilities/account 请求响应体: {}", response.text)

            response_data = response.json()

            if "resultData" not in response_data:
                logger.error("响应中缺少 resultData")
                raise ParsingError("服务器响应格式不正确")

            template_list = response_data["resultData"].get("templateList", [])
            if len(template_list) < 4:
                logger.error("templateList 数据不完整")
                raise ParsingError("服务器响应数据不完整")

            remaining_energy = float(template_list[3]["value"])
            logger.info("房间 {} 剩余电量: {} 度", room, remaining_energy)
            return remaining_energy

        except httpx.HTTPStatusError as exc:
            logger.error("获取剩余电量请求返回失败状态码: {}", exc.response.status_code)
            raise NetworkError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError, IndexError, ValueError) as exc:
            logger.error("从剩余电量响应中提取数据失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取剩余电量网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    @require_auth
    def logout(self) -> None:
        """登出账户，清除 Cookie 但保留连接池"""
        logger.debug("正在登出校园卡系统")
        if self._refresh_timer is not None:
            self._refresh_timer.cancel()
            self._refresh_timer = None
        self._access_token = None
        self._refresh_token = None
        self._tid = None
        self._client.cookies.clear()
        self._client.headers.clear()
        self._logged_in = False
        logger.info("已登出校园卡系统")

    def close(self) -> None:
        """清除 Cookie 和连接池"""
        logger.debug("正在关闭校园卡客户端")
        if self._refresh_timer is not None:
            self._refresh_timer.cancel()
            self._refresh_timer = None
        if self._logged_in:
            self.logout()
        self._client.close()
        logger.info("校园卡客户端已关闭")
