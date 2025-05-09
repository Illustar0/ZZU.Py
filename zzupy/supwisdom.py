import base64
import datetime
import json
import random
import time

import httpx
from loguru import logger

from zzupy.models import Courses, RoomOccupancyData, SemesterData
from zzupy.utils import get_sign, sync_wrapper


class Supwisdom:
    """
    树维教务相关功能的类
    """

    def __init__(self, parent):
        """
        初始化Supwisdom实例

        :param parent: 父对象，通常是ZZUPy实例
        """
        self._parent = parent
        # 默认请求头
        self._default_headers = {
            "User-Agent": "",  # 将在请求时动态设置
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
        self.biz_type_id = None
        self.current_semester_id = None

    def get_courses(
        self,
        start_date: str,
        semester_id: str | int = None,
        biz_type_id: str | int = None,
    ) -> Courses:
        """
        获取课程表

        :param str start_date: 课表的开始日期，格式必须为 YYYY-MM-DD ，且必须为某一周周一，否则课表会时间错乱
        :param str semester_id: 学期ID
        :param str biz_type_id: 业务类型 ID，用于区分本科生和研究生
        :return: 返回课程表数据
        :rtype: Courses
        :raises ValueError: 如果日期格式不正确
        :raises Exception: 如果API请求失败
        """
        return sync_wrapper(self.get_courses_async)(
            start_date, semester_id, biz_type_id
        )

    async def get_courses_async(
        self,
        start_date: str,
        semester_id: str | int = None,
        biz_type_id: str | int = None,
    ) -> Courses:
        """
        异步获取课程表

        :param str start_date: 课表的开始日期，格式必须为 YYYY-MM-DD ，且必须为某一周周一，否则课表会时间错乱
        :param str semester_id: 学期ID
        :param str biz_type_id: 业务类型 ID，用于区分本科生和研究生
        :return: 返回课程表数据
        :rtype: Courses
        :raises ValueError: 如果日期格式不正确
        :raises Exception: 如果API请求失败
        """

        if semester_id is None:
            semester_id = self.current_semester_id
        if biz_type_id is None:
            biz_type_id = self.biz_type_id
        # 验证日期格式
        try:
            start_datetime = datetime.datetime.strptime(start_date, "%Y-%m-%d")
            # 检查是否为周一
            if start_datetime.weekday() != 0:
                logger.error("提供的日期不是周一，课表可能会时间错乱")
        except ValueError:
            raise ValueError("日期格式必须为 YYYY-MM-DD")

        # 计算结束日期（一周后）
        end_date = (start_datetime + datetime.timedelta(days=6)).strftime("%Y-%m-%d")

        # 准备请求数据
        data = {
            "biz_type_id": str(biz_type_id),
            "end_date": end_date,
            "random": int(random.uniform(10000, 99999)),
            "semester_id": str(semester_id),
            "start_date": start_date,
            "timestamp": int(round(time.time() * 1000)),
            "token": self._parent._dynamicToken,
        }

        # 生成签名
        params = "&".join([f"{key}={value}" for key, value in data.items()])
        sign = get_sign(self._parent._dynamicSecret, params)
        data["sign"] = sign

        # 设置请求头
        headers = self._default_headers.copy()
        headers["User-Agent"] = (
            self._parent._DeviceParams.userAgentPrecursor + "SuperApp"
        )
        headers["token"] = self._parent._dynamicToken
        response = None
        try:
            # 发送请求
            response = await self._parent._client.post(
                "https://jw.v.zzu.edu.cn/app-ws/ws/app-service/student/course/schedule/get-course-tables",
                headers=headers,
                data=data,
            )

            # 检查响应状态
            response.raise_for_status()

            # 解析响应数据
            response_json = response.json()
            if "business_data" not in response_json:
                raise Exception(f"API返回格式错误: {response.text}")

            # 解码并解析课程数据
            courses_json = base64.b64decode(response_json["business_data"]).decode(
                "utf-8"
            )
            courses_list = json.loads(courses_json)

            # 按日期和开始时间排序
            sorted_courses = sorted(
                courses_list,
                key=lambda x: (
                    x["date"],
                    datetime.datetime.strptime(x.get("start_time", "00:00"), "%H:%M"),
                ),
            )

            # 转换为Courses对象
            return Courses.from_list(sorted_courses)

        except httpx.HTTPStatusError as e:
            raise Exception(f"API请求失败: HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            raise Exception(f"网络请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            # 检查response是否已定义
            error_text = response.text if response is not None else "无响应内容"
            raise Exception(f"解析响应JSON失败: {error_text}")
        except Exception as e:
            raise Exception(f"获取课程表失败: {str(e)}")

    def get_current_week_courses(
        self, semester_id: str | int = None, biz_type_id: str | int = None
    ) -> Courses:
        """
        获取本周课程表

        :param str semester_id: 学期ID
        :param str biz_type_id: 业务类型 ID，用于区分本科生和研究生
        :return: 返回本周课程表数据
        :rtype: Courses
        """

        if semester_id is None:
            semester_id = self.current_semester_id
        if biz_type_id is None:
            biz_type_id = self.biz_type_id
        # 获取当前日期
        today = datetime.datetime.now()
        # 计算本周一的日期
        monday = today - datetime.timedelta(days=today.weekday())
        # 格式化为YYYY-MM-DD
        monday_str = monday.strftime("%Y-%m-%d")
        # 获取课程表
        return self.get_courses(monday_str, semester_id, biz_type_id)

    async def get_current_week_courses_async(
        self, semester_id: str | int = None, biz_type_id: str | int = None
    ) -> Courses:
        """
        异步获取本周课程表

        :param str semester_id: 学期ID。
        :param str biz_type_id: 业务类型 ID，用于区分本科生和研究生
        :return: 返回本周课程表数据
        :rtype: Courses
        """
        if semester_id is None:
            semester_id = self.current_semester_id
        if biz_type_id is None:
            biz_type_id = self.biz_type_id
        # 获取当前日期
        today = datetime.datetime.now()
        # 计算本周一的日期
        monday = today - datetime.timedelta(days=today.weekday())
        # 格式化为YYYY-MM-DD
        monday_str = monday.strftime("%Y-%m-%d")
        # 获取课程表
        return await self.get_courses_async(monday_str, semester_id, biz_type_id)

    def get_today_courses(
        self, semester_id: str | int = None, biz_type_id: str | int = None
    ) -> Courses:
        """
        获取今日课程表

        :param str semester_id: 学期ID
        :param str biz_type_id: 业务类型 ID，用于区分本科生和研究生
        :return: 返回今日课程表数据
        :rtype: Courses
        """

        if semester_id is None:
            semester_id = self.current_semester_id
        if biz_type_id is None:
            biz_type_id = self.biz_type_id
        # 获取本周课程表
        week_courses = self.get_current_week_courses(semester_id, biz_type_id)

        # 获取今天的日期
        today_str = datetime.datetime.now().strftime("%Y-%m-%d")

        # 筛选今天的课程
        today_courses = [
            course for course in week_courses.courses if course.date == today_str
        ]

        return Courses(courses=today_courses)

    async def get_today_courses_async(
        self, semester_id: str | int = None, biz_type_id: str | int = None
    ) -> Courses:
        """
        异步获取今日课程表

        :param str semester_id: 学期ID
        :param str biz_type_id: 业务类型 ID，用于区分本科生和研究生
        :return: 返回今日课程表数据
        :rtype: Courses
        """
        if semester_id is None:
            semester_id = self.current_semester_id
        if biz_type_id is None:
            biz_type_id = self.biz_type_id
        # 获取本周课程表
        week_courses = await self.get_current_week_courses_async(
            semester_id, biz_type_id
        )

        # 获取今天的日期
        today_str = datetime.datetime.now().strftime("%Y-%m-%d")

        # 筛选今天的课程
        today_courses = [
            course for course in week_courses.courses if course.date == today_str
        ]

        return Courses(courses=today_courses)

    def get_room_data(
        self,
        building_id: int | str,
        date_str: str = datetime.datetime.now().strftime("%Y-%m-%d"),
    ) -> RoomOccupancyData:
        """
        获取教室占用数据

        :param building_id: 建筑ID
        :param date_str: 日期字符串，格式为YYYY-MM-DD，默认为当天
        :return: 返回教室占用数据
        :rtype: RoomOccupancyData
        :raises Exception: 如果API请求失败
        """
        return sync_wrapper(self.get_room_data_async)(building_id, date_str)

    async def get_room_data_async(
        self,
        building_id: int | str,
        date_str: str = datetime.datetime.now().strftime("%Y-%m-%d"),
    ) -> RoomOccupancyData:
        """
        异步获取教室占用数据

        :param building_id: 建筑ID
        :param date_str: 日期字符串，格式为YYYY-MM-DD，默认为当天
        :return: 返回教室占用数据
        :rtype: RoomOccupancyData
        :raises Exception: 如果API请求失败
        """
        data = {
            "building_id": building_id,
            "start_date": date_str,
            "random": int(random.uniform(10000, 99999)),
            "end_date": None,
            "token": self._parent._dynamicToken,
            "timestamp": int(round(time.time() * 1000)),
        }
        params = "&".join([f"{key}={value}" for key, value in data.items()])
        sign = get_sign(self._parent._dynamicSecret, params)
        data["sign"] = sign
        # 在try块外初始化response变量为None
        response = None
        try:
            headers = self._default_headers.copy()
            headers["User-Agent"] = (
                self._parent._DeviceParams.userAgentPrecursor + "SuperApp"
            )
            headers["token"] = self._parent._dynamicToken
            response = await self._parent._client.post(
                "https://jw.v.zzu.edu.cn/app-ws/ws/app-service/room/borrow/occupancy/search",
                headers=headers,
                data=data,
            )
            response.raise_for_status()

            # 解析响应数据
            business_data = json.loads(
                base64.b64decode(response.json()["business_data"])
            )
            return RoomOccupancyData(**business_data[0])

        except httpx.HTTPStatusError as e:
            raise Exception(f"API请求失败: HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            raise Exception(f"网络请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            # 检查response是否已定义
            error_text = response.text if response is not None else "无响应内容"
            raise Exception(f"解析响应JSON失败: {error_text}")
        except Exception as e:
            logger.error(f"获取教室占用数据失败: {e}")
            raise

    def get_semester_data(self, biz_type_id: str | int = None) -> SemesterData:
        """
        获取学期数据

        :param biz_type_id: 业务类型 ID，用于区分本科生和研究生。
        :return: 返回学期数据
        :rtype: SemesterData
        :raises Exception: 如果API请求失败
        """
        return sync_wrapper(self.get_semester_data_async)(biz_type_id)

    async def get_semester_data_async(
        self, biz_type_id: str | int = None
    ) -> SemesterData:
        """
        异步获取学期数据

        :param biz_type_id: 业务类型 ID，用于区分本科生和研究生。
        :return: 返回学期数据
        :rtype: SemesterData
        :raises Exception: 如果API请求失败
        """
        if biz_type_id is None:
            biz_type_id = self.biz_type_id
        data = {
            "biz_type_id": str(biz_type_id),
            "random": int(random.uniform(10000, 99999)),  # '1' 代表本科生
            "timestamp": int(round(time.time() * 1000)),
            "token": self._parent._dynamicToken,
        }
        params = "&".join([f"{key}={value}" for key, value in data.items()])
        sign = get_sign(self._parent._dynamicSecret, params)
        data["sign"] = sign
        response = None
        try:
            headers = self._default_headers.copy()
            headers["User-Agent"] = (
                self._parent._DeviceParams.userAgentPrecursor + "SuperApp"
            )
            headers["token"] = self._parent._dynamicToken
            response = await self._parent._client.post(
                "https://jw.v.zzu.edu.cn/app-ws/ws/app-service/common/get-semester",
                headers=headers,
                data=data,
            )
            response.raise_for_status()

            # 解析响应数据
            business_data = json.loads(
                base64.b64decode(response.json()["business_data"])
            )
            return SemesterData(**business_data)

        except httpx.HTTPStatusError as e:
            raise Exception(f"API请求失败: HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            raise Exception(f"网络请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            # 检查response是否已定义
            error_text = response.text if response is not None else "无响应内容"
            raise Exception(f"解析响应JSON失败: {error_text}")
        except Exception as e:
            logger.error(f"获取学期数据失败: {e}")
            raise

    def get_biz_type_id(
        self,
    ) -> int:
        """
        获取账户默认业务类型 ID，用于区分本科生和研究生。

        :return: 返回默认业务类型 ID
        :rtype: int
        """
        return self.biz_type_id

    def get_current_semester_id(self) -> int:
        """
        获取默认学期 ID

        :return: 返回学期 ID
        :rtype: int
        """
        return self.current_semester_id
