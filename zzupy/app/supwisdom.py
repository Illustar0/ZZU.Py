import base64
import datetime
import json
import random
import time
from typing import Final

import httpx
import numpy as np
from loguru import logger

from zzupy.app.interfaces import ICASClient
from zzupy.exception import LoginError, NetworkError, ParsingError
from zzupy.models import Course, RoomOccupancyData, SemesterData
from zzupy.utils import get_sign


class SupwisdomClient:
    """
    树维教务 App 客户端
    """

    DYNAMIC_SECRET: Final = "supwisdom_eams_app_secret"
    LOGIN_TOKEN_URL: Final = (
        "https://jw.v.zzu.edu.cn/app-ws/ws/app-service/super/app/login-token"
    )
    GET_SEMESTER_URL: Final = (
        "https://jw.v.zzu.edu.cn/app-ws/ws/app-service/common/get-semester"
    )
    GET_COURSES_URL: Final = "https://jw.v.zzu.edu.cn/app-ws/ws/app-service/student/course/schedule/get-course-tables"
    GET_ROOM_DATA_URL: Final = (
        "https://jw.v.zzu.edu.cn/app-ws/ws/app-service/room/borrow/occupancy/search"
    )

    def __init__(self, cas_client: ICASClient) -> None:
        """
        :param cas_client: 已登录的 CASClient 实例
        """
        if cas_client.user_token is None:
            raise LoginError("CASClient 必须已经登录")
        self._client = httpx.Client()
        self._cas_client = cas_client
        self._client.cookies.set("userToken", cas_client.user_token, ".zzu.edu.cn", "/")
        self._dynamic_secret = None
        self._dynamic_token = None
        self._biz_type_id = None
        self._current_semester_id = None

    def __enter__(self) -> "SupwisdomClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def login(self) -> None:
        """
        登录到树维教务系统

        :raises LoginError: 如果登录失败
        :raises ParsingError: 如果响应解析失败
        :raises NetworkError: 如果网络请求失败
        """
        timestamp = int(round(time.time() * 1000))
        random_num = random.randint(10000, 99999)

        data = {
            "random": random_num,
            "timestamp": timestamp,
            "userToken": self._cas_client.user_token,
        }

        params = "&".join(f"{k}={v}" for k, v in data.items())
        data["sign"] = get_sign(self.DYNAMIC_SECRET, params)

        try:
            logger.debug("正在向树维教务 ({}) 发送登录请求...", self.LOGIN_TOKEN_URL)
            response = self._client.post(
                self.LOGIN_TOKEN_URL,
                data=data,
            )
            response.raise_for_status()
            logger.debug("/login-token 请求响应体: {}", response.text)

            response_data = response.json()
            business_data = json.loads(base64.b64decode(response_data["business_data"]))

            self._dynamic_secret = business_data["secret"]
            self._dynamic_token = business_data["token"]
            self._biz_type_id = business_data["user_info"]["biz_type_infos"][0]["id"]

            self._current_semester_id = self.get_semester_data().cur_semester_id

        except httpx.HTTPStatusError as exc:
            logger.error("树维教务登录请求返回失败状态码: {}", exc.response.status_code)
            raise LoginError(f"服务器返回错误状态 {exc.response.status_code}") from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从 /login-token 响应中提取数据失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("树维教务登录网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    def get_courses(
        self,
        start_date: str,
        semester_id: str | int = None,
    ) -> np.ndarray:
        """
        获取某一周课程表矩阵

        :param start_date: 课表的开始日期，格式必须为 YYYY-MM-DD，且需要为周一。
        :param semester_id: 学期 ID
        :return: 7x10 的课程表矩阵，行=星期(0=周一...6=周日)，列=节次(0=第1节...9=第10节)，元素为Course对象或None
        :raises ValueError: 如果日期格式不正确
        :raises ParsingError: 如果响应解析失败
        :raises NetworkError: 如果网络请求失败
        """
        if semester_id is None:
            semester_id = self._current_semester_id

        try:
            start_datetime = datetime.datetime.strptime(start_date, "%Y-%m-%d")
            start_datetime = start_datetime - datetime.timedelta(
                days=start_datetime.weekday()
            )
            start_date = start_datetime.strftime("%Y-%m-%d")
        except ValueError:
            raise ValueError("日期格式必须为 YYYY-MM-DD")

        end_date = (start_datetime + datetime.timedelta(days=6)).strftime("%Y-%m-%d")

        data = {
            "biz_type_id": str(self._biz_type_id),
            "end_date": end_date,
            "random": random.randint(10000, 99999),
            "semester_id": str(semester_id),
            "start_date": start_datetime.strftime("%Y-%m-%d"),
            "timestamp": int(round(time.time() * 1000)),
            "token": self._dynamic_token,
        }

        params = "&".join([f"{key}={value}" for key, value in data.items()])
        sign = get_sign(self._dynamic_secret, params)
        data["sign"] = sign

        headers = {"token": self._dynamic_token}

        try:
            logger.debug("正在向 {} 发送请求...", self.GET_COURSES_URL)
            response = self._client.post(
                self.GET_COURSES_URL,
                headers=headers,
                data=data,
            )
            response.raise_for_status()
            logger.debug("/get-course-tables 请求响应体: {}", response.text)

            response_data = response.json()
            if "business_data" not in response_data:
                raise ParsingError(f"API返回格式错误: {response.text}")

            courses_json = base64.b64decode(response_data["business_data"]).decode(
                "utf-8"
            )
            courses_list = json.loads(courses_json)

            schedule_matrix = np.full((7, 10), None, dtype=object)

            for course_data in courses_list:
                course = Course(**course_data)

                course_date = datetime.datetime.strptime(course.date, "%Y-%m-%d")
                week_start = datetime.datetime.strptime(start_date, "%Y-%m-%d")
                day_index = (course_date - week_start).days

                if 0 <= day_index <= 6:
                    start_period = max(0, course.start_unit - 1)
                    end_period = min(10, course.end_unit)

                    for period in range(start_period, end_period):
                        schedule_matrix[day_index, period] = course

            return schedule_matrix

        except httpx.HTTPStatusError as exc:
            logger.error("获取课程表请求返回失败状态码: {}", exc.response.status_code)
            raise ParsingError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从 /get-course-tables 响应中提取数据失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取课程表网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    def get_current_week_courses(self, semester_id: str | int = None) -> np.ndarray:
        """
        获取本周课程表

        :param semester_id: 学期ID
        :return: 本周课程表矩阵，行=星期(0=周一...6=周日)，列=节次(0=第1节...9=第10节)，元素为Course对象或None
        """
        today = datetime.datetime.now()
        monday = today - datetime.timedelta(days=today.weekday())
        monday_str = monday.strftime("%Y-%m-%d")
        return self.get_courses(monday_str, semester_id)

    def get_today_courses(self, semester_id: str | int = None) -> np.ndarray:
        """
        获取今日课程表

        :param semester_id: 学期ID
        :return: 今日课程数组，索引=节次(0=第1节...9=第10节)，元素为Course对象或None
        """
        week_matrix = self.get_current_week_courses(semester_id)
        today = datetime.datetime.now()
        day_index = today.weekday()

        return week_matrix[day_index]

    def get_next_course_today(self, semester_id: str | int = None) -> Course | None:
        """
        获取当天的下一节课

        :param semester_id: 学期 ID
        :return: 下一节课的 Course 对象，如果没有则返回 None
        """
        today_courses = self.get_today_courses(semester_id)
        current_time = datetime.datetime.now()

        next_course = None
        next_start_time = None

        for course in today_courses:
            if course is not None:
                try:
                    course_start_time = datetime.datetime.strptime(
                        f"{course.date} {course.start_time}", "%Y-%m-%d %H:%M"
                    )

                    if course_start_time > current_time:
                        if (
                            next_start_time is None
                            or course_start_time < next_start_time
                        ):
                            next_course = course
                            next_start_time = course_start_time
                except ValueError:
                    continue

        return next_course

    def get_room_data(
        self,
        building_id: int | str,
        date_str: str = None,
    ) -> RoomOccupancyData:
        """
        获取教室占用数据

        :param building_id: 建筑ID
        :param date_str: 日期字符串，格式为YYYY-MM-DD，默认为当天
        :return: 返回教室占用数据
        :raises ParsingError: 如果响应解析失败
        :raises NetworkError: 如果网络请求失败
        """
        if date_str is None:
            date_str = datetime.datetime.now().strftime("%Y-%m-%d")

        data = {
            "building_id": building_id,
            "start_date": date_str,
            "random": random.randint(10000, 99999),
            "end_date": None,
            "token": self._dynamic_token,
            "timestamp": int(round(time.time() * 1000)),
        }
        params = "&".join([f"{key}={value}" for key, value in data.items()])
        sign = get_sign(self._dynamic_secret, params)
        data["sign"] = sign

        headers = {"token": self._dynamic_token}

        try:
            logger.debug("正在向 {} 发送请求...", self.GET_ROOM_DATA_URL)
            response = self._client.post(
                self.GET_ROOM_DATA_URL,
                headers=headers,
                data=data,
            )
            response.raise_for_status()
            logger.debug("/occupancy/search 请求响应体: {}", response.text)

            response_data = response.json()
            business_data = json.loads(base64.b64decode(response_data["business_data"]))
            return RoomOccupancyData(**business_data[0])

        except httpx.HTTPStatusError as exc:
            logger.error(
                "获取教室占用数据请求返回失败状态码: {}", exc.response.status_code
            )
            raise ParsingError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从 /occupancy/search 响应中提取数据失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取教室占用数据网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    def get_semester_data(self) -> SemesterData:
        """
        获取学期数据

        :return: 返回学期数据
        :raises ParsingError: 如果响应解析失败
        :raises NetworkError: 如果网络请求失败
        """
        data = {
            "biz_type_id": str(self._biz_type_id),
            "random": random.randint(10000, 99999),
            "timestamp": int(round(time.time() * 1000)),
            "token": self._dynamic_token,
        }
        params = "&".join([f"{key}={value}" for key, value in data.items()])
        sign = get_sign(self._dynamic_secret, params)
        data["sign"] = sign

        headers = {"token": self._dynamic_token}

        try:
            logger.debug("正在向 {} 发送请求...", self.GET_SEMESTER_URL)
            response = self._client.post(
                self.GET_SEMESTER_URL,
                headers=headers,
                data=data,
            )
            response.raise_for_status()
            logger.debug("/get-semester 请求响应体: {}", response.text)

            response_data = response.json()
            business_data = json.loads(base64.b64decode(response_data["business_data"]))
            return SemesterData(**business_data)

        except httpx.HTTPStatusError as exc:
            logger.error("获取学期数据请求返回失败状态码: {}", exc.response.status_code)
            raise ParsingError(
                f"服务器返回错误状态 {exc.response.status_code}"
            ) from exc
        except (json.JSONDecodeError, KeyError) as exc:
            logger.error("从 /get-semester 响应中提取数据失败: {}", exc)
            raise ParsingError("服务器响应格式不正确") from exc
        except httpx.RequestError as exc:
            logger.error("获取学期数据网络请求失败: {}", exc)
            raise NetworkError("网络连接异常") from exc

    @property
    def biz_type_id(self) -> int:
        """
        获取账户默认业务类型 ID

        没有实际意义

        :return: 默认业务类型 ID
        """
        return self._biz_type_id

    @property
    def current_semester_id(self) -> int:
        """
        获取默认学期 ID

        :return: 学期 ID
        """
        return self._current_semester_id

    def close(self) -> None:
        """清除 Cookie 和连接池"""
        self._client.cookies.clear()
        self._client.headers.clear()
        self._client.close()
        self._dynamic_secret = None
        self._dynamic_token = None
