"""140w 教务"""

import json
from typing import Final

import httpx
from loguru import logger
from whenever import Date

from zzupy.app.interfaces import ICASClient
from zzupy.exception import (
    DataNotFoundError,
    InvalidArgumentError,
    NetworkError,
    NotLoggedInError,
    OperationError,
    ParsingError,
)
from pydantic import ValidationError

from zzupy.model.eas import (
    Lesson,
    TeachingWeek,
    LessonModel,
    SemesterModel,
    Semester,
    WeekIndexModel,
    CurrentSemesterModel,
    TeachingWeeks,
)
from zzupy.utils import require_auth


class UndergradEASClient:
    USER_INFO_URL: Final[str] = (
        "https://jwxt.zzu.edu.cn/eams-door/api/v1/portal/home/user-info"
    )
    COURSE_URL: Final[str] = (
        "https://jwxt.zzu.edu.cn/eams-micro-server/api/v1/lesson/student/course-table"
    )
    CURRENT_SEMESTER_URL: Final[str] = (
        "https://jwxt.zzu.edu.cn/eams-micro-server/api/v1/semester/current-semester"
    )
    ALL_SEMESTERS_URL: Final[str] = (
        "https://jwxt.zzu.edu.cn/eams-door/api/v1/calendar/get-all-semesters"
    )
    WEEK_INDEX_URL: Final[str] = (
        "https://info.s.zzu.edu.cn/portal-api/v1/calendar/share/schedule/getWeekOfTeaching"
    )

    def __init__(self, cas_client: ICASClient):
        if not cas_client.logged_in:
            raise NotLoggedInError("CASClient 必须已经登录")

        def request_logger(request):
            logger.trace(f">>> {request.method} {request.url}")
            logger.trace(f">>> Headers: {dict(request.headers)}")
            if request.content:
                try:
                    logger.trace(f">>> Body: {request.content.decode('utf-8')}")
                except Exception:
                    logger.trace(">>> Body: (Binary)")

        def response_logger(response):
            logger.trace(f"<<< Headers: {dict(response.headers)}")

        self._client = httpx.Client(
            event_hooks={"request": [request_logger], "response": [response_logger]}
        )
        self._cas_client = cas_client
        self._client.cookies.set(
            "userToken", self._require_user_token(), ".zzu.edu.cn", "/"
        )
        self._logged_in = False
        self._current_semester_id: int | None = None

    def _require_user_token(self) -> str:
        user_token = self._cas_client.user_token
        if user_token is None:
            raise NotLoggedInError("CASClient 缺少 userToken")
        return user_token

    def __enter__(self) -> "UndergradEASClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def login(self) -> None:
        """登录到新本科教务系统

        Raises:
            OperationError: 如果登录失败。
            ParsingError: 如果响应解析失败。
            NetworkError: 如果网络请求失败。
        """
        logger.info("尝试从本科教务系统获取用户信息...")

        try:
            headers = {"Authorization": self._require_user_token()}
            response = self._client.get(
                self.USER_INFO_URL,
                headers=headers,
            )
            response.raise_for_status()
            logger.trace("{} 请求响应体: {}", self.USER_INFO_URL, response.text)

            response_data = response.json()

            if response_data["result"] != 0:
                logger.error("服务器返回消息 {}", response_data["msg"])
                raise OperationError(f"服务器返回消息 {response_data['msg']}")

        except httpx.HTTPStatusError as exc:
            logger.error(
                "{}请求返回失败状态码: {}",
                self.USER_INFO_URL,
                exc.response.status_code,
            )
            raise OperationError.from_http_status(
                exc,
                "服务器返回错误状态",
                context={"url": self.USER_INFO_URL},
            ) from exc
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("从 {} 响应中提取数据失败: {}", self.USER_INFO_URL, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": self.USER_INFO_URL},
            ) from exc
        except httpx.RequestError as exc:
            logger.error("{} 请求失败: {}", self.USER_INFO_URL, exc)
            raise NetworkError.from_exception(
                exc,
                "网络连接异常",
                context={"url": self.USER_INFO_URL},
            ) from exc

        self._current_semester_id = self._get_current_semester().id

        self._logged_in = True
        logger.info("教务系统登录成功")

    def _get_current_semester(self) -> Semester:
        logger.info("尝试获取当前学期...")
        url = f"{self.CURRENT_SEMESTER_URL}"
        try:
            headers = {"Authorization": self._require_user_token()}
            response = self._client.get(url, headers=headers)
            response.raise_for_status()
            logger.trace("{} 请求响应体: {}", url, response.text)

            response_data = response.json()

        except httpx.HTTPStatusError as exc:
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
        except httpx.RequestError as exc:
            logger.error("{} 请求失败: {}", url, exc)
            raise NetworkError.from_exception(
                exc,
                "网络连接异常",
                context={"url": url},
            ) from exc

        if response_data["result"] != 0:
            logger.error("服务器返回消息 {}", response_data["msg"])
            raise OperationError(f"服务器返回消息 {response_data['msg']}")

        try:
            data = CurrentSemesterModel.model_validate(response_data)
        except ValidationError as exc:
            logger.error("从 {} 响应中解析数据失败: {}", url, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": url},
            ) from exc

        return data.data

    @require_auth
    def get_teaching_week(
        self,
        week: int,
        semester_id: int | None = None,
    ) -> TeachingWeek:
        """
        获取 {semester_id} 号学期的第 {week_index} 教学周
        Args:
            week: 教学周序数
            semester_id: 学期 ID。不填写则为本学期。

        Returns:
            TeachingWeek: 教学周

        Raises:
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
            InvalidArgumentError: 如果教学周序数不正确。
            OperationError: 如果服务器发生异常。
        """
        logger.info("尝试获取第 {} 教学周...", week)
        if week < 1:
            raise InvalidArgumentError("教学周序数不可小于 1")
        if semester_id is None:
            semester_id = self._current_semester_id
        teaching_weeks = self.get_teaching_weeks(semester_id)
        if week > len(teaching_weeks):
            raise InvalidArgumentError(
                f"教学周序数超出范围: {week}",
                context={"week": week, "total_weeks": len(teaching_weeks)},
            )
        return teaching_weeks[week - 1]

    @require_auth
    def get_teaching_weeks(
        self,
        semester_id: int | None = None,
    ) -> TeachingWeeks:
        """
        获取 {semester_id} 号学期的全部教学周
        Args:
            semester_id: 学期 ID。不填写则为本学期。

        Returns:
            TeachingWeeks: 由一个学期的全部教学周组成的列表模型。

        Raises:
            ParsingError: 如果响应解析失败
            NetworkError: 如果网络请求失败
            DataNotFoundError: 如果学期不存在。
            OperationError: 如果服务器发生异常。
        """
        logger.info("尝试获取全部教学周...")
        if semester_id is None:
            semester_id = self._current_semester_id

        for semester in self.get_semesters():
            if semester.id == semester_id:
                week_indices = semester.week_indices
                break
        else:
            raise DataNotFoundError(
                "semester_id 不存在",
                context={"semester_id": semester_id},
            )

        url = f"{self.COURSE_URL}/{semester_id}"
        try:
            headers = {"Authorization": self._require_user_token()}
            response = self._client.get(url, headers=headers)
            response.raise_for_status()
            logger.trace("{} 请求响应体: {}", url, response.text)

            response_data = response.json()

        except httpx.HTTPStatusError as exc:
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
        except httpx.RequestError as exc:
            logger.error("{} 请求失败: {}", url, exc)
            raise NetworkError.from_exception(
                exc,
                "网络连接异常",
                context={"url": url},
            ) from exc

        if response_data["result"] != 0:
            logger.error("服务器返回消息 {}", response_data["msg"])
            raise OperationError(f"服务器返回消息 {response_data['msg']}")

        try:
            data = LessonModel.model_validate(response_data)
        except ValidationError as exc:
            logger.error("从 {} 响应中解析数据失败: {}", url, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": url},
            ) from exc

        teaching_weeks = []
        for week_index in week_indices:
            teaching_week = TeachingWeek()
            for datum in data.data:
                for schedule in datum.schedules:
                    if schedule.week_index != week_index:
                        continue
                    lesson = Lesson(course=datum.course, schedule=schedule)
                    for unit in range(schedule.start_unit, schedule.end_unit + 1):
                        teaching_week.set(schedule.weekday, unit, lesson)
            teaching_weeks.append(teaching_week)

        return TeachingWeeks(teaching_weeks)

    @require_auth
    def get_week_index(self, date: Date) -> int | None:
        """
        获取指定日期的教学周序数

        Returns:
            int | None: 教学周序数

        Raises:
            ParsingError: 如果响应解析失败。
            NetworkError: 如果网络请求失败。
            OperationError: 如果服务器发生异常。
        """
        logger.info("尝试获取 {} 的教学周序数...", date.format_iso())
        url = f"{self.WEEK_INDEX_URL}"
        params = {"today": date.format_iso()}
        try:
            headers = {"X-Id-Token": self._require_user_token()}
            response = self._client.get(url, headers=headers, params=params)
            response.raise_for_status()
            logger.trace("{} 请求响应体: {}", url, response.text)

            response_data = response.json()

        except httpx.HTTPStatusError as exc:
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
        except httpx.RequestError as exc:
            logger.error("{} 请求失败: {}", url, exc)
            raise NetworkError.from_exception(
                exc,
                "网络连接异常",
                context={"url": url},
            ) from exc

        if response_data["code"] != 0:
            logger.error("服务器返回消息 {}", response_data["msg"])
            raise OperationError(f"服务器返回消息 {response_data['msg']}")

        try:
            data = WeekIndexModel.model_validate(response_data)
        except ValidationError as exc:
            logger.error("从 {} 响应中解析数据失败: {}", url, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": url},
            ) from exc

        if data.data.data.date[0] != "":
            return int(data.data.data.date[0])
        else:
            return None

    @require_auth
    def get_semesters(
        self,
    ) -> list[Semester]:
        """
        获取所有学期数据

        Returns:
            list[Semester]: 所有学期的数据

        Raises:
            ParsingError: 如果响应解析失败。
            NetworkError: 如果网络请求失败。
            OperationError: 如果服务器发生异常。
        """
        logger.info("尝试获取所有学期数据...")
        url = f"{self.ALL_SEMESTERS_URL}"
        try:
            headers = {"Authorization": self._require_user_token()}
            response = self._client.get(url, headers=headers)
            response.raise_for_status()
            logger.trace("{} 请求响应体: {}", url, response.text)

            response_data = response.json()

        except httpx.HTTPStatusError as exc:
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
        except httpx.RequestError as exc:
            logger.error("{} 请求失败: {}", url, exc)
            raise NetworkError.from_exception(
                exc,
                "网络连接异常",
                context={"url": url},
            ) from exc

        if response_data["result"] != 0:
            logger.error("服务器返回消息 {}", response_data["msg"])
            raise OperationError(f"服务器返回消息 {response_data['msg']}")

        try:
            data = SemesterModel.model_validate(response_data)
        except ValidationError as exc:
            logger.error("从 {} 响应中解析数据失败: {}", url, exc)
            raise ParsingError.from_exception(
                exc,
                "服务器响应格式不正确",
                context={"url": url},
            ) from exc

        return data.data

    def logout(self) -> None:
        """登出账户，清除 Cookie 但保留连接池"""
        logger.debug("正在登出教务系统")
        self._client.cookies.clear()
        self._client.headers.clear()
        self._current_semester_id = None
        self._logged_in = False
        logger.debug("EASClient 已登出")

    def close(self) -> None:
        """清除 Cookie 和连接池"""
        if self._logged_in:
            self.logout()
        self._client.close()
        logger.debug("EASClient 已关闭")
