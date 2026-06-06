from __future__ import annotations

import uuid
from typing import Any, List

from icalendar import Calendar
from icalendar.cal import Event
from pydantic import BaseModel, model_validator, ConfigDict, RootModel, Field
from pydantic.alias_generators import to_camel
from whenever import ZonedDateTime, Date, Instant, Time


class Campus(BaseModel):
    """校区信息"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    name_zh: str
    """校区中文名"""
    name_en: None | str = None
    """校区英文名"""
    code: str
    """校区编号"""


class CultivateType(BaseModel):
    """培养类型，如主修、辅修等"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    name_zh: str
    """培养类型中文名"""
    name_en: str | None = None
    """培养类型英文名"""
    code: str
    """培养类型编号"""


class PeriodInfo(BaseModel):
    """课时详情，描述一门课程各类学时的分配情况"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    total: int
    """总学时"""
    weeks: int
    """开课周数"""
    theory: int | None
    """理论学时数"""
    theory_unit: str | None
    """理论学时单位"""
    require_theory: int | None
    """要求完成的理论学时数"""
    practice: None
    practice_unit: str | None
    require_practice: None
    focus_practice: None
    focus_practice_unit: None
    dispersed_practice: None
    test: None
    test_unit: None
    require_test: None
    experiment: int | None
    """实验学时数"""
    experiment_unit: str | None
    """实验学时单位"""
    require_experiment: int | None
    """要求完成的实验学时数"""
    machine: None
    machine_unit: None
    require_machine: None
    design: None
    design_unit: None
    require_design: None
    periods_per_week: int
    """每周课时数"""
    extra: None
    extra_unit: None
    require_extra: None


class Course(BaseModel):
    """课程基本信息"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    code: str
    """课程编号"""
    name_zh: str
    """课程中文名"""
    name_en: str | None = None
    """课程英文名"""
    credits: float
    """学分"""
    period_info: PeriodInfo
    """课时详情"""
    theory: bool
    """是否含理论课"""
    experiment: bool
    """是否含实验课"""
    practice: bool
    """是否含实践课"""
    test: bool
    """是否含考试课时"""
    machine: bool
    """是否含上机课"""
    design: bool
    """是否含设计课"""
    extra: bool
    """是否含其他课时类型"""


class OpenDepartment(BaseModel):
    """开课院系"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    name_zh: str
    """院系中文名"""
    name_en: None | str = None
    """院系英文名"""
    code: str
    """院系编号"""


class CourseType(BaseModel):
    """课程类型，如必修课、选修课等"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    name_zh: str
    """课程类型中文名"""
    name_en: None | str = None
    """课程类型英文名"""
    code: str
    """课程类型编号"""


class DateTimeText(BaseModel):
    """上课时间的文字描述"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    text_zh: str
    """中文描述"""
    text_en: str
    """英文描述"""
    text: str
    """默认显示文本"""


class DateTimePlaceText(BaseModel):
    """上课时间与地点的文字描述，如「1~16周 星期四 3~4节 主校区 北3_111」"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    text_zh: str
    """中文描述"""
    text_en: str
    """英文描述"""
    text: str
    """默认显示文本"""


class DateTimePlacePersonText(BaseModel):
    """上课时间、地点与教师的文字描述，如「1~16周 星期四 3~4节 主校区 北3_111 王艳玲」"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    text_zh: str
    """中文描述"""
    text_en: str
    """英文描述"""
    text: str
    """默认显示文本"""


class ScheduleText(BaseModel):
    """教学班排课的综合文字描述，聚合了三个层次的描述信息"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    date_time_text: DateTimeText
    """仅时间描述"""
    date_time_place_text: DateTimePlaceText
    """时间+地点描述"""
    date_time_place_person_text: DateTimePlacePersonText
    """时间+地点+教师描述"""


class ScheduleGroup(BaseModel):
    """排课组，将一个教学班的多次课归入同一组"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    """排课组 ID"""
    lesson_id: int
    """所属教学班 ID"""
    no: int
    """排课组序号"""


class Building(BaseModel):
    """楼栋信息"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    name_zh: str
    """楼栋中文名"""
    name_en: None | str = None
    """楼栋英文名"""
    code: str
    """楼栋编号"""


class Room(BaseModel):
    """教室信息"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    name_zh: str
    """教室中文名"""
    name_en: None | str = None
    """教室英文名"""
    building: Building
    """所在楼栋"""
    campus: Campus
    """所在校区"""
    seat_number: None
    """座位数"""


class Schedule(BaseModel):
    """单次课程的具体排课记录"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    schedule_group_id: int
    """所属排课组 ID，关联 ScheduleGroup.id"""
    date: Date
    """上课日期，格式 "YYYY-MM-DD" """
    original_date: None | str = None
    """原始日期"""
    weekday: int
    """星期几，1=周一，4=周四，7=周日"""
    start_time: ZonedDateTime
    """开始时间，格式 HHMM，如 1010 表示 10:10"""
    end_time: ZonedDateTime
    """结束时间，格式 HHMM，如 1150 表示 11:50"""
    teacher_name: str
    """授课教师中文姓名"""
    teacher_name_en: str | None
    """授课教师英文姓名"""
    teacher_id: None | str = None
    person_id: None | str = None
    custom_place: None | str = None
    """自定义上课地点"""
    room: Room | None
    """教室信息"""
    start_unit: int
    """开始节次，如 3（第3节）"""
    end_unit: int
    """结束节次，如 4（第4节）"""
    start_unit_name_zh: None | str = None
    end_unit_name_zh: None | str = None
    start_unit_name_en: None | str = None
    end_unit_name_en: None | str = None
    state: str
    """课程状态"""
    week_index: int
    """本次课所在教学周，如 1 表示第1周"""
    lesson_type: str
    """课时类型，如 "THEORY"（理论课）"""
    periods: int
    """本次课课时数，如 2"""
    real_start_time: ZonedDateTime
    """实际开始时间，格式同 startTime"""
    real_end_time: ZonedDateTime
    """实际结束时间，格式同 endTime"""

    @model_validator(mode="before")
    @classmethod
    def assemble_whenever_datetime(cls, data: dict) -> dict:
        if not isinstance(data, dict):
            return data

        date_str = data.get("date")
        if not date_str:
            return data

        try:
            schedule_date = Date.parse_iso(str(date_str))
        except ValueError as exc:
            raise ValueError(f"无法解析课程日期 date={date_str!r}") from exc

        time_keys = [
            "startTime",
            "endTime",
            "realStartTime",
            "realEndTime",
        ]

        for key in time_keys:
            time_val = data.get(key)
            if time_val:
                if isinstance(time_val, ZonedDateTime):
                    continue

                time_str = str(time_val).strip().zfill(4)
                try:
                    schedule_time = Time.parse(time_str, format="hhmm")
                    data[key] = schedule_date.at(schedule_time).assume_tz(
                        "Asia/Shanghai"
                    )
                except ValueError as exc:
                    raise ValueError(
                        f"无法解析课程时间字段 {key}={time_val!r}"
                    ) from exc

        return data


class Datum(BaseModel):
    """教学班信息，包含课程、排课等完整数据"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    id: int
    """教学班 ID"""
    biz_type_id: int
    """业务类型 ID"""
    campus: Campus
    """开课校区"""
    cultivate_type: CultivateType
    """培养类型"""
    code: str
    """教学班编号"""
    course: Course
    """课程基本信息"""
    remark: None | str = None
    """备注"""
    schedule_state: str
    """排课状态"""
    std_count: int
    """选课学生人数"""
    open_department: OpenDepartment
    """开课院系"""
    course_type: CourseType
    """课程类型"""
    teacher_assignment_list: list[str]
    """授课教师中文姓名列表"""
    teacher_assignment_en_list: list[str | None]
    """授课教师英文姓名列表"""
    schedule_text: ScheduleText
    """排课文字描述（时间/地点/教师）"""
    schedule_groups: list[ScheduleGroup]
    """排课组列表"""
    schedules: list[Schedule]
    """每次课的具体排课记录列表"""
    students: list[Any]
    """学生列表"""
    time_table_layout_assoc: int
    """关联的课表布局 ID"""
    suggest_schedule_weeks_info: None
    """建议排课周信息"""


class LessonModel(BaseModel):
    """课程表查询 API 响应根模型"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    result: int
    """响应结果码"""
    message: None | str = None
    """响应消息"""
    data: list[Datum]
    """教学班数据列表"""


class Lesson(BaseModel):
    """课表中的一节课"""

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True
    )

    course: Course
    """对应课程"""
    schedule: Schedule
    """对应时间"""


class TeachingWeek(BaseModel):
    """教学周课表，7 天 × 10 节的网格"""

    model_config = ConfigDict(frozen=False)

    DAYS: int = 7
    UNITS: int = 10

    lessons: dict[tuple[int, int], Lesson] = Field(default_factory=dict)
    """内部存储：仅存储非空课程，key 为 (weekday, unit)，value 为 Lesson"""

    def _validate_index(self, weekday: int, unit: int) -> None:
        if not (1 <= weekday <= self.DAYS):
            raise IndexError(f"星期 {weekday} 超出范围 (1-{self.DAYS})")
        if not (1 <= unit <= self.UNITS):
            raise IndexError(f"节次 {unit} 超出范围 (1-{self.UNITS})")

    def set(self, weekday: int, unit: int, lesson: Lesson) -> None:
        """设置某天某节的课程

        Args:
            weekday: 第几天
            unit: 第几节
            lesson: 课程

        Raises:
            IndexError: 如果 {weekday} 或 {unit} 超出范围
        """
        self._validate_index(weekday, unit)
        self.lessons[(weekday, unit)] = lesson

    def get(self, weekday: int, unit: int) -> Lesson | None:
        """获取某天某节的课程

        Args:
            weekday: 第几天
            unit: 第几节

        Returns:
            Lesson | None: 对应课程或 None

        Raises:
            IndexError: 如果 {weekday} 或 {unit} 超出范围
        """
        self._validate_index(weekday, unit)
        return self.lessons.get((weekday, unit))

    def get_day(self, weekday: int) -> list[Lesson | None]:
        """获取某天的全部课程

        Args:
            weekday: 第几天

        Returns:
            list[Lesson | None]: 由第 {weekday} 天中的第 {unit} 节课组成的列表

        Raises:
            IndexError: 如果 {weekday} 超出范围
        """
        self._validate_index(weekday, 1)
        return [self.lessons.get((weekday, unit)) for unit in range(1, self.UNITS + 1)]

    def get_unit(self, unit: int) -> list[Lesson | None]:
        """获取某节 7 天的课程

        Args:
            unit: 第几节课

        Returns:
            list[Lesson | None]: 由 7 天中的第 {unit} 节课组成的列表

        Raises:
            IndexError: 如果 {unit} 超出范围
        """
        self._validate_index(1, unit)
        return [self.lessons.get((day, unit)) for day in range(1, self.DAYS + 1)]

    @property
    def grid(self) -> list[list[Lesson | None]]:
        """网格形式的课表，仅在访问时动态生成"""
        return [
            [self.lessons.get((day, unit)) for unit in range(1, self.UNITS + 1)]
            for day in range(1, self.DAYS + 1)
        ]

    def to_calendar(
        self, prodid: str = "-//ZZU.Py//Teaching Schedule Calendar//CN"
    ) -> Calendar:
        """
        将教学周的课表转换为符合 RFC 5545 的 Calendar 对象。
        可以使用以下代码将其写入 .ics 或对它做你想做的任何事
        ```python
        with open('my_schedule.ics', 'wb') as f:
            f.write(aTeachingWeek.to_calendar().to_ical())
        ```

        Args:
            prodid: Calendar 的 prodid 参数。

        Returns:
            Calendar 对象。
        """
        cal = Calendar()
        cal.add("prodid", prodid)
        cal.add("version", "2.0")

        processed_schedule_ids = set()

        for lesson in self.lessons.values():
            if not lesson:
                continue

            schedule = lesson.schedule
            course = lesson.course

            # 去重
            if schedule in processed_schedule_ids:
                continue
            processed_schedule_ids.add(schedule)

            event = Event()

            # 课程中文名
            event.add("summary", course.name_zh)

            # 起始时间
            start_time = (
                schedule.real_start_time.py_datetime()
                or schedule.start_time.py_datetime()
            )
            end_time = (
                schedule.real_end_time.py_datetime() or schedule.end_time.py_datetime()
            )
            event.add("dtstart", start_time)
            event.add("dtend", end_time)

            # 事件生成时间
            event.add("dtstamp", Instant.now().py_datetime())

            # 事件 UID
            event.add("uid", f"{uuid.uuid4()}@schedule")

            # 上课地点
            location = ""
            if schedule.room:
                location = f"{schedule.room.campus.name_zh} {schedule.room.building.name_zh} {schedule.room.name_zh}"
            elif schedule.custom_place:
                location = schedule.custom_place

            if location:
                event.add("location", location)

            # 描述
            description_lines = [
                f"授课教师: {schedule.teacher_name or '未知'}",
                f"课程代码: {course.code}",
                f"学分: {course.credits}",
                f"节次: 第 {schedule.start_unit} - {schedule.end_unit} 节",
                f"教学周: 第 {schedule.week_index} 周",
                f"类型: {schedule.lesson_type}",
            ]
            event.add("description", "\n".join(description_lines))

            cal.add_component(event)
        return cal


class TeachingWeeks(RootModel):
    root: list[TeachingWeek] = Field(default_factory=list)

    def __iter__(self):
        return iter(self.root)

    def __getitem__(self, item):
        return self.root[item]

    def __len__(self):
        return len(self.root)

    def to_calendar(
        self, prodid: str = "-//ZZU.Py//Teaching Schedule Calendar//CN"
    ) -> Calendar:
        """
        将教学周的课表转换为符合 RFC 5545 的 Calendar 对象。
        可以使用以下代码将其写入 .ics 或对它做你想做的任何事
        ```python
        with open('my_schedule.ics', 'wb') as f:
            f.write(aTeachingWeek.to_calendar().to_ical())
        ```

        Args:
            prodid: Calendar 的 prodid 参数。

        Returns:
            Calendar 对象。
        """
        cal = Calendar()
        cal.add("prodid", prodid)
        cal.add("version", "2.0")

        processed_schedule_ids = set()
        for teaching_week in self.root:
            for lesson in teaching_week.lessons.values():
                if not lesson:
                    continue

                schedule = lesson.schedule
                course = lesson.course

                # 去重
                if schedule in processed_schedule_ids:
                    continue
                processed_schedule_ids.add(schedule)

                event = Event()

                # 课程中文名
                event.add("summary", course.name_zh)

                # 起始时间
                start_time = (
                    schedule.real_start_time.py_datetime()
                    or schedule.start_time.py_datetime()
                )
                end_time = (
                    schedule.real_end_time.py_datetime()
                    or schedule.end_time.py_datetime()
                )
                event.add("dtstart", start_time)
                event.add("dtend", end_time)

                # 事件生成时间
                event.add("dtstamp", Instant.now().py_datetime())

                # 事件 UID
                event.add("uid", f"{uuid.uuid4()}@schedule")

                # 上课地点
                location = ""
                if schedule.room:
                    location = f"{schedule.room.campus.name_zh} {schedule.room.building.name_zh} {schedule.room.name_zh}"
                elif schedule.custom_place:
                    location = schedule.custom_place

                if location:
                    event.add("location", location)

                # 描述
                description_lines = [
                    f"授课教师: {schedule.teacher_name or '未知'}",
                    f"课程代码: {course.code}",
                    f"学分: {course.credits}",
                    f"节次: 第 {schedule.start_unit} - {schedule.end_unit} 节",
                    f"教学周: 第 {schedule.week_index} 周",
                    f"类型: {schedule.lesson_type}",
                ]
                event.add("description", "\n".join(description_lines))

                cal.add_component(event)

        return cal


class Semester(BaseModel):
    """单个学期"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: int
    code: str
    name_zh: str
    name_en: str | None = None
    school_year: str
    start_date: Date
    end_date: Date
    week_start_on_sunday: bool
    count_in_term: bool
    season: str
    week_indices: list[int]
    biz_types: None


class SemesterModel(BaseModel):
    """获取全部学期数据 API 响应根模型"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    result: int
    """响应结果码"""
    message: None
    """响应消息"""
    data: list[Semester]
    """学期数据列表"""


class CurrentSemesterModel(BaseModel):
    """获取当前学期数据 API 响应根模型"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    result: int
    """响应结果码"""
    message: None
    """响应消息"""
    data: Semester
    """学期数据列表"""


class WeekIndexModel(BaseModel):
    """获取某日期的教学周序数 API 响应根模型"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    class InnerData(BaseModel):
        model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

        class NestedData(BaseModel):
            model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)
            date: List[str]
            semester: str

        msg: str
        code: int
        data: NestedData
        success: bool

    code: int
    """响应结果码"""
    message: str | None
    """响应消息"""
    data: InnerData
    """学期数据列表"""
