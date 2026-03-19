# 本科教务系统

`zzupy.app.eas` 当前导出 `UndergradEASClient`，用于访问郑州大学新版本科教务接口。

## 核心能力

- 登录本科教务并校验当前账号可用性
- 获取全部学期列表
- 获取某个学期的全部教学周课表
- 获取指定教学周课表
- 根据日期查询教学周序数
- 将单周或整学期课表导出为 iCalendar

## 前置条件

使用前需要先完成 CAS 登录：

```python
from zzupy.app import CASClient, UndergradEASClient

cas = CASClient("your_account", "your_password")
cas.login()

with UndergradEASClient(cas) as eas:
    eas.login()
```

## 快速开始

```python title="获取第 1 教学周课表"
from zzupy.app import CASClient, UndergradEASClient

cas = CASClient("your_account", "your_password")
cas.login()

with UndergradEASClient(cas) as eas:
    eas.login()

    week = eas.get_teaching_week(week=1)
    lesson = week.get(weekday=1, unit=1)
    if lesson:
        print(lesson.course.name_zh)
```

## 登录行为

`UndergradEASClient.login()` 会先请求用户信息，再缓存当前学期 ID。后续如果调用 `get_teaching_week()` 或 `get_teaching_weeks()` 时没有显式传入 `semester_id`，就会默认使用这个当前学期。

## 课表查询

### 获取单周课表

```python title="查询指定教学周"
week = eas.get_teaching_week(week=3)

lesson = week.get(weekday=3, unit=2)
if lesson:
    print(lesson.course.name_zh)
```

### 获取整学期课表

```python title="查询整学期"
weeks = eas.get_teaching_weeks()
print(len(weeks))
```

### 索引规则

`TeachingWeek` 是 7 x 10 的课表网格：

- `weekday`: `1` 到 `7`，分别对应周一到周日
- `unit`: `1` 到 `10`，分别对应第 1 节到第 10 节

```python title="遍历某一天全部节次"
day = week.get_day(weekday=1)
for idx, lesson in enumerate(day, start=1):
    if lesson:
        print(idx, lesson.course.name_zh)
```

## 学期查询

```python title="读取学期列表"
semesters = eas.get_semesters()

for semester in semesters:
    print(semester.id, semester.name_zh, semester.start_date, semester.end_date)
```

也可以显式指定学期：

```python title="按 semester_id 查询课表"
semesters = eas.get_semesters()
target = semesters[0]

weeks = eas.get_teaching_weeks(semester_id=target.id)
```

## 教学周序数

`get_week_index()` 接收 `whenever.Date`：

```python title="由日期换算教学周"
from whenever import Date

week_index = eas.get_week_index(Date.parse_iso("2025-03-01"))
print(week_index)
```

如果该日期不落在任何教学周中，返回值可能是 `None`。

## iCalendar 导出

`TeachingWeek` 与 `TeachingWeeks` 都实现了 `to_calendar()`：

```python title="导出单周课表"
week = eas.get_teaching_week(week=1)

with open("week1.ics", "wb") as f:
    f.write(week.to_calendar().to_ical())
```

```python title="导出整学期课表"
weeks = eas.get_teaching_weeks()

with open("semester.ics", "wb") as f:
    f.write(weeks.to_calendar().to_ical())
```

## 数据模型

常用模型位于 `zzupy.model.eas`：

- `Lesson`：某一节课，由 `course` 和 `schedule` 组成
- `TeachingWeek`：单周课表，提供 `get()` / `get_day()` / `get_unit()` / `grid`
- `TeachingWeeks`：多个 `TeachingWeek` 的容器，支持索引和遍历
- `Semester`：学期元信息和 `week_indices`

## 异步版本

异步接口位于 `zzupy.aio.app.eas`：

```python title="异步用法"
import asyncio

from zzupy.aio.app import CASClient, UndergradEASClient


async def main():
    cas = CASClient("your_account", "your_password")
    await cas.login()

    async with UndergradEASClient(cas) as eas:
        await eas.login()
        week = await eas.get_teaching_week(week=1)
        print(week.get(weekday=1, unit=1))


asyncio.run(main())
```

## 异常

常见异常：

- `NotLoggedInError`：CAS 未登录或未调用 `eas.login()`
- `NetworkError`：网络请求失败
- `ParsingError`：响应结构变化，Pydantic 校验失败
- `OperationError`：服务端返回业务错误
- `IndexError`：教学周或学期索引超出范围
