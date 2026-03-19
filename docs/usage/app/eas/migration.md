# 教务系统迁移指南

本页面用于从旧的 `SupwisdomClient` 迁移到新的 `UndergradEASClient`。

## 适用范围

- 旧接口：`zzupy.app.supwisdom.SupwisdomClient`
- 新接口：`zzupy.app.eas.UndergradEASClient`

!!! warning "兼容性说明"
    `SupwisdomClient` 已不再作为当前公开接口维护。新项目请直接使用 `UndergradEASClient`。

## 迁移时最重要的变化

- 新接口围绕“教学周”组织数据，而不是直接提供“当前周 / 今日 / 下一节课”等便捷方法
- 课表数据改为结构化模型，常用字段位于 `zzupy.model.eas`
- 支持 `TeachingWeek.to_calendar()` / `TeachingWeeks.to_calendar()`
- 旧接口中的空教室查询能力目前没有对应实现

## API 对照

| 场景 | 旧接口 | 新接口 | 说明 |
| --- | --- | --- | --- |
| 登录教务 | `client.login()` | `eas.login()` | 都要求先完成 CAS 登录 |
| 当前周课表 | `get_current_week_courses()` | `get_teaching_week(week)` | 需要你自己确定教学周序数 |
| 指定周课表 | `get_courses(date)` | `get_teaching_week(week)` | 新接口按教学周查询 |
| 今日课程 | `get_today_courses()` | 无直接等价方法 | 用 `TeachingWeek.get_day()` 自行筛选 |
| 下一节课 | `get_next_course_today()` | 无直接等价方法 | 需要在当天节次中自行判断 |
| 学期信息 | `get_semester_data()` | `get_semesters()` | 新接口返回 `list[Semester]` |
| 空教室 | `get_room_data()` | 不支持 | 暂无替代接口 |
| 导出日历 | 不支持 | `to_calendar()` | 新增能力 |

## 迁移示例

### 初始化与登录

```python title="旧接口"
from zzupy.app import CASClient, SupwisdomClient

cas = CASClient("your_account", "your_password")
cas.login()

with SupwisdomClient(cas) as client:
    client.login()
```

```python title="新接口"
from zzupy.app import CASClient, UndergradEASClient

cas = CASClient("your_account", "your_password")
cas.login()

with UndergradEASClient(cas) as eas:
    eas.login()
```

### 课表查询

```python title="旧接口：当前周"
week = client.get_current_week_courses()
```

```python title="新接口：指定教学周"
week = eas.get_teaching_week(week=1)
```

### 由日期换算教学周

```python title="先算周序数，再查课表"
from whenever import Date

week_index = eas.get_week_index(Date.parse_iso("2025-03-01"))
if week_index is not None:
    week = eas.get_teaching_week(week=week_index)
```

### 今日课程的替代写法

```python title="用 get_day() 自行筛选"
week = eas.get_teaching_week(week=1)
lessons_today = week.get_day(weekday=1)

for idx, lesson in enumerate(lessons_today, start=1):
    if lesson:
        print(f"第{idx}节", lesson.course.name_zh)
```

### 导出日历

```python title="导出 .ics"
weeks = eas.get_teaching_weeks()

with open("semester.ics", "wb") as f:
    f.write(weeks.to_calendar().to_ical())
```

## 异步迁移

异步版本的迁移原则完全相同，只是调用方式改为 `await`：

```python title="异步版本"
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

## 迁移建议

- 如果旧代码依赖“当前周 / 今日 / 下一节课”这样的便捷方法，建议先在业务层封装一层兼容函数
- 如果你只需要导出课表，新接口已经足够直接，优先使用 `to_calendar()` 而不是自己拼 `.ics`
- 如果你依赖空教室查询，当前需要继续保留旧逻辑或等待后续支持
