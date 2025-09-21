# 智慧教务系统

智慧教务系统（树维教务）模块提供了郑州大学教务系统的各项功能，包括课表查询、空教室查询、学期信息获取等服务。

## 模块概述 {#overview}

`zzupy.app.supwisdom` 模块包含以下主要功能：

- **课表查询** - 获取个人课程表信息
- **空教室查询** - 查询教室占用状态和空闲教室
- **学期管理** - 获取学期信息和切换学期
- **智能课程分析** - 获取下一节课、今日课程等

## 快速开始 {#quick-start}

### 基础使用

当然，我个人是不推荐这种使用方法的。如果你没有对豫见郑大 App 做特殊处理，那么你 ZZU.Py 每次登录都会把你手机上的豫见郑大 App 踢下线
```python title="基础课表查询"
from zzupy.app import CASClient, SupwisdomClient

# 统一认证登录
cas = CASClient("your_account", "your_password")
cas.login()

# 创建智慧教务客户端
with SupwisdomClient(cas) as client:
    # 登录教务系统
    client.login()
    
    # 获取本周课表
    schedule = client.get_current_week_courses()
    
    # 打印今天的课程
    today_courses = client.get_today_courses()
    for i, course in enumerate(today_courses):
        if course is not None:
            print(f"第{i+1}节: {course.course_name}")
```

### Token 认证方式

!!! info "推荐方式"
    如果已有有效的 Token，可以直接使用 Token 认证，避免重复登录。
    即便没有，你也可以先账密登录，再访问 CASClient 实例的 [`user_token`][zzupy.app.auth.CASClient.user_token] 和 [`refresh_token`][zzupy.app.auth.CASClient.refresh_token] 来获取。

```python title="使用已有Token"
from zzupy.app import CASClient, SupwisdomClient

# 使用已有的 Token
cas = CASClient("your_account", "your_password") 
cas.set_token("your_user_token", "your_refresh_token")
cas.login()  # 会验证 Token 有效性，无效则调用账密登录并刷新 Token

with SupwisdomClient(cas) as client:
    client.login()
    schedule = client.get_current_week_courses()
```

## 课表查询 {#course-schedule}

### 获取周课表

```python title="获取指定周课表"
# 获取指定日期所在周的课表
schedule = client.get_courses("2024-03-04")  # 自动调整为周一

# 课表是 7x10 的 numpy 矩阵
# 行: 星期 (0=周一, 1=周二, ..., 6=周日)
# 列: 节次 (0=第1节, 1=第2节, ..., 9=第10节)
print(f"课表矩阵形状: {schedule.shape}")

# 遍历整周课表
for day in range(7):
    day_name = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"][day]
    print(f"\n{day_name}:")
    
    for period in range(10):
        course = schedule[day, period]
        if course is not None:
            print(f"  第{period+1}节: {course.course_name} @ {course.rooms[0].name}")
```

### 获取今日课程

```python title="今日课程查询"
# 获取今天的课程
today_courses = client.get_today_courses()

print("今日课程安排:")
for i, course in enumerate(today_courses):
    if course is not None:
        teachers = ", ".join([t.name for t in course.teachers])
        rooms = ", ".join([r.name for r in course.rooms])
        print(f"第{i+1}节 ({course.start_time}-{course.end_time}):")
        print(f"  课程: {course.course_name}")
        print(f"  教师: {teachers}")
        print(f"  教室: {rooms}")
```

### 获取下一节课

```python title="智能课程提醒"
# 获取今天剩余的下一节课
next_course = client.get_next_course_today()

if next_course:
    print(f"下一节课: {next_course.course_name}")
    print(f"时间: {next_course.start_time}-{next_course.end_time}")
    print(f"地点: {next_course.rooms[0].name}")
else:
    print("今天没有更多课程了")
```

## 空教室查询 {#empty-rooms}

### 查询教室占用状态

```python title="教室占用查询"
# 查询指定建筑的教室占用情况
# building_id 需要通过其他途径获取，常见的有：
# 1: 主楼, 2: 东教学楼, 3: 西教学楼等
room_data = client.get_room_data(building_id=1)

print(f"查询日期: {room_data.date}")
print(f"时间段总数: {room_data.max_unit}")
print(f"教室总数: {len(room_data.rooms)}")

# 查看第一个教室的占用情况
first_room = room_data.rooms[0]
print(f"\n{first_room.room_name} ({first_room.building_name}):")
print(f"容量: {first_room.room_capacity}人")
print(f"占用状态: {first_room.occupy_units}")
```

### 查找空闲教室

```python title="空闲教室查找"
# 获取教室数据
room_data = client.get_room_data(building_id=1)

# 查找第3-4节课（上午第3-4节）时间段的空闲教室
empty_rooms_morning = room_data.get_available_rooms(3)  # 第3节
print(f"第3节课空闲教室数量: {len(empty_rooms_morning)}")

for room in empty_rooms_morning[:5]:  # 显示前5个
    print(f"- {room.room_name} (容量: {room.room_capacity}人)")

# 查找下午第1-2节课的空闲教室
empty_rooms_afternoon = room_data.get_available_rooms(6)  # 第6节
print(f"\n第6节课空闲教室数量: {len(empty_rooms_afternoon)}")
```

### 按条件筛选教室

```python title="高级教室筛选"
room_data = client.get_room_data(building_id=1)

# 筛选容量大于100人的大教室
large_rooms = [
    room for room in room_data.get_available_rooms(3)
    if room.room_capacity > 100
]

print("大型空闲教室:")
for room in large_rooms:
    print(f"- {room.room_name}: {room.room_capacity}人")

# 按楼层筛选
third_floor_rooms = [
    room for room in room_data.get_available_rooms(3)
    if room.floor == "3"
]

print(f"\n三楼空闲教室: {len(third_floor_rooms)}间")
```

## 学期管理 {#semester-management}

### 获取学期信息

```python title="学期信息查询"
# 获取所有学期数据
semester_data = client.get_semester_data()

print(f"当前默认学期ID: {semester_data.cur_semester_id}")
print(f"可用学期数量: {len(semester_data.semesters)}")

# 遍历所有学期
for semester in semester_data.semesters:
    print(f"学期: {semester.name} ({semester.code})")
    print(f"  时间: {semester.start_date} ~ {semester.end_date}")
    print(f"  学年: {semester.year} {semester.season}")
```

### 切换学期查询

```python title="跨学期课表查询"
# 获取学期信息
semester_data = client.get_semester_data()

# 选择特定学期
target_semester = semester_data.semesters[1]  # 选择第二个学期
print(f"切换到学期: {target_semester.name}")

# 查询该学期的课表
schedule = client.get_current_week_courses(semester_id=target_semester.id)

# 查询该学期的今日课程
today_courses = client.get_today_courses(semester_id=target_semester.id)
```

## 数据模型 {#data-models}

### Course 课程模型

课程信息模型：

[:octicons-link-external-24: Course 完整文档][zzupy.models.Course]

```python
class Course:
    course_code: str        # 课程代码
    course_name: str        # 课程名称
    date: str              # 上课日期 (YYYY-MM-DD)
    start_time: str        # 上课时间 (HH:MM)
    end_time: str          # 下课时间 (HH:MM)
    start_unit: int        # 开始节次
    end_unit: int          # 结束节次
    lesson_id: int         # 课程ID
    lesson_no: str         # 课程编号
    rooms: List[Room]      # 教室列表
    teachers: List[Teacher] # 教师列表
    weeks: str             # 周次信息
    weekstate: str         # 周状态
    teachclass_std_count: int # 班级人数
```

### RoomOccupancyData 教室占用数据

教室占用信息模型：

[:octicons-link-external-24: RoomOccupancyData 完整文档][zzupy.models.RoomOccupancyData]

```python
class RoomOccupancyData:
    date: str                    # 查询日期
    max_unit: int               # 最大时间单元数
    rooms: List[RoomOccupancy]  # 教室占用信息列表
    
    def get_available_rooms(self, unit_index: int) -> List[RoomOccupancy]:
        # 获取指定时间段的空闲教室
```

### SemesterData 学期数据

学期信息模型：

[:octicons-link-external-24: SemesterData 完整文档][zzupy.models.SemesterData]

```python
class SemesterData:
    cur_semester_id: int        # 当前默认学期ID
    semesters: List[Semester]   # 学期列表
```

## 异步支持 {#async-support}

所有功能都提供异步版本，位于 `zzupy.aio.app.supwisdom` 模块：

```python title="异步使用示例"
from zzupy.aio.app import CASClient, SupwisdomClient

async def get_schedule():
    # 异步认证
    cas = CASClient("your_account", "your_password")
    await cas.login()
    
    # 异步教务操作
    async with SupwisdomClient(cas) as client:
        await client.login()
        
        # 异步获取课表
        schedule = await client.get_current_week_courses()
        today_courses = await client.get_today_courses()
        
        return schedule, today_courses

# 在异步环境中使用
import asyncio
schedule, today_courses = asyncio.run(get_schedule())
```

## 错误处理 {#error-handling}

详见[`zzupy.app.supwisdom`][zzupy.app.supwisdom]

## 注意事项 {#notes}

!!! warning "重要提醒"
    
    1. **认证依赖**: SupwisdomClient 需要已登录的 CASClient 实例
    3. **Token 有效期**: userToken 约1个月有效，refreshToken 约2个月有效
    4. **API 限制**: 避免频繁请求，可能会被限制访问
    5. **数据时效性**: 课表数据可能存在更新延迟

## 常见问题 {#faq}

??? question "SupwisdomClient 初始化失败？"
    
    确保 CASClient 已经成功登录：
    
    ```python
    cas = CASClient("account", "password")
    cas.login()  # 必须先登录
    
    # 检查登录状态
    if not cas.logged_in:
        raise Exception("CAS登录失败")
    
    client = SupwisdomClient(cas)
    ```

??? question "课表矩阵如何理解？"
    
    课表是一个 7×10 的 numpy 矩阵：
    
    - **行索引** (0-6): 星期一到星期日
    - **列索引** (0-9): 第1节到第10节课
    - **元素值**: Course 对象或 None
    
    ```python
    # 获取周三第5节课
    wednesday_5th = schedule[2, 4]  # 注意索引从0开始
    
    # 获取周五全天课程
    friday_courses = schedule[4, :]
    ```

??? question "建筑ID如何获取？"
    
    建筑ID需要通过其他方式获取，常见的包括：
    
    - 主楼: 1
    - 东教学楼: 2  
    - 西教学楼: 3
    
    也可以通过网页版教务系统查看具体的建筑ID。

??? question "时间单元索引如何理解？"
    
    时间单元索引从1开始，对应实际的上课节次：
    
    - 1-2节: 第1-2个时间单元
    - 3-4节: 第3-4个时间单元
    - 以此类推
    
    ```python
    # 查找第3-4节课的空教室
    empty_rooms = room_data.get_available_rooms(3)  # 第3节
    ```

??? question "如何处理跨学期查询？"
    
    指定 semester_id 参数：
    
    ```python
    # 获取所有学期
    semester_data = client.get_semester_data()
    
    # 选择目标学期
    target_semester_id = semester_data.semesters[0].id
    
    # 查询指定学期课表
    schedule = client.get_courses("2024-03-04", semester_id=target_semester_id)
    ```