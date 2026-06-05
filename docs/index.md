# ZZU.Py

`zzupy` 为郑州大学常见线上服务提供 Python 客户端，覆盖移动端、Web 端以及对应异步实现。

!!! warning
    当前仅适配本科教务新系统，研究生教务暂未支持。

## 你可以用它做什么

- 使用 App 端 CAS 完成统一认证，支持账密登录和预置 Token，支持 MFA 多因素认证
- 查询新本科教务课表、学期列表、教学周序数，并导出 `.ics`
- 查询校园卡余额、默认房间、电量并为宿舍充值电费
- 在校园网环境下自动发现 Portal 参数并完成认证
- 登录自助服务系统，查看在线设备并踢设备下线

## 安装

```bash
pip install -U zzupy
# uv add zzupy
```

要求：Python `>=3.11`

## 快速开始

### CAS + 本科教务

```python
from zzupy.app import CASClient, UndergradEASClient

cas = CASClient("your_account", "your_password")
# cas.set_token("your_userToken", "your_refreshToken")
# cas.set_device("your_deviceId")
if cas.mfa.is_required():
    cas.mfa.send_sms()
    cas.mfa.verify_sms(input("input sms code:"))
cas.login()

with UndergradEASClient(cas) as eas:
    eas.login()
    week = eas.get_teaching_week(week=1)
    lesson = week.get(weekday=1, unit=1)
    if lesson:
        print(lesson.course.name_zh)
```

### 校园网 Portal 认证

```python
from zzupy.web import EPortalClient, discover_portal_info

portal = discover_portal_info()
with EPortalClient(portal.portal_server_url, bind_address=portal.user_ip, force_bind=True) as client:
    result = client.auth("your_account", "your_password")
    print(result.message)
```

## 模块结构

### `zzupy.app`

- `CASClient`：移动端统一认证
- `UndergradEASClient`：新本科教务
- `ECardClient`：校园一卡通

### `zzupy.web`

- `discover_portal_info`：探测校园网 Portal 参数
- `EPortalClient`：完成 Portal 认证
- `SelfServiceSystem`：校园网设备管理

### `zzupy.aio`

- 提供同步客户端的异步对应实现

## 阅读建议

- 如果你刚开始接入，先看 `Usage`
- 如果你想确认方法签名和模型字段，直接看 `API`
- 如果你在迁移旧教务接口，先看 `Usage -> 教务系统 -> 迁移指南`

## 开发

项目使用 `uv` 管理环境，常用命令：

```bash
uv sync --locked --all-extras
uv run python scripts/generate_api_reference.py
uv run zensical serve
uv run zensical build
ruff check
ruff format
uv build
```
