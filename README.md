# ZZU.Py

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Illustar0/ZZU.Py)    

豫见郑大相关服务的 Python API 封装。

## 概述

`zzupy` 面向郑州大学常用线上服务，提供统一、显式且带类型提示的 Python 客户端。当前主要覆盖：

- App 端统一认证（CAS）
- 新本科教务（EAS）
- 校园一卡通
- 校园网 Portal 认证与自助服务系统
- 对应的异步实现

> [!WARNING]
> 当前仅适配本科教务新系统，研究生教务暂未支持。

## 特性

- 账密登录与 Token 复用并存，适合脚本和长期任务
- 同步 / 异步 API 基本对齐，迁移成本低
- 使用 Pydantic 模型组织响应数据，便于补全和校验
- 提供统一异常层级，公共异常基类为 `zzupy.exception.ZZUError`
- 保留较底层的请求行为，尽量贴近真实上游接口

## 安装

```bash
pip install -U zzupy
```

要求：

- Python `>=3.11`

## 快速开始

### 统一认证 + 本科教务

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

## 模块概览

### `zzupy.app`

- `CASClient`: App 端统一认证
- `UndergradEASClient`: 新本科教务课表与学期数据
- `ECardClient`: 校园卡余额、电费与房间相关接口

### `zzupy.web`

- `discover_portal_info`: 自动探测校园网 Portal 参数
- `EPortalClient`: Portal 认证
- `SelfServiceSystem`: 自助服务系统设备管理

### `zzupy.aio`

- 提供 `app` 与 `web` 下主要客户端的异步版本

## 文档

- 使用文档：<https://illustar0.github.io/ZZU.Py/>
- API 参考：<https://illustar0.github.io/ZZU.Py/reference/api/>
- 文档站点由 `Zensical` 构建

## 开发

项目使用 `uv` 管理环境和命令。

```bash
uv sync --extra develop,docs
uv run python scripts/generate_api_reference.py
uv run zensical serve
uv run zensical build
ruff format zzupy
ruff check zzupy
ty check zzupy
uv build
```

异常处理建议优先捕获 `zzupy.exception.ZZUError`，再按需细分到 `NetworkError`、`ParsingError`、`OperationError`、`InvalidArgumentError` 等具体异常。

如需快速打开库内日志，推荐直接调用 `logger.enable("zzupy")`。
```python
# 启用 TRACE 日志
from loguru import logger
import sys

logger.remove()
logger.add(sys.stderr, level="TRACE")
logger.enable("zzupy")
```

## 许可证

本项目使用 MIT 许可证，详见 `LICENSE`。

## 相关链接

- GitHub：<https://github.com/Illustar0/ZZU.Py>
- Issues：<https://github.com/Illustar0/ZZU.Py/issues>
