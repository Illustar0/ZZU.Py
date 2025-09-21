# ZZU.Py

豫见郑大的 Python API 封装

## 概述

ZZU.Py 是一个为郑州大学各个线上系统和相关服务提供 Python API 封装的库。它提供了简洁易用的接口来访问校园各类服务，包括移动应用 API、校园网络认证、一卡通服务等。

!!! warning
    研究生教务系统暂未适配

## 特性

- **统一认证系统 (CAS)** - 支持账密登录和 Token 认证
- **智慧教务系统** - 获取课表、查询空教室
- **校园网络服务** - Portal 认证、设备管理、流量查询
- **校园卡服务** - 余额查询、电费充值
- **类型安全** - 基于 Pydantic 的数据模型验证
- **异步支持** - 基于 httpx 的高性能网络请求

## 快速开始

### 安装

```bash
pip install zzupy --upgrade
```

### 基础使用

```python
from zzupy.app import CASClient, SupwisdomClient

# CAS 认证
cas = CASClient("Your account", "Your password")
cas.login()

with SupwisdomClient(cas) as client:
    # 获取本周课表
    week_courses = client.get_week_courses()
    print(week_courses)
```

### 核心模块

#### `app` - 移动应用 API 抽象层

提供基于移动端逆向的 API 封装：

- **auth**: CAS 统一认证系统客户端
- **supwisdom**: 智慧教务系统，支持课表查询、空教室查询
- **ecard**: 校园卡服务，支持余额查询、电费充值
- **interfaces**: 定义统一的客户端接口规范

#### `web` - Web API 客户端模块

提供基于 Web 端逆向的 API 封装：

- **network**: 校园网络服务，包含 Portal 认证和设备管理

#### `aio` - 各模块的异步实现

提供以上模块的异步实现


## 开发指南

### 环境要求

- Python >= 3.13
- 依赖管理：使用 uv

### 贡献代码

欢迎提交 Issue 和 Pull Request。在贡献代码前，请确保：

1. 代码符合项目风格规范
2. 添加必要的类型注解
3. 编写相应的文档字符串
4. 测试通过

## 许可证

本项目使用 MIT 许可证。详见 [LICENSE](https://github.com/Illustar0/ZZU.Py/blob/main/LICENSE) 文件。

## 相关链接

- [GitHub 仓库](https://github.com/Illustar0/ZZU.Py)
- [API 参考文档](reference/api.md)
- [问题反馈](https://github.com/Illustar0/ZZU.Py/issues)

