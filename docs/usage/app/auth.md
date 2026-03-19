# 统一认证系统

`zzupy.app.auth` 提供 App 端统一认证客户端 `CASClient`，负责获取和维护 `userToken` / `refreshToken`。

## 认证模型

郑州大学的统一认证在 Web 端和移动端是两套不同实现：

- Web 端：传统登录页流程
- App 端：JWT Token 流程

`zzupy.app.CASClient` 封装的是后者，因此它更适合给 `zzupy.app` 与 `zzupy.aio.app` 下的客户端复用。

## 核心能力

- 账密登录
- 预置 Token 后跳过账密登录
- 自动检查 Token 是否即将过期
- 在会话生命周期内维护登录状态

## 快速开始

### 账密登录

!!! warning "副作用"
    账密登录会影响手机端豫见郑大 App 的在线状态。若你已经有可用 Token，优先使用 Token 方式。

```python title="最基本的登录流程"
from zzupy.app import CASClient

cas = CASClient("your_account", "your_password")
cas.login()

print(cas.logged_in)
print(cas.user_token)
print(cas.refresh_token)
```

### 复用已有 Token

```python title="使用 set_token()"
from zzupy.app import CASClient

cas = CASClient("your_account", "your_password")
cas.set_token("your_user_token", "your_refresh_token")
cas.login()

print(cas.logged_in)
```

如果预置的 Token 仍然有效，`login()` 会直接复用；如果已经失效或即将过期，则会退回账密登录并更新 Token。

## 与其他客户端配合使用

`CASClient` 本身只负责认证。通常你会把它传给其他 App 客户端：

```python title="给 EAS / 一卡通复用"
from zzupy.app import CASClient, ECardClient, UndergradEASClient

cas = CASClient("your_account", "your_password")
cas.login()

with UndergradEASClient(cas) as eas:
    eas.login()

with ECardClient(cas) as ecard:
    ecard.login()
```

## Token 持久化

项目本身不约束存储方式，只要求你在下次启动时重新调用 `set_token()`。

```python title="简单文件持久化示例"
import json
from pathlib import Path

from zzupy.app import CASClient

token_file = Path("tokens.json")

cas = CASClient("your_account", "your_password")

if token_file.exists():
    tokens = json.loads(token_file.read_text())
    cas.set_token(tokens["user_token"], tokens["refresh_token"])

cas.login()

token_file.write_text(
    json.dumps(
        {
            "user_token": cas.user_token,
            "refresh_token": cas.refresh_token,
        },
        ensure_ascii=False,
        indent=2,
    )
)
```

!!! warning "安全提示"
    `userToken` 和 `refreshToken` 都是敏感凭据。示例仅展示调用方式；生产环境请自行加密存储。

## 常用属性与方法

- `login()`：登录或校验当前 Token
- `set_token(user_token, refresh_token)`：预置已有 Token
- `logout()`：清理当前登录状态
- `close()`：关闭底层连接
- `logged_in`：当前是否已登录
- `user_token` / `refresh_token`：当前会话 Token

## 异步版本

异步接口位于 `zzupy.aio.app.auth`，方法名基本一致，只是改为 `await` 调用：

```python title="异步登录"
import asyncio

from zzupy.aio.app import CASClient


async def main():
    cas = CASClient("your_account", "your_password")
    await cas.login()
    print(cas.logged_in)
    await cas.close()


asyncio.run(main())
```

## 异常

常见异常来自 `zzupy.exception`：

- `ZZUError`：所有项目异常的基类，带 `message`、`context` 和 `to_dict()`
- `LoginError`：账号密码错误，或服务端拒绝登录
- `NetworkError`：网络请求失败
- `ParsingError`：响应结构与预期不符

如果你希望统一处理所有认证失败场景，可以优先捕获 `ZZUError`，再根据 `exc.context` 补充日志。

## 注意事项

- `CASClient` 可作为上下文管理器使用，用完后建议 `close()`
- 预置 Token 时仍然需要传入账号和密码，因为失效后可能自动退回账密登录
- 当前实现不会单独调用 refresh token 接口，而是直接重新走账密登录流程
