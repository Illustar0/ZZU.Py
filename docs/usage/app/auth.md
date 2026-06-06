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
- 获取个人信息聚合数据
- 自动检查 Token 是否即将过期
- 在会话生命周期内维护登录状态

## 快速开始

### 账密登录

!!! warning "副作用"
    账密登录会影响手机端豫见郑大 App 的在线状态。若你已经有可用 Token，优先使用 Token 方式。

```python title="最基本的登录流程"
from zzupy.app import CASClient

cas = CASClient("your_account", "your_password")
# cas.set_token("your_userToken", "your_refreshToken")
# cas.set_device("your_deviceId")
if cas.mfa.is_required():
    cas.mfa.send_sms()
    cas.mfa.verify_sms(input("input sms code:"))
cas.login()

print(cas.logged_in)
print(cas.user_token)
print(cas.refresh_token)
```

### MFA 验证

在 v7.1.0 中，`ZZU.Py` 引入了对 MFA 多因素验证的支持。 **你必须把你的应用升级至 `ZZU.Py >= 7.1.0`。**   
截止 2026 年 6 月 5 日，是否会被要求进行 MFA 验证主要由 `deviceId` 决定。在 `ZZU.Py >= 7.1.0` 中，`ZZU.Py` 内置了字符串 `ZZU.Py` 作为 `deviceId`。

想要适配 MFA 验证，你有两种选择：
#### 1. 使用内置的 `deviceId` 完成一次 MFA 验证并将其添加为可信设备

在你能够实时操作的设备上运行，并确保你能够访问你的 MFA 手机。  
```python title="MFA 验证"
from zzupy.app import CASClient

cas = CASClient("your_account", "your_password")
# 或者你也可以使用你喜欢的字符串作为 deviceId
# cas.set_device("原神牛逼") 
if cas.mfa.is_required():
    cas.mfa.send_sms()
    cas.mfa.verify_sms(input("input sms code:"))
cas.login()

print(cas.logged_in)
print(cas.user_token)
print(cas.refresh_token)
```

接着前往[安全中心](https://authx-service.s.zzu.edu.cn/security-center/eqIP-management)，将设备 ID 显示为 `ZZU.Py` 的设备设置为可信设备。   
完成后，理论上后续 `ZZU.Py` 就不会再被要求进行 MFA 验证。  
使用 `cas.set_device("")`，进行 MFA 验证并设置可信设备无法让 `ZZU.Py < 7.1.0` 的应用正常运转！

#### 2. 抓包并使用常用设备的 deviceId 并将其添加为可信设备

对你的常用设备上的“豫见郑大” APP 进行抓包，获取其 `deviceId`。我们假设它是 `鸣潮牛逼`。  
接着前往[安全中心](https://authx-service.s.zzu.edu.cn/security-center/eqIP-management)，将设备 ID 显示为 `鸣潮牛逼` 的设备设置为可信设备。   
然后在你的应用中使用它。  

```python title="MFA 验证"
from zzupy.app import CASClient

cas = CASClient("your_account", "your_password")
# 设置 deviceId
cas.set_device("鸣潮牛逼") 
if cas.mfa.is_required():
    cas.mfa.send_sms()
    cas.mfa.verify_sms(input("input sms code:"))
cas.login()

print(cas.logged_in)
print(cas.user_token)
print(cas.refresh_token)
```

### 复用已有 Token

```python title="使用 set_token()"
from zzupy.app import CASClient

cas = CASClient("your_account", "your_password")
cas.set_token("your_userToken", "your_refreshToken")
# cas.set_device("your_deviceId")
if cas.mfa.is_required():
    cas.mfa.send_sms()
    cas.mfa.verify_sms(input("input sms code:"))
cas.login()

print(cas.logged_in)
```

如果预置的 Token 仍然有效，`login()` 会直接复用；如果已经失效或即将过期，则会退回账密登录并更新 Token。

### 复用已有 deviceId

```python title="使用 set_device()"
from zzupy.app import CASClient

cas = CASClient("your_account", "your_password")
cas.set_token("your_userToken", "your_refreshToken")
cas.set_device("your_deviceId")
if cas.mfa.is_required():
    cas.mfa.send_sms()
    cas.mfa.verify_sms(input("input sms code:"))
cas.login()

print(cas.logged_in)
```

对常用设备上的豫见郑大抓包来获取 `deviceId`

## 读取个人信息

`get_user_info()` 会组合两个 App 接口，返回学号、姓名、身份类型、学院、一卡通余额、未读邮件数和科研信息数量。

```python title="读取个人信息"
from zzupy.app import CASClient

cas = CASClient("your_account", "your_password")
cas.login()

info = cas.get_user_info()
print(info.name)
print(info.uid)
print(info.balance)
```

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
- `get_user_info()`：获取个人信息聚合数据
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
    info = await cas.get_user_info()
    print(cas.logged_in)
    print(info.name)
    await cas.close()


asyncio.run(main())
```

## 异常

常见异常来自 `zzupy.exception`：

- `ZZUError`：所有项目异常的基类，带 `message`、`context` 和 `to_dict()`
- `LoginError`：账号密码错误，或服务端拒绝登录
- `OperationError`：认证成功但业务接口返回失败结果
- `NetworkError`：网络请求失败
- `ParsingError`：响应结构与预期不符

如果你希望统一处理所有认证失败场景，可以优先捕获 `ZZUError`，再根据 `exc.context` 补充日志。

## 注意事项

- `CASClient` 可作为上下文管理器使用，用完后建议 `close()`
- 预置 Token 时仍然需要传入账号和密码，因为失效后可能自动退回账密登录
- 当前实现不会单独调用 refresh token 接口，而是直接重新走账密登录流程
