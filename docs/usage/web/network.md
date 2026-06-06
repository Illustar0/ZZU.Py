# 校园网络服务

`zzupy.web.network` 提供三部分能力：

- `discover_portal_info()`：自动探测当前网络的 Portal 参数
- `EPortalClient`：执行 Portal 认证
- `SelfServiceSystem`：登录校园网自助服务系统并管理在线设备

## Portal 认证

### 推荐流程：先自动发现，再认证

```python title="自动发现 Portal 信息"
from zzupy.web import EPortalClient, discover_portal_info

portal = discover_portal_info()

with EPortalClient(portal.portal_server_url, bind_address=portal.user_ip) as client:
    result = client.auth("your_account", "your_password")
    print(result.success, result.message)
```

`discover_portal_info()` 会尝试：

1. 访问外部地址，判断当前是否被 Portal 劫持
2. 解析跳转后的认证页 URL
3. 提取 `user_ip` 与认证页基地址
4. 尝试推断真正的 Portal 服务端地址

!!! warning "调用前提"
    这个探测流程需要你当前处于校园网认证环境中。如果已经完成认证，它会抛出 `NetworkError`。

### 手动指定 Portal 地址

如果你已经知道 Portal 服务地址，也可以直接创建客户端：

```python title="直接认证"
from zzupy.web import EPortalClient

with EPortalClient("http://172.16.2.9:801") as client:
    result = client.auth("your_account", "your_password")
    print(result.message)
```

## `EPortalClient` 参数说明

### `bind_address`

默认会自动取本机 IP，也可以手动指定：

```python
with EPortalClient("http://172.16.2.9:801", bind_address="192.168.1.100") as client:
    result = client.auth("your_account", "your_password")
```

### `force_bind`

在路由器或旁路网关环境中，本机可能并没有 `portal.user_ip` 对应的地址。此时可以启用 `force_bind=True`，让客户端即使无法真正绑定该 IP，也把它写入认证参数：

```python
portal = discover_portal_info()

with EPortalClient(
    portal.portal_server_url,
    bind_address=portal.user_ip,
    force_bind=True,
) as client:
    result = client.auth("your_account", "your_password")
```

### `isp_suffix`

`auth()` 支持直接追加运营商后缀：

```python title="融合宽带示例"
result = client.auth("your_account", "your_password", isp_suffix="@cmcc")
```

常见值：

- `@cmcc`
- `@unicom`
- `@telecom`

### `encrypt`

`auth(..., encrypt=True)` 会启用 Portal 参数加密模式，对应底层的 `portal_auth()` 加密实现。

```python
result = client.auth("your_account", "your_password", encrypt=True)
```

!!! note "实际情况"
    当前大多数校园网 Portal 场景下并不需要启用该选项。

## Portal 返回结果

`EPortalClient.auth()` 返回 `zzupy.model.network.AuthResult`：

- `result`：结果码
- `message`：服务端消息（由 `msg` 字段映射而来）
- `ret_code`：附加状态码，可能为空
- `success`：当 `result == 1` 时为 `True`

```python
result = client.auth("your_account", "your_password")
if result.success:
    print("认证成功")
else:
    print(result.message)
```

## 自助服务系统

`SelfServiceSystem` 用于访问学校的校园网自助服务页面。不同园区的地址可能不同，常见形式类似 `http://10.2.7.16:8080`。

### 登录并查看在线设备

```python title="查询在线设备"
from zzupy.web import SelfServiceSystem

with SelfServiceSystem("http://10.2.7.16:8080") as system:
    system.login("your_account", "your_password")
    devices = system.get_online_devices()

    for device in devices:
        print(device.ip, device.mac, device.login_time)
```

### 踢设备下线

```python title="踢掉一台设备"
with SelfServiceSystem("http://10.2.7.16:8080") as system:
    system.login("your_account", "your_password")
    devices = system.get_online_devices()

    if devices:
        system.kick_device(devices[0].session_id)
```

## 数据模型

常用模型位于 `zzupy.model.network`：

- `PortalInfo`：认证页地址、Portal 服务地址、用户 IP
- `AuthResult`：Portal 认证结果
- `OnlineDevice`：自助服务系统中的在线设备信息

!!! note "字段命名"
    `OnlineDevice` 使用 snake_case 字段名，例如 `login_time`、`session_id`。旧的 camelCase 属性仍可读取，但会触发 `DeprecationWarning`。

## 异步版本

异步接口位于 `zzupy.aio.web.network`：

```python title="异步 Portal 认证"
import asyncio

from zzupy.aio.web import EPortalClient, SelfServiceSystem, discover_portal_info


async def main():
    portal = await discover_portal_info()

    async with EPortalClient(portal.portal_server_url, bind_address=portal.user_ip) as client:
        result = await client.auth("your_account", "your_password")
        print(result.message)

    async with SelfServiceSystem("http://10.2.7.16:8080") as system:
        await system.login("your_account", "your_password")
        devices = await system.get_online_devices()
        print(len(devices))


asyncio.run(main())
```

## 异常

常见异常：

- `ZZUError`：所有项目异常的基类，带 `context` 可用于统一日志处理
- `NetworkError`：网络请求失败，或当前网络不在预期认证状态
- `ParsingError`：HTML / JSON / JSONP 结构变化
- `LoginError`：自助服务系统登录失败
- `NotLoggedInError`：未登录却调用需要登录的方法
- `OperationError`：踢设备等操作收到异常状态码

## 注意事项

- `discover_portal_info()` 返回的是 `PortalInfo`；通常不需要自己拼 URL
- `SelfServiceSystem.login()` 依赖页面里隐藏的 `checkcode` 字段，若学校页面改版，优先检查这里
- 不同园区的自助服务系统地址可能不同；如果登录失败，先确认地址是否正确
