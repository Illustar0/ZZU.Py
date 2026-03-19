# 校园一卡通

`zzupy.app.ecard` 提供 `ECardClient`，用于访问校园卡余额、电费和宿舍房间相关接口。

## 前置条件

`ECardClient` 依赖已经登录的 `CASClient`：

```python
from zzupy.app import CASClient, ECardClient

cas = CASClient("your_account", "your_password")
cas.login()

with ECardClient(cas) as ecard:
    ecard.login()
```

## 核心能力

- 查询校园卡余额
- 获取默认宿舍房间
- 按层级枚举区域 / 楼栋 / 楼层 / 房间
- 查询宿舍剩余电量
- 为指定宿舍充值电费

## 快速开始

```python title="余额与电量查询"
from zzupy.app import CASClient, ECardClient

cas = CASClient("your_account", "your_password")
cas.login()

with ECardClient(cas) as ecard:
    ecard.login()

    print("余额:", ecard.get_balance())
    print("默认房间:", ecard.get_default_room())
    print("默认房间剩余电量:", ecard.get_remaining_energy())
```

## 登录与会话

`ECardClient.login()` 会完成两步：

1. 通过 CAS Token 换取 `tid`
2. 再向一卡通服务换取自己的 `accessToken` / `refreshToken`

登录成功后，客户端会定时重新获取 Token，默认周期为 45 分钟。

## 余额查询

```python title="查询校园卡余额"
balance = ecard.get_balance()
print(f"校园卡余额: {balance:.2f} 元")
```

## 房间查询

### 获取默认房间

```python title="读取默认宿舍"
room = ecard.get_default_room()
print(room)
```

房间 ID 形如 `99-12--33-404`，格式为：

- `area-building--level-room`

### 逐级枚举房间

`get_room_dict(room_id)` 的入参表示当前层级：

- `""`：所有区域
- `"99"`：区域下的楼栋
- `"99-12"`：楼栋下的楼层/单元
- `"99-12--33"`：楼层/单元下的房间

```python title="逐级获取房间 ID"
areas = ecard.get_room_dict("")
buildings = ecard.get_room_dict("99")
levels = ecard.get_room_dict("99-12")
rooms = ecard.get_room_dict("99-12--33")
```

## 剩余电量

### 查询默认房间

```python
energy = ecard.get_remaining_energy()
print(energy)
```

### 查询指定房间

```python
energy = ecard.get_remaining_energy(room="99-12--33-404")
print(energy)
```

## 电费充值

`recharge_energy()` 需要三个参数：

- `payment_password`：一卡通支付密码
- `amt`：充值金额，必须大于 `0`
- `room`：目标房间 ID

```python title="为指定房间充值电费"
import os

payment_password = os.environ["ECARD_PAYMENT_PASSWORD"]

ecard.recharge_energy(
    payment_password=payment_password,
    amt=30,
    room="99-12--33-404",
)
```

!!! danger "安全提示"
    不要在代码中硬编码支付密码。推荐从环境变量、密钥管理系统或本地加密配置中读取。

## 异步版本

异步接口位于 `zzupy.aio.app.ecard`：

```python title="异步用法"
import asyncio

from zzupy.aio.app import CASClient, ECardClient


async def main():
    cas = CASClient("your_account", "your_password")
    await cas.login()

    async with ECardClient(cas) as ecard:
        await ecard.login()
        balance = await ecard.get_balance()
        print(balance)


asyncio.run(main())
```

## 异常

常见异常：

- `NotLoggedInError`：CAS 未登录，或一卡通客户端未完成 `login()`
- `NetworkError`：网络请求失败
- `ParsingError`：服务端响应结构变化
- `OperationError`：充值等操作被服务端拒绝
- `ValueError`：房间 ID 或金额参数不合法

## 注意事项

- `ECardClient` 初始化时就会检查 `cas_client.logged_in`
- 查询电量时如果不传 `room`，会自动调用 `get_default_room()`
- `get_room_dict()` 和 `get_remaining_energy()` 都要求房间 ID 使用一卡通系统自己的格式
