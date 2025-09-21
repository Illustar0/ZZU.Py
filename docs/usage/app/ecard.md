# 校园一卡通系统

校园一卡通系统模块提供了郑州大学一卡通的各项功能，包括余额查询、电费充值、剩余电量查询等服务。

## 模块概述 {#overview}

`zzupy.app.ecard` 模块包含以下主要功能：

- **余额查询** - 查询校园卡当前余额
- **电费充值** - 为宿舍充值电费
- **电量查询** - 查询宿舍剩余电量
- **房间管理** - 获取和管理宿舍房间信息
- **自动刷新** - Token 自动刷新机制，确保会话持续有效

## 快速开始 {#quick-start}

### 基础使用

!!! warning "认证依赖"
    ECardClient 需要已登录的 CASClient 实例才能正常工作。

```python title="基础一卡通操作"
from zzupy.app import CASClient, ECardClient

# 统一认证登录
cas = CASClient("your_account", "your_password")
cas.login()

# 创建一卡通客户端
with ECardClient(cas) as ecard:
    # 登录一卡通系统
    ecard.login()
    
    # 查询校园卡余额
    balance = ecard.get_balance()
    print(f"校园卡余额: {balance} 元")
    
    # 查询默认宿舍剩余电量
    energy = ecard.get_remaining_energy()
    print(f"剩余电量: {energy} 度")
```

### Token 认证方式

```python title="使用已有Token"
from zzupy.app import CASClient, ECardClient

# 使用已有的 Token
cas = CASClient("your_account", "your_password") 
cas.set_token("your_user_token", "your_refresh_token")
cas.login()  # 会验证 Token 有效性

with ECardClient(cas) as ecard:
    ecard.login()
    balance = ecard.get_balance()
    print(f"当前余额: {balance} 元")
```

## 余额查询 {#balance-query}

### 校园卡余额

```python title="查询校园卡余额"
# 查询当前校园卡余额
balance = ecard.get_balance()
print(f"校园卡余额: {balance:.2f} 元")

# 余额不足提醒
if balance < 10:
    print("⚠️ 余额不足，请及时充值")
elif balance < 50:
    print("💡 余额较低，建议充值")
else:
    print("✅ 余额充足")
```

## 电费管理 {#electricity-management}

### 查询剩余电量

```python title="电量查询"
# 查询默认宿舍剩余电量
energy = ecard.get_remaining_energy()
print(f"默认宿舍剩余电量: {energy} 度")

# 查询指定房间剩余电量
room_id = "99-12--33-404"  # 房间ID格式: areaid-buildingid--unitid-roomid
energy = ecard.get_remaining_energy(room=room_id)
print(f"房间 {room_id} 剩余电量: {energy} 度")

# 电量预警
if energy < 5:
    print("🔴 电量严重不足，请立即充值")
elif energy < 20:
    print("🟡 电量偏低，建议充值")
else:
    print("🟢 电量充足")
```

### 电费充值

!!! danger "支付密码安全"
    支付密码是敏感信息，请确保代码中不要硬编码，建议从环境变量或安全配置中读取。

```python title="电费充值"
import os

# 从环境变量获取支付密码（推荐）
payment_password = os.getenv("ECARD_PAYMENT_PASSWORD")

# 为默认宿舍充值50元电费
try:
    default_room = ecard.get_default_room()
    ecard.recharge_energy(
        payment_password=payment_password,
        amt=50,  # 充值金额（元）
        room=default_room
    )
    print("✅ 电费充值成功")
    
    # 查询充值后的电量
    new_energy = ecard.get_remaining_energy()
    print(f"充值后剩余电量: {new_energy} 度")
    
except Exception as e:
    print(f"❌ 充值失败: {e}")
```

### 批量充值

```python title="多房间批量充值"
# 定义多个房间
rooms = [
    "99-12--33-404",
    "99-12--33-405",
    "99-12--33-406"
]

payment_password = os.getenv("ECARD_PAYMENT_PASSWORD")

for room in rooms:
    try:
        # 先查询电量
        energy = ecard.get_remaining_energy(room=room)
        print(f"房间 {room} 当前电量: {energy} 度")
        
        # 电量低于20度时自动充值
        if energy < 20:
            ecard.recharge_energy(
                payment_password=payment_password,
                amt=30,  # 充值30元
                room=room
            )
            print(f"✅ 房间 {room} 充值成功")
        else:
            print(f"⏭️ 房间 {room} 电量充足，跳过充值")
            
    except Exception as e:
        print(f"❌ 房间 {room} 操作失败: {e}")
```

## 房间管理 {#room-management}

### 获取默认房间

```python title="默认房间管理"
# 获取账户默认房间
default_room = ecard.get_default_room()
print(f"默认房间: {default_room}")

# 解析房间信息
def parse_room_id(room_id: str) -> dict:
    """解析房间ID格式"""
    try:
        area_building, unit_room = room_id.split("--")
        area, building = area_building.split("-")
        unit, room = unit_room.split("-")
        
        return {
            "area": area,
            "building": building, 
            "unit": unit,
            "room": room,
            "full_id": room_id
        }
    except ValueError:
        return {"error": "房间ID格式不正确"}

room_info = parse_room_id(default_room)
print(f"区域: {room_info['area']}")
print(f"建筑: {room_info['building']}")  
print(f"单元: {room_info['unit']}")
print(f"房间: {room_info['room']}")
```

### 房间信息查询

```python title="房间信息获取"
# 获取区域列表（顶级）
areas = ecard.get_room_dict("")
print("可用区域:")
for area_id, area_name in areas.items():
    print(f"  {area_id}: {area_name}")

# 获取指定区域的建筑列表
area_id = "99"  # 假设选择区域99
buildings = ecard.get_room_dict(area_id)
print(f"\n区域 {area_id} 的建筑:")
for building_id, building_name in buildings.items():
    print(f"  {building_id}: {building_name}")

# 获取指定建筑的单元列表
building_id = f"{area_id}-12"
units = ecard.get_room_dict(building_id)
print(f"\n建筑 {building_id} 的单元:")
for unit_id, unit_name in units.items():
    print(f"  {unit_id}: {unit_name}")

# 获取指定单元的房间列表
unit_id = f"{building_id}--33"
rooms = ecard.get_room_dict(unit_id)
print(f"\n单元 {unit_id} 的房间:")
for room_id, room_name in rooms.items():
    print(f"  {room_id}: {room_name}")
```



## 异步支持 {#async-support}

所有功能都提供异步版本，位于 [`zzupy.app.ecard`][zzupy.aio.app.ecard] 模块：

## 错误处理 {#error-handling}

详见[`zzupy.app.ecard`][zzupy.app.ecard]

## 注意事项 {#notes}

!!! warning "重要提醒"
    
    1. **认证依赖**: ECardClient 需要已登录的 CASClient 实例
    2. **支付密码安全**: 支付密码是敏感信息，请妥善保管，不要硬编码
    3. **Token 刷新**: 系统会自动每45分钟刷新一次Token，无需手动处理
    4. **充值限制**: 单次充值金额必须大于0，建议不要过于频繁充值
    5. **房间格式**: 房间ID格式为 `areaid-buildingid--unitid-roomid`
    6. **网络环境**: 需要能够访问校园网或具备相应的网络访问权限

## 常见问题 {#faq}

??? question "如何获取正确的房间ID？"
    
    使用 `get_room_dict()` 方法逐级获取：
    
    ```python
    # 1. 获取区域列表
    areas = ecard.get_room_dict("")
    
    # 2. 选择区域，获取建筑列表
    buildings = ecard.get_room_dict("99")
    
    # 3. 选择建筑，获取单元列表  
    units = ecard.get_room_dict("99-12")
    
    # 4. 选择单元，获取房间列表
    rooms = ecard.get_room_dict("99-12--33")
    
    # 最终房间ID格式: 99-12--33-404
    ```
