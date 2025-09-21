# 校园网络服务

校园网络服务模块提供了郑州大学校园网认证、设备管理和流量查询等功能。支持 Portal 认证和自助服务系统的各种操作。

## 模块概述 {#overview}

`zzupy.web.network` 模块包含以下主要功能：

- **Portal 认证** - 校园网自动认证登录
- **Portal 信息发现** - 自动检测校园网认证配置
- **设备管理** - 查看在线设备、踢设备下线
- **自助服务系统** - 校园网账户管理

## Portal 认证 {#portal-auth}

### 基础使用 {#basic-usage}

!!! warning "地址说明"
    此处的 `http://172.16.2.9:801` 仅由松园与菊园使用，且随时可能更改。
    
    **推荐使用[自动发现 Portal 配置](#discover-portal)方式，无需手动配置地址。**

```python
from zzupy.web import EPortalClient

# 使用默认配置
with EPortalClient("http://172.16.2.9:801") as client:
    result = client.auth("your_account", "your_password")
    if result.success:
        print(f"认证成功: {result.message}")
    else:
        print(f"认证失败: {result.message}")
```

### 自动发现 Portal 配置 {#discover-portal}

!!! success "推荐方式"
    这是推荐的认证方式，可以自动检测校园网配置，无需手动指定服务器地址。

```python title="自动发现并认证"
from zzupy.web import discover_portal_info, EPortalClient
from zzupy.exception import NetworkError, ParsingError

try:
    # 自动发现校园网配置
    portal_info = discover_portal_info()
    print(f"发现 Portal 服务器: {portal_info.portal_server_url}")
    print(f"用户IP: {portal_info.user_ip}")
    
    # 使用发现的配置进行认证
    with EPortalClient(portal_info.portal_server_url, bind_address=portal_info.user_ip) as client:
        result = client.auth("your_account", "your_password")
        print(result.message)
        
except NetworkError as e:
    print(f"网络错误: {e}")
except ParsingError as e:
    print(f"解析错误: {e}")
```

### 高级配置 {#advanced-config}

#### IP 地址绑定 {#ip-binding}

!!! info "适用场景"
    当你需要指定特定的本地IP地址进行认证时使用。

```python title="手动IP绑定"
# 手动指定绑定IP
with EPortalClient(
    "http://172.16.2.9",
    bind_address="192.168.1.100"
) as client:
    result = client.auth("your_account", "your_password")
```

#### 强制绑定模式 {#force-bind}

!!! warning "路由器环境"
    在路由器后使用时，本地IP可能无法直接绑定。启用 `force_bind=True` 可以强制使用指定IP。

```python title="强制绑定模式"
# 路由器环境下使用强制绑定
portal_info = discover_portal_info()
with EPortalClient(
    "http://172.16.2.9",
    bind_address=portal_info.user_ip,
    force_bind=True
) as client:
    result = client.auth("your_account", "your_password")
```

#### 切换运营商 {#isp-suffix}

=== "校园网"

    ```python
    with EPortalClient("http://172.16.2.9:801") as client:
        result = client.auth("your_account", "your_password")
    ```

=== "移动融合宽带"

    ```python
    with EPortalClient("http://172.16.2.9:801") as client:
        result = client.auth("your_account", "your_password", isp_suffix="@cmcc")
    ```

=== "联通融合宽带"

    ```python
    with EPortalClient("http://172.16.2.9:801") as client:
        result = client.auth("your_account", "your_password", isp_suffix="@unicom")
    ```

=== "电信融合宽带"

    ```python
    with EPortalClient("http://172.16.2.9:801") as client:
        result = client.auth("your_account", "your_password", isp_suffix="@telecom")
    ```

#### 加密认证 {#encryption}

!!! danger "高级功能"
    如果你不知道这是什么，请不要启用它。  
    目前校园网 Portal 认证并未启用加密。

```python title="加密认证" hl_lines="3"
# 启用加密传输
with EPortalClient("http://172.16.2.9:801") as client:
    result = client.auth("your_account", "your_password", encrypt=True)
```

## 自助服务系统 {#self-service}

自助服务系统提供设备管理功能，可以查看当前在线设备并管理连接。

!!! note "服务地址"
    自助服务系统的默认地址为 `http://10.2.7.16:8080`

### 登录和设备查询 {#device-query}

```python title="设备查询示例"
from zzupy.web import SelfServiceSystem

# 连接自助服务系统
with SelfServiceSystem("http://10.2.7.16:8080") as system:
    # 登录
    system.login("your_account", "your_password")
    
    # 获取在线设备列表
    devices = system.get_online_devices()
    
    for device in devices:
        print(f"设备IP: {device.ip}")
        print(f"MAC地址: {device.mac}")
        print(f"登录时间: {device.loginTime}")
        print(f"上行流量: {device.upFlow}")
        print(f"下行流量: {device.downFlow}")
        print(f"使用时长: {device.useTime}秒")
        print("---")
```

### 设备管理 {#device-management}

```python title="踢设备下线"
with SelfServiceSystem("http://10.2.7.16:8080") as system:
    system.login("your_account", "your_password")
    
    # 获取设备列表
    devices = system.get_online_devices()
    
    # 踢除指定设备
    if devices:
        target_device = devices[0]  # 选择第一个设备
        system.kick_device(target_device.sessionId)
        print(f"已踢除设备: {target_device.ip}")
```

## 数据模型 {#data-models}

以下是网络模块中使用的主要数据模型：

### AuthResult {#auth-result}

Portal 认证结果模型：

```python
class AuthResult:
    result: int          # 认证结果代码
    message: str         # 服务器返回消息
    ret_code: int | None # 额外返回码
    
    @property
    def success(self) -> bool:
        return self.result == 1
```

### PortalInfo {#portal-info}

Portal 配置信息模型：

[:octicons-link-external-24: PortalInfo 完整文档][zzupy.models.PortalInfo]
```python
class PortalInfo:
    auth_url: str           # 认证网页URL
    portal_server_url: str  # Portal服务器URL
    user_ip: str           # 客户端IP地址
```

### OnlineDevice {#online-device}

在线设备信息模型：

[:octicons-link-external-24: OnlineDevice 完整文档][zzupy.models.OnlineDevice]
```python
class OnlineDevice:
    brasid: str         # BRAS ID
    downFlow: str       # 下行流量
    hostName: str       # 主机名
    ip: str            # IP地址
    loginTime: str     # 登录时间
    mac: str           # MAC地址
    sessionId: str     # 会话ID
    terminalType: str  # 终端类型
    upFlow: str        # 上行流量
    useTime: str       # 使用时长（秒）
    userId: int        # 用户ID
```

## 异步支持 {#async-support}

所有网络功能都提供异步版本，位于 [:octicons-link-external-24: `zzupy.aio.web.network`][zzupy.aio.web.network] 模块：

```python title="异步认证示例"
from zzupy.aio.web import EPortalClient, SelfServiceSystem

# 异步 Portal 认证
async with EPortalClient("http://172.16.2.9") as client:
    result = await client.auth("your_account", "your_password")
    print(result.message)

# 异步设备管理
async with SelfServiceSystem("http://172.16.2.9") as system:
    await system.login("your_account", "your_password")
    devices = await system.get_online_devices()
    print(f"在线设备数量: {len(devices)}")
```

## 错误处理 {#error-handling}

详见 [:octicons-link-external-24: `zzupy.web.network`][zzupy.web.network]


## 注意事项 {#notes}

!!! warning "重要提醒"
    
    1. **网络环境**: Portal 认证需要在校园网环境下进行
    2. **IP 绑定**: 在路由器环境下可能需要使用 `force_bind=True`
    3. **认证频率**: 避免频繁认证请求，可能会被服务器限制
    4. **设备限制**: 校园网通常限制 3-5 台终端同时在线
    5. **异常处理**: 建议对所有网络操作进行适当的异常处理

## 常见问题 {#faq}

??? question "认证时提示 '未被 MITM，请检查校园网是否已认证'"
    
    这表示当前网络已经通过认证，无需重复认证。

??? question "如何在路由器环境下使用？"
    
    设置 `bind_address` 为路由器分配的内网IP，并启用 `force_bind=True`。
    
    ```python
    portal_info = discover_portal_info()
    with EPortalClient(
        portal_info.portal_server_url,
        bind_address=portal_info.user_ip,
        force_bind=True
    ) as client:
        result = client.auth("account", "password")
    ```

??? question "Portal 信息发现失败怎么办？"
    
    这说明学校又改了什么东西。  
    发 Issue 并贴上 Debug 日志。
    

??? question "设备管理功能无法使用？"
    
    不同区域的自助服务系统的地址不一定一致。
    确保使用正确的自助服务系统地址，并且账户密码正确。  
    
