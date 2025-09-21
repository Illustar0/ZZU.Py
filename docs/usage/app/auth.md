# 统一认证系统

统一认证系统（CAS）是郑州大学所有线上系统的基础认证服务，提供了统一的身份验证和授权机制。

!!! info "认证方案说明"
    郑州大学的统一认证在 Web 端和移动端使用了完全不同的认证方案：
    
    - **Web 端**: 使用高度魔改的 CAS 系统
    - **移动端**: 使用基于 JWT 的认证方案

## 模块概述 {#overview}

`zzupy.app.auth` 模块提供以下核心功能：

- **JWT 认证** - 基于 RS512 算法的 JSON Web Token 认证
- **Token 管理** - userToken 和 refreshToken 的自动管理
- **RSA 加密** - 账号密码的安全传输加密
- **自动续期** - Token 有效性验证和自动刷新
- **会话管理** - 登录状态维护和安全登出

## 快速开始 {#quick-start}

### 账密登录 {#password-login}

!!! warning "设备限制"
    账密登录会将豫见郑大 App 踢下线。推荐使用 [Token 认证方式](#token-auth) 避免冲突。

```python title="基础账密登录"
from zzupy.app import CASClient

# 创建认证客户端
cas = CASClient("your_account", "your_password")

# 执行登录
cas.login()

# 检查登录状态
if cas.logged_in:
    print("登录成功!")
    print(f"userToken: {cas.user_token}")
    print(f"refreshToken: {cas.refresh_token}")
else:
    print("登录失败")
```

### Token 认证方式 {#token-auth}

!!! success "推荐方式"
    使用已有 Token 可以避免重复登录，不会影响手机端 App 的使用。

在实际使用中，往往建议对 Token 进行[持久化保存](#token-persistence)。

```python title="Token 认证登录"
from zzupy.app import CASClient

# 使用已有 Token（推荐）
cas = CASClient("your_account", "your_password")
cas.set_token("your_user_token", "your_refresh_token")
cas.login()  # 自动验证 Token 有效性

print(f"登录状态: {cas.logged_in}")
```

### 获取 Token {#get-token}

=== "方法一：账密登录获取"

    ```python
    # 首次账密登录
    cas = CASClient("your_account", "your_password")
    cas.login()
    
    # 保存 Token 以备后用
    user_token = cas.user_token
    refresh_token = cas.refresh_token
    
    print(f"userToken: {user_token}")
    print(f"refreshToken: {refresh_token}")
    ```

=== "方法二：App 抓包获取"

    通过对豫见郑大 App 进行网络抓包获取 Token：
    
    1. 使用抓包工具（如 Charles、Burp Suite）
    2. 抓取 App 的认证请求
    3. 从响应中提取 `userToken` 和 `refreshToken`

## Token 管理 {#token-management}

### Token 类型说明 {#token-types}

- **userToken**: 主要使用的 Token，约 1 个月有效期
- **refreshToken**: 用于刷新 userToken 的 Token，2 个月有效期，但由于 userToken 有效期实在太长，目前没能观察到刷新逻辑，故只能使用账密登录刷新。

### Token 有效性管理 {#token-validation}

```python title="Token 有效性检查"
from zzupy.app import CASClient

cas = CASClient("account", "password")
cas.set_token("old_user_token", "old_refresh_token")
    
# login() 会自动验证 Token 有效性，有效则跳过账密登录，无效则调用账密登录并刷新 Token
cas.login()
```

### Token 持久化 {#token-persistence}

只是一个简单的 Claude 生成的例子。生产环境中还是建议加密保存。

```python title="Token 持久化存储"
import json
import os
from pathlib import Path

class TokenManager:
    def __init__(self, token_file="tokens.json"):
        self.token_file = Path(token_file)
    
    def save_tokens(self, user_token: str, refresh_token: str):
        """保存 Token 到文件"""
        tokens = {
            "user_token": user_token,
            "refresh_token": refresh_token
        }
        
        with open(self.token_file, 'w') as f:
            json.dump(tokens, f, indent=2)
    
    def load_tokens(self) -> tuple[str, str] | None:
        """从文件加载 Token"""
        if not self.token_file.exists():
            return None
            
        try:
            with open(self.token_file, 'r') as f:
                tokens = json.load(f)
            return tokens.get("user_token"), tokens.get("refresh_token")
        except (json.JSONDecodeError, KeyError):
            return None
    
    def clear_tokens(self):
        """清除保存的 Token"""
        if self.token_file.exists():
            os.remove(self.token_file)

# 使用示例
token_manager = TokenManager()

# 尝试加载已保存的 Token
saved_tokens = token_manager.load_tokens()

cas = CASClient("your_account", "your_password")

if saved_tokens:
    user_token, refresh_token = saved_tokens
    cas.set_token(user_token, refresh_token)

cas.login()

if cas.logged_in:
    # 保存最新的 Token
    token_manager.save_tokens(cas.user_token, cas.refresh_token)
    print("Token 已更新并保存")
```


## 异步支持 {#async-support}

所有认证功能都提供异步版本，位于 [`zzupy.aio.app.auth`][zzupy.aio.app.auth] 模块：


## 错误处理 {#error-handling}

详见[`zzupy.app.auth`][zzupy.app.auth]

## 注意事项 {#notes}

!!! warning "重要提醒"
    
    1. **设备限制**: 账密登录会导致豫见郑大 App 被踢下线
    2. **Token 安全**: userToken 和 refreshToken 请妥善保管，不要泄露
    3. **网络环境**: 需要能够访问校园网或具备相应的网络访问权限
    4. **Token 有效期**: userToken ~30天，refreshToken ~60天
    5. **频率限制**: 避免过于频繁的登录请求，可能被服务器限制

## 常见问题 {#faq}

??? question "为什么推荐使用 Token 认证？"
    
    Token 认证有以下优势：
    
    - **避免冲突**: 不会将手机端 App 踢下线
    - **安全性**: 避免频繁传输账号密码
    - **效率**: 跳过 RSA 加密和 JWT 验证过程
    - **稳定性**: 减少网络请求，提高可靠性

??? question "Token 过期了怎么办？"
    
    CASClient 会自动处理 Token 过期：
    
    ```python
    cas = CASClient("account", "password")
    cas.set_token("expired_token", "expired_refresh_token")
    
    # login() 会自动检测 Token 有效性
    cas.login()  # 如果 Token 过期，会自动执行账密登录
    
    # 获取新的 Token
    new_user_token = cas.user_token
    new_refresh_token = cas.refresh_token
    ```

??? question "如何获取豫见郑大 App 的 Token？"
    
    两种方法：
    
    1. **抓包获取**: 使用网络抓包工具监控 App 的认证请求
    2. **代码获取**: 首次使用账密登录，然后保存返回的 Token
    
    ```python
    # 方法2示例
    cas = CASClient("account", "password")
    cas.login()
    
    print(f"保存这些 Token 以备后用:")
    print(f"userToken: {cas.user_token}")
    print(f"refreshToken: {cas.refresh_token}")
    ```

??? question "登录失败的常见原因？"
    
    可能的原因和解决方案：
    
    - **账号密码错误**: 检查账号密码是否正确
    - **网络连接问题**: 确保能访问 `cas.s.zzu.edu.cn`
    - **账户被锁定**: 联系学校信息化办公室
    - **Token 无效**: 重新获取有效的 Token
    - **服务器维护**: 等待服务恢复正常
