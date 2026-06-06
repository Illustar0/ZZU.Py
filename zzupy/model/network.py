import json
import warnings
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


def _warn_deprecated_alias(old_name: str, new_name: str) -> None:
    warnings.warn(
        f"{old_name} 已弃用，请使用 {new_name}",
        DeprecationWarning,
        stacklevel=3,
    )


class OnlineDevice(BaseModel):
    """在线设备信息"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    brasid: str
    """BRAS ID"""
    down_flow: str
    """下行流量"""
    host_name: str = ""
    """主机名"""
    ip: str
    """IP地址"""
    login_time: str
    """登录时间，格式为YYYY-MM-DD HH:MM:SS"""
    mac: str
    """MAC地址"""
    session_id: str
    """会话ID"""
    terminal_type: str
    """终端类型"""
    up_flow: str
    """上行流量"""
    use_time: str
    """使用时间（秒）"""
    user_id: int
    """用户ID"""

    @property
    def downFlow(self) -> str:
        _warn_deprecated_alias("OnlineDevice.downFlow", "down_flow")
        return self.down_flow

    @property
    def hostName(self) -> str:
        _warn_deprecated_alias("OnlineDevice.hostName", "host_name")
        return self.host_name

    @property
    def loginTime(self) -> str:
        _warn_deprecated_alias("OnlineDevice.loginTime", "login_time")
        return self.login_time

    @property
    def sessionId(self) -> str:
        _warn_deprecated_alias("OnlineDevice.sessionId", "session_id")
        return self.session_id

    @property
    def terminalType(self) -> str:
        _warn_deprecated_alias("OnlineDevice.terminalType", "terminal_type")
        return self.terminal_type

    @property
    def upFlow(self) -> str:
        _warn_deprecated_alias("OnlineDevice.upFlow", "up_flow")
        return self.up_flow

    @property
    def useTime(self) -> str:
        _warn_deprecated_alias("OnlineDevice.useTime", "use_time")
        return self.use_time

    @property
    def userId(self) -> int:
        _warn_deprecated_alias("OnlineDevice.userId", "user_id")
        return self.user_id

    def dump_json(self, indent: Optional[int] = None) -> str:
        """格式化为JSON字符串"""
        return json.dumps(self.model_dump(), ensure_ascii=False, indent=indent)


class AuthResult(BaseModel):
    """Portal 认证结果"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    result: int
    """认证结果"""
    message: str = Field(..., alias="msg")
    """Portal 服务器返回信息"""
    ret_code: int | None = None  # 不知道是个啥

    @property
    def success(self) -> bool:
        return self.result == 1


class PortalInfo(BaseModel):
    """探测出的 Portal 认证信息"""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    auth_url: str
    """认证网页 URL"""
    portal_server_url: str
    """Portal 服务器 URL"""
    user_ip: str
    """客户端 IP"""
