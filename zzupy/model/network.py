import json
from typing import Optional

from pydantic import BaseModel, Field


class OnlineDevice(BaseModel):
    """在线设备信息"""

    brasid: str
    """BRAS ID"""
    downFlow: str
    """下行流量"""
    hostName: str = ""
    """主机名"""
    ip: str
    """IP地址"""
    loginTime: str
    """登录时间，格式为YYYY-MM-DD HH:MM:SS"""
    mac: str
    """MAC地址"""
    sessionId: str
    """会话ID"""
    terminalType: str
    """终端类型"""
    upFlow: str
    """上行流量"""
    useTime: str
    """使用时间（秒）"""
    userId: int
    """用户ID"""

    def dump_json(self, indent: Optional[int] = None) -> str:
        """格式化为JSON字符串"""
        return json.dumps(self.model_dump(), ensure_ascii=False, indent=indent)


class AuthResult(BaseModel):
    """Portal 认证结果"""

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

    auth_url: str
    """认证网页 URL"""
    portal_server_url: str
    """Portal 服务器 URL"""
    user_ip: str
    """客户端 IP"""
