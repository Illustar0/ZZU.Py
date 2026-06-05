"""异常处理模块。"""

from __future__ import annotations

from typing import Any, Mapping, Self

import httpx2


class ZZUError(Exception):
    """项目异常基类。

    除了人类可读的错误消息外，还会保留额外上下文，便于调用方记录日志、
    序列化或调试。

    Args:
        message: 错误消息。
        context: 结构化上下文信息。
        error_code: 可选错误代码。
    """

    default_message = "发生未知错误"

    def __init__(
        self,
        message: str | None = None,
        *,
        context: Mapping[str, Any] | None = None,
        error_code: str | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.context = dict(context or {})
        self.error_code = error_code
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(message={self.message!r}, "
            f"error_code={self.error_code!r}, context={self.context!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        """将异常转换为便于日志记录或序列化的字典。"""
        data = {
            "type": self.__class__.__name__,
            "message": self.message,
            "context": self.context,
        }
        if self.error_code is not None:
            data["error_code"] = self.error_code
        if self.__cause__ is not None:
            data["cause"] = repr(self.__cause__)
        return data

    @classmethod
    def from_exception(
        cls,
        exc: Exception,
        message: str | None = None,
        *,
        context: Mapping[str, Any] | None = None,
        error_code: str | None = None,
    ) -> Self:
        """基于底层异常构造项目异常。"""
        merged_context = dict(context or {})
        merged_context.setdefault("cause_type", type(exc).__name__)
        return cls(message, context=merged_context, error_code=error_code)

    @classmethod
    def from_http_status(
        cls,
        exc: httpx2.HTTPStatusError,
        message: str | None = None,
        *,
        context: Mapping[str, Any] | None = None,
        error_code: str | None = None,
    ) -> Self:
        """基于 HTTP 状态错误构造项目异常。"""
        request = exc.request
        response = exc.response
        merged_context = dict(context or {})
        merged_context.setdefault("method", request.method)
        merged_context.setdefault("url", str(request.url))
        merged_context.setdefault("status_code", response.status_code)
        detail = message or cls.default_message
        return cls(
            f"{detail} {response.status_code}",
            context=merged_context,
            error_code=error_code,
        )


class ClientStateError(ZZUError, RuntimeError):
    """客户端状态错误。"""


class InvalidArgumentError(ZZUError, ValueError):
    """调用参数不合法。"""


class NetworkError(ZZUError):
    """网络请求失败或网络环境异常。"""

    default_message = "网络请求失败"


class LoginError(ZZUError):
    """登录失败。"""

    default_message = "登录失败"


class ParsingError(ZZUError):
    """响应解析或数据校验失败。"""

    default_message = "数据解析失败"


class NotLoggedInError(ClientStateError):
    """在未登录状态下调用了需要登录的方法。"""

    default_message = "需要登录"


class AuthenticationError(ClientStateError):
    """认证失败。"""

    default_message = "认证失败"


class OperationError(ZZUError):
    """服务端接受请求但业务处理失败。"""

    default_message = "操作失败"


class DataNotFoundError(OperationError, LookupError):
    """请求的数据不存在或当前上下文中无法找到。"""

    default_message = "请求的数据不存在"


class MFAError(LoginError):
    """MFA 状态错误，当前会话可能需要 MFA 验证"""

    default_message = "MFA 状态错误，当前会话可能需要 MFA 验证"


__all__ = [
    "AuthenticationError",
    "ClientStateError",
    "DataNotFoundError",
    "InvalidArgumentError",
    "LoginError",
    "NetworkError",
    "NotLoggedInError",
    "OperationError",
    "ParsingError",
    "ZZUError",
    "MFAError",
]
