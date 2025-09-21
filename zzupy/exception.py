"""异常处理模块"""


class ZZUError(Exception):
    """基类异常"""

    pass


class NetworkError(ZZUError):
    """网络出错"""

    pass


class LoginError(ZZUError):
    """登录失败"""

    pass


class ParsingError(ZZUError):
    """数据解析失败"""

    pass


class NotLoggedInError(ZZUError):
    """未登录"""

    pass


class AuthenticationError(ZZUError):
    """认证失败"""

    pass


class OperationError(ZZUError):
    """操作失败"""

    pass
