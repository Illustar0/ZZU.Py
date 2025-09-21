"""Web API 客户端模块"""

from .network import EPortalClient, SelfServiceSystem, discover_portal_info

__all__ = [
    "EPortalClient",
    "SelfServiceSystem",
    "discover_portal_info",
]
