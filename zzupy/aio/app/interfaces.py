"""抽象接口"""

from abc import ABC, abstractmethod


class ICASClient(ABC):
    @abstractmethod
    def __init__(self, account: str, password: str) -> None:
        pass

    @abstractmethod
    async def login(self, force_login: bool = False) -> None:
        pass

    @property
    @abstractmethod
    def user_token(self) -> str | None:
        pass

    @property
    @abstractmethod
    def refresh_token(self) -> str | None:
        pass

    @property
    @abstractmethod
    def logged_in(self) -> bool:
        pass
