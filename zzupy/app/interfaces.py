from abc import ABC, abstractmethod


class ICASClient(ABC):
    @abstractmethod
    def __init__(
        self,
        user_token: str | None = None,
        refresh_token: str | None = None,
    ) -> None:
        pass

    @abstractmethod
    def login(self, account: str, password: str) -> None:
        pass

    @abstractmethod
    @property
    def user_token(self) -> str | None:
        pass

    @abstractmethod
    @property
    def refresh_token(self) -> str | None:
        pass
