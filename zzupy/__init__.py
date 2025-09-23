from loguru import logger

from . import aio
from . import app
from . import web
from . import exception

logger.disable(__name__)

__version__ = "6.0.0-rc.6"
__all__ = ["aio", "app", "web", "exception"]
