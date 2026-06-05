"""zzupy 日志工具。"""

import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx2

from loguru import logger as _logger

logger = _logger

_REDACTED = "[REDACTED]"
_MAX_BODY_LENGTH = 2048
_DEFAULT_HANDLER_ID = 0
_TEXT_CONTENT_TYPES = (
    "application/json",
    "application/x-www-form-urlencoded",
    "application/xml",
    "application/javascript",
    "text/",
)
_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "accesstoken",
        "authorization",
        "clientid",
        "cookie",
        "deviceid",
        "password",
        "refresh_token",
        "refreshtoken",
        "set-cookie",
        "token",
        "user_token",
        "usertoken",
        "username",
    }
)


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace("_", "").replace("-", "")


def _is_sensitive_key(key: str) -> bool:
    return _normalize_key(key) in _SENSITIVE_KEYS


def _truncate_text(text: str, limit: int = _MAX_BODY_LENGTH) -> str:
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... (truncated, total={len(text)})"


def _sanitize_value(key: str | None, value: Any) -> Any:
    if key is not None and _is_sensitive_key(key):
        return _REDACTED

    if isinstance(value, dict):
        return {k: _sanitize_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(key, item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_value(key, item) for item in value)
    return value


def sanitize_http_headers(headers: httpx2.Headers) -> dict[str, str]:
    """脱敏并标准化 HTTP 头，便于安全输出到日志。"""
    return {
        key: _REDACTED if _is_sensitive_key(key) else value
        for key, value in headers.items()
    }


def sanitize_http_url(url: str | httpx2.URL) -> str:
    """脱敏 URL 查询参数。"""
    parsed = urlsplit(str(url))
    if not parsed.query:
        return str(url)

    sanitized_query = urlencode(
        [
            (key, _REDACTED if _is_sensitive_key(key) else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ],
        doseq=True,
    )
    return urlunsplit(parsed._replace(query=sanitized_query))


def sanitize_http_body(
    body: bytes | str | None,
    *,
    content_type: str | None = None,
    limit: int = _MAX_BODY_LENGTH,
) -> str:
    """按内容类型对 HTTP Body 做脱敏与截断。"""
    if body in (None, b"", ""):
        return ""

    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return "(binary)"
    else:
        text = body

    stripped = text.strip()
    normalized_type = (content_type or "").split(";", 1)[0].strip().lower()

    if normalized_type == "application/x-www-form-urlencoded":
        sanitized_form = urlencode(
            [
                (key, _REDACTED if _is_sensitive_key(key) else value)
                for key, value in parse_qsl(text, keep_blank_values=True)
            ],
            doseq=True,
        )
        return _truncate_text(sanitized_form, limit)

    if normalized_type == "application/json" or stripped.startswith(("{", "[")):
        try:
            return _truncate_text(
                json.dumps(
                    _sanitize_value(None, json.loads(text)),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                limit,
            )
        except json.JSONDecodeError:
            pass

    if normalized_type and not any(
        normalized_type.startswith(prefix) for prefix in _TEXT_CONTENT_TYPES
    ):
        return "(binary)"

    return _truncate_text(text, limit)


def log_http_headers(
    message: str,
    headers: httpx2.Headers,
    *,
    level: str = "TRACE",
) -> None:
    """输出脱敏后的 HTTP 头日志。"""
    logger.log(level.upper(), "{}: {}", message, sanitize_http_headers(headers))


def log_http_response_body(
    url: str | httpx2.URL,
    text: str,
    *,
    content_type: str | None = None,
    level: str = "TRACE",
) -> None:
    """输出脱敏后的 HTTP 响应体日志。"""
    logger.log(
        level.upper(),
        "{} 请求响应体: {}",
        sanitize_http_url(url),
        sanitize_http_body(text, content_type=content_type),
    )


def build_http_event_hooks(*, async_client: bool = False) -> dict[str, list[Any]]:
    """创建带脱敏能力的 HTTP 请求/响应日志钩子。"""

    def log_request(request: httpx2.Request) -> None:
        sanitized_url = sanitize_http_url(request.url)
        logger.trace(">>> {} {}", request.method, sanitized_url)
        log_http_headers(">>> Headers", request.headers)

        body = sanitize_http_body(
            request.content,
            content_type=request.headers.get("content-type"),
        )
        if body:
            logger.trace(">>> Body: {}", body)

    def log_response(response: httpx2.Response) -> None:
        request = response.request
        sanitized_url = sanitize_http_url(request.url)
        logger.trace(
            "<<< {} {} {}", response.status_code, request.method, sanitized_url
        )
        log_http_headers("<<< Headers", response.headers)

    if async_client:

        async def async_request_logger(request: httpx2.Request) -> None:
            log_request(request)

        async def async_response_logger(response: httpx2.Response) -> None:
            log_response(response)

        return {
            "request": [async_request_logger],
            "response": [async_response_logger],
        }

    return {
        "request": [log_request],
        "response": [log_response],
    }
