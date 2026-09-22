"""管理接口身份校验。

- 仅接受 ``Authorization: Bearer <token>``；空、格式错误、凭据错误一律拒绝；
- 使用 :func:`hmac.compare_digest` 做常数时间比较，降低计时侧信道；
- 本模块不记录任何请求凭据；对外错误信息统一为 "unauthorized"，
  不泄漏规则版本、规则数量等内部状态。
"""

from __future__ import annotations

import hmac

from app.audit import mask_secret


class AdminAuthenticator:
    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("admin token must not be empty")
        self._token = token

    def authenticate(self, authorization_header: str | None) -> bool:
        if not authorization_header:
            return False
        parts = authorization_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False
        provided = parts[1].strip()
        if not provided:
            return False
        return hmac.compare_digest(provided, self._token)

    def redacted(self, authorization_header: str | None) -> str:
        """供日志使用：凭据存在与否可见，值一律掩码。"""
        if not authorization_header:
            return "<none>"
        return f"bearer:{mask_secret('x') if authorization_header else ''}"
