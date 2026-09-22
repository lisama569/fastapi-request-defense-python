"""管理接口身份校验。

- 仅接受 ``Authorization: Bearer <token>``；
- 使用 ``hmac.compare_digest`` 做常量时间比较，避免计时侧信道；
- 失败统一抛 AuthError，对外只有 401 与固定错误体，不区分
  "令牌缺失/格式错误/令牌错误"，也不回显任何内部状态；
- 日志只能记录令牌的不可逆短摘要（``mask_token``）。
"""

from __future__ import annotations

import hashlib
import hmac


class AuthError(Exception):
    """未授权或凭据错误。统一对外，不区分细节。"""

    GENERIC_MESSAGE = "unauthorized"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mask_token(token: str) -> str:
    """令牌脱敏：只输出 sha256 前 8 位，永不输出完整凭据。"""
    if not token:
        return "<absent>"
    return f"sha256:{_digest(token)[:8]}"


def authenticate(authorization_header: str | None, expected_token: str) -> None:
    """校验 Bearer 令牌；任何异常/不匹配都抛 AuthError。"""
    if not expected_token:
        # 服务未配置管理令牌 => 管理能力一律关闭（fail-closed）
        raise AuthError(AuthError.GENERIC_MESSAGE)
    if not authorization_header:
        raise AuthError(AuthError.GENERIC_MESSAGE)
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        raise AuthError(AuthError.GENERIC_MESSAGE)
    presented = parts[1].strip()
    if not hmac.compare_digest(presented, expected_token):
        raise AuthError(AuthError.GENERIC_MESSAGE)
