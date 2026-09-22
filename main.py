"""服务入口：uvicorn main:app。"""

from request_defense.app import app

__all__ = ["app"]
