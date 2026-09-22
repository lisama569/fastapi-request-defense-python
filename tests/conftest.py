"""pytest 全局夹具：单测日志中打印输入摘要与判定依据。"""

from __future__ import annotations

import logging
import sys

import pytest


@pytest.fixture(scope="session", autouse=True)
def _configure_audit_logging():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root = logging.getLogger("request_defense")
    root.setLevel(logging.DEBUG)
    root.handlers = [handler]
    root.propagate = False
    yield


@pytest.fixture(autouse=True)
def _case_banner(request):
    # 每个用例前打印标题，方便从日志关联输入与判定依据
    logging.getLogger("request_defense").info("==== TEST CASE: %s ====", request.node.name)
    yield
