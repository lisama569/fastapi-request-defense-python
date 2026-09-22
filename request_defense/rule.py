"""单条请求特征规则：编译与求值。

规则模型：对请求的某个特征字段做正则匹配（``re.search`` 语义），
命中后按 ``effect`` 给出 MATCH_ALLOW / MATCH_DENY，未命中为 NO_MATCH。

支持的 field_name：
  - source / path / method / body
  - header:<名称>      （缺失视为空串）
  - query:<名称>       （缺失视为空串）

规则本身保持无状态，求值所需上下文全部来自 RequestFeatures，
因此规则求值异常不会污染共享状态。
"""

from __future__ import annotations

import re
from typing import Final

from .types import RequestFeatures, RuleConfig, RuleEffect, RuleVerdict


class RuleDefinitionError(ValueError):
    """非法规则定义（规则集校验阶段抛出，触发整集拒绝）。"""


_DIRECT_FIELDS: Final[frozenset[str]] = frozenset(
    {"source", "path", "method", "body"}
)
_MAX_PATTERN_LEN: Final[int] = 2048
_MAX_HEADER_NAME_LEN: Final[int] = 128


class Rule:
    """可执行的特征规则（不可变、无状态、可被多线程并发求值）。"""

    __slots__ = ("config", "_compiled", "_field_kind", "_field_key")

    def __init__(self, config: RuleConfig) -> None:
        self.config = config
        kind, key = self._parse_field_name(config.field_name)
        self._field_kind = kind
        self._field_key = key
        pattern = config.pattern
        try:
            self._compiled = re.compile(pattern)
        except re.error as exc:
            raise RuleDefinitionError(
                f"rule {config.rule_id!r}: invalid regex: {exc}"
            ) from exc

    @staticmethod
    def _parse_field_name(field_name: str) -> tuple[str, str]:
        if field_name in _DIRECT_FIELDS:
            return field_name, ""
        if field_name.startswith("header:"):
            key = field_name[len("header:") :].strip().lower()
            if not key or len(key) > _MAX_HEADER_NAME_LEN:
                raise RuleDefinitionError(f"invalid header field: {field_name!r}")
            return "header", key
        if field_name.startswith("query:"):
            key = field_name[len("query:") :].strip()
            if not key or len(key) > _MAX_HEADER_NAME_LEN:
                raise RuleDefinitionError(f"invalid query field: {field_name!r}")
            return "query", key
        raise RuleDefinitionError(f"unknown field: {field_name!r}")

    @classmethod
    def compile(cls, config: RuleConfig) -> "Rule":
        """编译并校验规则；非法时抛 RuleDefinitionError。"""
        if not isinstance(config, RuleConfig):
            raise RuleDefinitionError("rule config must be RuleConfig")
        if not config.rule_id or not config.rule_id.strip():
            raise RuleDefinitionError("rule_id must be non-empty")
        if len(config.rule_id) > 128:
            raise RuleDefinitionError("rule_id too long")
        if not isinstance(config.priority, int) or config.priority < 0:
            raise RuleDefinitionError(
                f"rule {config.rule_id!r}: priority must be non-negative int"
            )
        if not isinstance(config.effect, RuleEffect):
            raise RuleDefinitionError(
                f"rule {config.rule_id!r}: invalid effect"
            )
        if not config.pattern:
            raise RuleDefinitionError(
                f"rule {config.rule_id!r}: pattern must be non-empty"
            )
        if len(config.pattern) > _MAX_PATTERN_LEN:
            raise RuleDefinitionError(
                f"rule {config.rule_id!r}: pattern too long"
            )
        return cls(config)

    def _extract(self, features: RequestFeatures) -> str:
        kind = self._field_kind
        if kind == "source":
            return features.source
        if kind == "path":
            return features.path
        if kind == "method":
            return features.method
        if kind == "body":
            return features.body_summary
        if kind == "header":
            return features.headers.get(self._field_key, "")
        if kind == "query":
            return features.query.get(self._field_key, "")
        # 编译期已保证不会走到这里
        raise RuleDefinitionError(f"unsupported field kind: {kind}")

    def evaluate(self, features: RequestFeatures) -> RuleVerdict:
        """对请求特征求值。

        正常返回 MATCH_ALLOW / MATCH_DENY / NO_MATCH；
        若自定义规则实现抛出异常，由引擎统一归类，不在此吞掉。
        """
        value = self._extract(features)
        if self._compiled.search(value) is not None:
            return (
                RuleVerdict.MATCH_DENY
                if self.config.effect is RuleEffect.DENY
                else RuleVerdict.MATCH_ALLOW
            )
        return RuleVerdict.NO_MATCH
