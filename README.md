# fastapi-request-defense

在 FastAPI 服务前的本地请求防护层：按来源滑动窗口限流 + 多规则特征组合判定
+ 判定审计，支持规则集运行时原子变更、规则故障隔离与有界降级、管理端鉴权。

## 快速开始

```bash
uv sync
uv run uvicorn main:app --reload
```

- 业务入口（`/`、`/ingest` 等）统一经过防护中间件；
- `GET /healthz` 免防护；`/admin/*` 需 Bearer 鉴权。

## 运行测试

```bash
uv run pytest          # 48 个测试：并发冲击 / 异常规则 / 非法规则集 / 鉴权脱敏
```

## 文档

详见 [docs/request-defense.md](docs/request-defense.md)：限流语义、规则模型、
降级策略、管理接口与验证方法。

## 关键配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `DEFENSE_RATE_LIMIT` | 10 | 每来源每窗口配额 |
| `DEFENSE_WINDOW_SECONDS` | 1.0 | 窗口秒数 |
| `DEFENSE_MAX_RULES` | 100 | 单请求规则数量上限 |
| `DEFENSE_BUDGET_MS` | 50.0 | 单请求规则求值耗时上限（毫秒） |
| `DEFENSE_ON_RULE_ERROR` | fail_closed | 规则故障降级：fail_closed / fail_open |
| `DEFENSE_ADMIN_TOKEN` | dev-only-admin-token | 管理令牌（生产必须覆盖） |
