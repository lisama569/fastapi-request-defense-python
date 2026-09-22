# 本地请求防护层（FastAPI Request Defense）

在现有 HTTP 服务前增加的一层**本地请求防护**，把三件事结合起来并给出一致、可解释的处置结论：

1. **来源限流** —— 按来源标识的滑动时间窗配额；
2. **请求特征规则** —— 多条规则组合判定（命中/未命中/冲突）；
3. **判定审计** —— 每次判定输出结论、原因、依据与输入摘要。

所有入口（除豁免的运维路径与管理路径外）都经过同一套中间件，因此正常、被限流、可疑流量的处置口径完全一致。

## 目录结构

```
request_defense/
  types.py         # Decision / Reason / RuleVerdict / RuleConfig / RequestFeatures 等核心类型
  ratelimiter.py   # 线程安全的滑动时间窗限流器
  rule.py          # 单条特征规则：编译（正则校验）与无状态求值
  store.py         # 规则集不可变快照 + 整体校验 + 原子替换（版本单调递增）
  engine.py        # 限流 + 规则组合判定 + 超时/异常隔离 + 资源上限
  auth.py          # 管理接口 Bearer 令牌校验（常量时间比较、fail-closed）
  audit.py         # 结构化审计日志（敏感头脱敏）
  config.py        # 环境变量配置
  app.py           # FastAPI 装配：防护中间件 + 业务入口 + /admin 管理接口
main.py            # uvicorn main:app
tests/             # 单元/并发/端到端测试（pytest）
```

## 快速开始

```bash
uv sync
uv run uvicorn main:app --reload
# 运行全部测试（含并发冲击、异常规则、非法规则集场景）
uv run pytest
```

管理令牌必须通过环境变量提供（未配置时管理能力一律关闭）：

```bash
REQUEST_DEFENSE_ADMIN_TOKEN=change-me \
REQUEST_DEFENSE_RATE_LIMIT=100 \
REQUEST_DEFENSE_WINDOW_MS=60000 \
uv run uvicorn main:app
```

## 一、限流语义

- **粒度**：按来源标识（`X-Forwarded-For` 首段，缺失时取 TCP 对端地址）独立计数，来源之间互不影响。
- **窗口**：滑动时间窗，默认每窗口 100 个请求 / 60 秒（`REQUEST_DEFENSE_RATE_LIMIT` / `REQUEST_DEFENSE_WINDOW_MS`）。
- **配额耗尽**：返回 `429`，错误码 `rate_limit_quota_exhausted`，审计记录含 `retry_after_ms`。
- **不计费的拒绝**：被限流的请求**不写入窗口时间戳**，因此重复重试不会消耗正常配额，也不会出现"重试越多次、配额恢复越慢"。
- **单调推进、不漏计/超发**：窗口基于 `time.monotonic_ns`，计数在锁内完成；过期时间戳（`ts <= now - window`）在每次判定时驱逐。并发冲击测试断言：N 个请求恰好放行 `limit` 个、拒绝其余，无超发无漏计。
- 限流判定先于规则求值：配额耗尽时直接返回 429，不消耗规则求值资源。

## 二、规则模型

一条规则描述为 `RuleConfig`：

| 字段 | 说明 |
| --- | --- |
| `rule_id` | 非空、规则集内唯一 |
| `priority` | 非负整数，**值越小越先求值**；相同优先级按 `rule_id` 排序，保证顺序确定 |
| `effect` | `deny` 或 `allow`（命中后的动作） |
| `field_name` | 特征字段，见下 |
| `pattern` | Python 正则表达式（`re.search` 语义），编译期校验 |
| `enabled` | 是否启用；停用规则不参与判定 |

支持的特征字段：`source`、`path`、`method`、`body`（body 只取前 512 字节摘要）、`header:<名称>`、`query:<名称>`；缺失的头/查询按空串处理，不抛异常。

**组合判定结论（确定、可解释）：**

| 情况 | 结论 | 错误码（`reason`） | HTTP |
| --- | --- | --- | --- |
| 无任何规则命中 | 放行 | `ok` | 200（继续业务） |
| 仅 `deny` 规则命中 | 拒绝 | `rule_match_deny` | 403 |
| `allow` 与 `deny` 同时命中（冲突） | 拒绝（**从严且确定**） | `rule_conflict_deny` | 403 |
| 规则求值抛异常且没有 deny 命中 | 默认拒绝 | `rule_evaluation_error` | 403 |
| 规则求值超过单请求时间预算 | 默认拒绝 | `rule_timeout` | 403 |
| 生效规则数超过上限 | 拒绝 | `rule_limit_exceeded` | 403 |
| 引擎基础设施故障 | 拒绝 | `engine_internal_error` | 500 |

正常请求不会被误拒（无命中即放行）；可疑请求不会被静默放行（冲突/故障默认 fail-closed）。

### 运行时规则变更（无需重启）

- `GET /admin/rules`：查看当前版本与规则；
- `PUT /admin/rules`：提交**完整**规则集，服务端先把所有规则编译/校验通过，再在同一把锁内原子替换不可变快照，版本号 `+1`。
- **整集拒绝**：空集、重复 `rule_id`、非法正则、未知字段、全部停用、数量超过 `REQUEST_DEFENSE_MAX_RULES`（默认 64）中任何一种情况，整个规则集被拒绝（`422 invalid_rule_set`，带 `index` 与 `current_version`），**旧版本继续生效，不会出现半更新**。
- 进行中的请求读取的是替换前的不可变快照，请求始终对应同一个 `rule_version`，不会出现版本混用或回退。

请求示例：

```bash
curl -X PUT http://127.0.0.1:8000/admin/rules \
  -H "Authorization: Bearer change-me" -H "Content-Type: application/json" \
  -d '{"rules":[{"rule_id":"deny-evil","priority":0,"effect":"deny",
       "field_name":"path","pattern":"^/evil"}]}'
```

## 三、规则故障隔离与降级策略

- **单条规则抛异常**：引擎捕获后把该规则记为 `error`（带异常类型名，如 `RuntimeError`），**其余规则继续求值**；请求不会因为某条规则出错而整体 500。
- **规则故障与服务故障严格分开**：规则自身错误是 `rule_evaluation_error`（403 类），只有线程池/队列等引擎基础设施故障才是 `engine_internal_error`（500 类），两类在响应、审计、日志中均可区分。
- **时间上限**：整次规则求值受 `REQUEST_DEFENSE_TIMEOUT_MS`（默认 200ms）总预算约束，逐条递减；超时的规则记 `rule_timeout`，不允许无界等待。规则在线程池中执行，线程池有界（4 worker），在途信号量上限 8，队列饱和按 `engine_internal_error` 降级，不无界占用资源。
- **数量上限**：`REQUEST_DEFENSE_MAX_RULES`（默认 64）。管理接口在写入侧拒绝超量规则集；引擎在求值侧对快照规则数做二次检查（纵深防御）。
- **失败后的状态**：规则对象无状态、请求特征不可变，单条规则失败/超时不写入任何共享状态；应用关闭时调用 `engine.shutdown()` 取消在途任务，无线程残留。
- **fail-open 仅作为显式可选项**：默认 fail-closed（规则故障即拒绝）；只有显式设置 `REQUEST_DEFENSE_FAIL_OPEN=1` 时，纯规则故障才降级为放行，且响应/审计中的原因码不变（仍然是 `rule_evaluation_error` / `rule_timeout`），放行与故障同时可解释。

## 四、管理接口安全

- 仅接受 `Authorization: Bearer <token>`，使用 `hmac.compare_digest` 常量时间比较；
- 未配置管理令牌时管理能力全部关闭（fail-closed）；
- 未授权/凭据错误统一返回 `401 {"error":"unauthorized","message":"unauthorized"}`，不区分"缺失/格式错/令牌错"，不回显规则数、版本等任何内部状态；
- 审计日志只记录令牌的不可逆短摘要（`sha256:xxxxxxxx`），`authorization` / `x-admin-token` / `cookie` / `proxy-authorization` 头一律脱敏，完整凭据与令牌不会出现在任何日志中。

## 五、审计与日志

每次判定输出一条 JSON 结构化日志（放行 INFO，限流/拒绝 WARNING），包含：

- `decision`（allow / rate_limited / deny）与可区分的 `reason`；
- `input`：来源、方法、路径、查询参数、**脱敏后**的请求头、body 前 512 字节摘要——足以复现判定；
- `basis`：`rule_version`、每条规则的结论/优先级/动作/错误类型/耗时、限流剩余配额与 retry_after；
- `elapsed_ms`：单请求总耗时。

## 六、验证方法

```bash
uv run pytest -v          # 全量 70 个用例，单测日志会打印每个用例的输入与判定依据
```

重点场景：

- **并发冲击**：`tests/test_ratelimiter.py::test_concurrent_burst_no_overcount_no_overgrant`
  （50 线程 × 4 请求，断言恰好 100 放行 / 100 拒绝）、
  `tests/test_engine.py::TestConcurrentCountingAndRuleChanges`
  （30 来源并发计数；8 请求线程与规则变更线程并发，断言无异常、版本不倒退）、
  `tests/test_app.py::TestConcurrencyViaHttp`（HTTP 端到端并发计数与变更期间无 500）；
- **异常规则**：`tests/test_engine.py::TestRuleFaultIsolation`（规则抛异常被隔离、
  其余规则继续、结论原因可区分、后续请求不被污染、超时按预算降级、fail-open 可选）；
- **非法规则集**：`tests/test_rules_store.py::TestRuleStore::test_invalid_set_rejected_entirely`
  与 `tests/test_app.py::TestRuntimeRuleChanges::test_invalid_rule_set_rejected_entirely`
  （空集/重复 id/坏正则/全停用/超量均被整集拒绝，旧版本原样保留）。

手动验证：

```bash
REQUEST_DEFENSE_ADMIN_TOKEN=change-me REQUEST_DEFENSE_RATE_LIMIT=3 \
  uv run uvicorn main:app
curl -s localhost:8000/api/echo                 # 200
for i in 1 2 3 4; do curl -s -o /dev/null -w "%{http_code}\n" localhost:8000/api/echo; done
# 200 200 200 429（第 4 个起 rate_limit_quota_exhausted）
curl -s localhost:8000/admin/rules              # 401
curl -s -H "Authorization: Bearer change-me" localhost:8000/admin/rules   # 200 + 当前规则版本
```
