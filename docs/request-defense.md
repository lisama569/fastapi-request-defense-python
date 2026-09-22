# 本地请求防护层（Request Defense）

在现有 FastAPI 服务前增加的本地防护层，把**来源限流**、**请求特征规则判定**与
**判定审计**组合为一条统一的请求处置流水线，使正常流量、被限流流量与可疑流量
在所有业务入口下得到一致、可解释的结论。

## 1. 总体结构

```
HTTP 请求
   │
   ▼
defense_middleware（统一入口，/admin、/healthz、/docs 除外）
   │  构造 RequestFeatures（source/method/path/headers/query/body_digest，敏感头打码）
   ▼
RequestDefense.inspect
   │  ① 规则存储快照 RuleStore.snapshot() —— 同一锁内取得 (引擎, 版本)
   │  ② SlidingWindowRateLimiter.check（滑动日志，按来源计数）
   │      └─ 超限：直接返回 rate_limited，不再进入规则求值
   │  ③ RuleEngine.evaluate（优先级组合判定；异常/超时/容量隔离与降级）
   │  ④ AuditLogger.record（审计入库 + 分级日志）
   ▼
DefenseGate.render：统一的状态码 / 响应体 / 响应头
```

模块职责：

| 模块 | 职责 |
| --- | --- |
| `app/ratelimit.py` | 按来源的滑动时间窗限流（sliding window log） |
| `app/rules.py` | 规则模型、规则集整体校验、组合判定引擎（异常隔离/超时/容量降级） |
| `app/rule_store.py` | 规则集版本化与运行时原子替换 |
| `app/defense.py` | 门面：限流→规则→审计的一致编排，服务故障兜底 |
| `app/audit.py` | 审计记录、分级日志、敏感信息脱敏 |
| `app/security.py` | 管理接口 Bearer 鉴权（常数时间比较） |
| `app/web.py` | HTTP 特征提取与结论渲染 |
| `main.py` | 组装服务、中间件、管理接口 |

## 2. 限流语义

- 算法：**滑动窗口日志（sliding window log）**。每个来源维护窗口内请求
  时间戳队列；每次检查先弹出 `now-window` 之前的过期事件，再比较队列长度
  与配额。
- **恰好一次计数**：只有放行的请求才会被追加到窗口；被拒请求不入队，因此
  不会重复扣减，也不会因拒绝而把配额“挤没”。
- **配额耗尽即拒绝**，原因固定为 `rate_limit_quota_exhausted`，HTTP 429，
  并带 `Retry-After`、`X-RateLimit-Limit`、`X-RateLimit-Remaining`。
- **单调窗口**：每个来源的时间在限流器内部单调化（`max(now, last_seen)`），
  时钟回拨不会让过期槽位复活；相同时间戳的重复请求各自计数，不漏计、不超发。
- 来源之间相互独立（按 `Request.client.host` 标识来源）。
- 空闲超过一个窗口的来源队列会被清理，避免内存无界增长。

并发正确性由每来源检查路径上的单把互斥锁保证：并发冲击下，放行数量恒等于
配额（测试 `test_concurrent_burst_admits_exactly_limit_no_more_no_less`
用 2000 线程竞争同一时间戳、配额 500 断言恰好 500 个放行）。

## 3. 规则模型

规则是声明式六元组（`app.models.RuleDef`）：

```
rule_id    规则唯一标识（规则集内不允许重复）
priority   优先级，数值越小越优先；同值按 rule_id 字典序（冲突结论确定）
action     命中后的处置倾向：allow / deny
field_name 取特征值的字段：
           path | method | source | body_digest
           header:<名称> | query:<名称>
operator   eq | ne | prefix | suffix | contains | regex | in（逗号分隔白名单）
expected   比较值
enabled    是否启用（停用规则不参与求值，也不占容量）
```

### 组合判定

1. 启用规则按 `(priority, rule_id)` 排序后依次求值；
2. 取**优先级最高的命中规则**的动作作为结论：
   - `allow` → `allow / rule_match_allow`
   - `deny` → `deny / rule_match_deny`（HTTP 403）
3. 全部未命中且无决定性故障 → `allow / no_rule_matched`（默认放行，
   正常请求不会被误拒）；
4. allow 与 deny 规则同时命中（冲突）时，由优先级唯一决定，且与规则传入
   顺序无关（确定性，见 `test_conflicting_rules_resolve_by_priority_deterministically`）。

每条规则的求值结果都会形成一条 `RuleTrace`（rule_id / priority /
outcome / detail），随判定写入审计，可完整复现判定依据。

### 规则故障隔离

单条规则求值抛出任何异常（坏正则、字段错误、自定义规则运行期错误等）都被
隔离为该规则的 `error` 轨迹，**其余规则继续参与决策**。规则故障与防护层
自身故障严格区分：

- 规则故障：`decision=rule_error`（fail_closed 时 HTTP 403）或带降级标记的
  放行（fail_open 时 HTTP 200 + `X-Defense-Reason`）；
- 服务故障：`decision=service_error / defense_internal_error`（HTTP 500），
  仅在规则存储/引擎等服务侧组件意外抛错时出现。

### 决定性故障与降级策略

并非所有故障都会推翻已有结论：只有**位于不劣于最高命中规则优先级**位置的
故障（异常 / 超时跳过 / 容量跳过）才使结论“不确定”；最高命中之后的低优先
级故障不影响已确定的高优先级结论。

对“不确定”结论按 `DEFENSE_ON_RULE_ERROR` 降级：

| 策略 | 结论 | 可区分原因 |
| --- | --- | --- |
| `fail_closed`（默认，安全优先） | 拒绝 | `rule_evaluation_error_fail_closed` / `rule_budget_exceeded_fail_closed` / `rule_capacity_exceeded_fail_closed` |
| `fail_open`（显式配置） | 放行 | 对应 `*_fail_open`，且 `degraded=true`、响应头带原因，**不是静默放行** |

## 4. 资源上限与降级

- **规则数量上限** `DEFENSE_MAX_RULES`（默认 100）：单请求最多求值这么多
  条，超出部分记 `skipped_capacity`，按容量策略降级。
- **单请求耗时上限** `DEFENSE_BUDGET_MS`（默认 50ms）：规则在共享的有界
  线程池中以“剩余预算”为超时执行；
  - 线程池与一个等大的非阻塞信号量配合：没有空闲求值槽位时**立即**按容量
    故障降级，任务不在队列中堆积（排队不会被误判为规则超时）；
  - 规则确实开始执行但超时：记 `skipped_timeout` 并降级，请求线程不继续
    等待，后台任务结束后归还槽位（有界，不泄漏线程/槽位）。
- 共享线程池与信号量由 `RuleStore` 持有、跨规则版本复用；规则集替换只换
  引擎对象，不新建/销毁线程池，因此频繁变更不会泄漏线程资源。
- 判定中所有中间状态（轨迹列表、命中/故障标记）都是请求内局部变量，
  失败路径不向限流器/规则存储回写任何“部分判定状态”。

## 5. 规则集运行时变更（不重启、原子生效）

- `PUT /admin/rules` 整体提交新规则集；
- 变更协议（杜绝半更新）：
  1. **先整体校验**（在锁外）：rule_id 非空且不重复、priority 为 int、
     action 合法、field_name/operator 合法、regex 可编译、启用规则数不超过
     容量；任一条非法 → `RuleSetValidationError`，整个集合被拒绝；
  2. 校验通过后构建全部规则对象；
  3. 加锁后以**单次属性赋值**替换当前引擎，版本号单调 +1。
- 非法或部分无效的集合返回 `400 invalid_ruleset` 且**当前在效规则与版本
  完全不变**（测试 `test_invalid_ruleset_rejected_entirely_no_half_update`）。
- 读侧 `snapshot()` 在同一把锁内同时取得 `(引擎, 版本)`，每个请求使用
  快照版本判定并把该版本写入审计；并发替换下版本永不回退
  （测试 `test_concurrent_replaces_never_regress_version`，50 线程并发替换
  断言版本恰好为 1..50）。
- 停用规则：在规则集中把 `enabled=false` 并重新提交；调整优先级：修改
  `priority` 后重新提交，均在下一个请求整体生效。

## 6. 管理接口与鉴权

| 接口 | 说明 |
| --- | --- |
| `GET /admin/rules` | 查看当前版本与生效规则 |
| `PUT /admin/rules` | 整体替换规则集（非法返回 400，版本不变） |
| `GET /admin/audit` | 查看最近审计记录（结论、原因、输入摘要、逐规则轨迹） |

- 所有 `/admin/*` 接口都要求 `Authorization: Bearer <token>`，使用
  `hmac.compare_digest` 常数时间比较；缺失/格式错误/凭据错误统一返回
  `401 {"detail":"unauthorized"}` 与 `WWW-Authenticate: Bearer`，
  **不回显凭据、不泄漏规则版本/数量等内部状态**。
- 令牌通过 `DEFENSE_ADMIN_TOKEN` 注入（默认值仅用于本地开发，生产必须覆盖）。
- `authorization`、`cookie`、`x-admin-token`、`proxy-authorization` 等敏感
  头在进入规则引擎前即被替换为 `***redacted***`；日志与审计中只出现
  固定掩码，任何地方都不会打印完整凭据或令牌
  （测试 `test_input_summary_redacts_sensitive_headers`、
  `test_audit_endpoint_records_basis_and_no_token_leak`）。

## 7. 审计与日志

- 每个被防护的请求都生成一条审计记录：决策、可区分原因、来源、方法、路径、
  **规则版本**、输入摘要（含脱敏后的头部/查询参数/body 摘要）、逐规则
  轨迹、剩余配额、耗时、是否降级。
- 日志分级，三类处置肉眼与机器均可区分：
  - 放行 → `INFO`，`decision=allow reason=no_rule_matched|rule_match_allow|...`
  - 限流 → `WARNING`，`decision=rate_limited reason=rate_limit_quota_exhausted`
  - 拒绝 → `WARNING`（命中规则）/ `ERROR`（规则故障降级）
- 单测在关键用例中额外打印输入摘要与判定依据（`tests/test_rules.py` 中的
  `_log_verdict`），失败时可直接从日志复现判定。

## 8. 处置结论一览

| decision | reason（可区分） | HTTP | 含义 |
| --- | --- | --- | --- |
| `allow` | `no_rule_matched` | 200 | 无规则命中（默认放行） |
| `allow` | `rule_match_allow` | 200 | 最高优先级命中为 allow |
| `allow` | `rule_*_fail_open` | 200（`degraded`/响应头标记） | fail_open 下降级放行 |
| `rate_limited` | `rate_limit_quota_exhausted` | 429 | 来源窗口配额耗尽 |
| `deny` | `rule_match_deny` | 403 | 最高优先级命中为 deny |
| `rule_error` | `rule_evaluation_error_fail_closed` | 403 | 规则异常，fail_closed |
| `rule_error` | `rule_budget_exceeded_fail_closed` | 403 | 单请求超时降级 |
| `rule_error` | `rule_capacity_exceeded_fail_closed` | 403 | 规则数/求值槽位超限降级 |
| `service_error` | `defense_internal_error` | 500 | 防护层自身故障（与规则故障分离） |

## 9. 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `DEFENSE_RATE_LIMIT` | `10` | 每来源每窗口配额 |
| `DEFENSE_WINDOW_SECONDS` | `1.0` | 限流窗口（秒） |
| `DEFENSE_MAX_RULES` | `100` | 单请求求值规则数量上限 |
| `DEFENSE_BUDGET_MS` | `50.0` | 单请求规则求值耗时上限（毫秒） |
| `DEFENSE_ON_RULE_ERROR` | `fail_closed` | `fail_closed` / `fail_open` |
| `DEFENSE_ADMIN_TOKEN` | `dev-only-admin-token` | 管理接口 Bearer 令牌（生产必须覆盖） |

## 10. 验证方法

```bash
uv sync                                  # 安装依赖
uv run pytest                            # 全部单测（48 个，含并发/异常/非法集场景）
uv run pytest -q --tb=short -k concurrent   # 仅并发一致性测试
uv run uvicorn main:app --reload         # 本地启动
```

手动验证示例：

```bash
# 1) 正常请求
curl -i http://127.0.0.1:8000/

# 2) 连续请求触发限流（默认每窗口 10 次）
for i in $(seq 1 12); do curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/; done

# 3) 可疑请求被拒绝（种子规则：/suspicious 前缀 deny）
curl -i http://127.0.0.1:8000/suspicious/x

# 4) 规则集整体替换（运行时生效，无需重启）
curl -i -X PUT http://127.0.0.1:8000/admin/rules \
  -H "Authorization: Bearer dev-only-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"rules":[{"rule_id":"block-post","priority":1,"action":"deny",
       "field_name":"method","operator":"eq","expected":"POST"}]}'

# 5) 非法规则集被整体拒绝（版本不变）
curl -i -X PUT http://127.0.0.1:8000/admin/rules \
  -H "Authorization: Bearer dev-only-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"rules":[{"rule_id":"bad","priority":1,"action":"wat",
       "field_name":"path","operator":"eq","expected":"/"}]}'

# 6) 未授权访问管理接口
curl -i http://127.0.0.1:8000/admin/rules

# 7) 查看审计（含判定依据与脱敏后的输入摘要）
curl -s -H "Authorization: Bearer dev-only-admin-token" \
  http://127.0.0.1:8000/admin/audit | python -m json.tool
```

测试覆盖的重点场景：

- **并发冲击**：2000 线程同戳竞争限流（恰好放行配额数）；8 线程 ×100 请求
  与持续规则变更并行（计数精确、无 deny/rule_error/service_error、版本不
  回退）；50 线程并发替换规则集（版本 1..50 单调）。
- **异常规则**：运行期抛错的规则被隔离，其余规则继续决策；fail_closed /
  fail_open 结论与原因可区分；慢规则超时、槽位耗尽容量降级、超时后槽位
  回收不泄漏。
- **非法规则集**：空 id、非法动作/字段/操作符、坏正则、重复 id、超容量等
  一律整体拒绝，已生效规则与版本保持不变，后续请求结论不受污染。
