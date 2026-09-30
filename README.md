# 本地请求防护层（FastAPI Request Defense）

在现有 HTTP 服务前增加的一层**本地请求防护**，把三件事结合起来并给出一致、可解释的处置结论：

1. **来源限流** —— 按来源标识的滑动时间窗配额；
2. **请求特征规则** —— 多条规则组合判定（命中/未命中/冲突）；
3. **判定审计** —— 每次判定输出结论、原因、依据与输入摘要。

所有入口（除豁免的运维路径与管理路径外）都经过同一套中间件，因此正常、被限流、可疑流量的处置口径完全一致；**带正文入口（POST/PUT/PATCH）与读入口共用同一套来源额度、特征规则与审计口径**。带正文入口的判定结论**只取决于正文的累计字节数，与正文的送达方式无关**——客户端一次性发整包（带 `Content-Length`）、分多片发送、还是不带长度一段段流式（分块）推送，同一份正文得到的结论完全相同；放行时业务侧拿到客户端原始正文（不消费、不截断、不改写）。

## 目录结构

```
request_defense/
  types.py         # Decision / Reason / RuleVerdict / RuleConfig / RequestFeatures 等核心类型
  ratelimiter.py   # 线程安全的滑动时间窗限流器
  rule.py          # 单条特征规则：编译（正则校验）与无状态求值
  store.py         # 规则集不可变快照 + 整体校验 + 原子替换（版本单调递增）
  policy.py        # 正文容量/内容策略（BodyPolicy）：不可变快照 + 整体校验 + 原子替换
  bodyguard.py     # 有界正文接收（读到结束/越界再下结论）+ ASGI receive 原样重放 + 接收上限/超时
  engine.py        # 限流预检 + 规则组合判定 + 超时/异常隔离 + 资源上限
  auth.py          # 管理接口 Bearer 令牌校验（常量时间比较、fail-closed）
  audit.py         # 结构化审计日志（敏感头脱敏、正文计量 body_meta）
  config.py        # 环境变量配置
  app.py           # FastAPI 装配：纯 ASGI 防护中间件 + 业务入口（含 POST/PUT/PATCH）+ /admin
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

支持的特征字段：`source`、`path`、`method`、`body`（body 只在 `inspect_limit` 检查上限内参与匹配，默认 64 KiB，可运行时调整；见第三节）、`header:<名称>`、`query:<名称>`；缺失的头/查询按空串处理，不抛异常。

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

## 三、带正文入口（POST / PUT / PATCH）与有界容量

带正文入口与 GET 等读入口走**完全相同**的防护链：先做来源额度预检（被限流直接 429，不读取正文、不执行业务），再做有界正文接收与内容判定，最后才进入业务。

### 3.1 送达方式无关：整包 / 分片 / 流式结论一致，放行即透传原始正文

防护层在**纯 ASGI 层包装 `receive`**（不使用会缓冲整个请求体的 BaseHTTPMiddleware）。为了让判定不依赖“正文恰好怎么被切成 ASGI 事件”，防护层不会只看前一两个事件就猜测结论，而是把 `http.request` 事件**持续读到“正文结束”（`more_body=False`）或“越过接收上限”为止**，只凭**累计字节数与结束事实**下结论：

- 读到结束、总字节 ≤ `inspect_limit`：正文完整落在检查范围内，进入内容判定；
- 读到结束、`inspect_limit` < 总字节 ≤ `receive_limit`：`content_inspection_incomplete`（403）；
- 累计字节一旦 > `receive_limit`：立刻 `body_too_large`（413），该越界事件及后续字节**不保留、不透传，业务不执行**。

因此像“最后一片数据恰好把检查上限填满、下一个事件只是独立的空收尾 `(b"", more_body=False)`”（httpx ASGI 测试通道与部分真实服务器对分块上传就是这种事件形态：**每个**数据事件都带 `more_body=True`，末尾再来一个空收尾事件）不会再被误判成“正文恰好等于上限”而放行；写在检查范围之后的规则特征，也不能靠“放在后面一片”绕过。

放行路径上，预取期间读到的 ASGI 事件按**原始事件边界原样重放**给下游（不拆事件、不改写 `more_body`），随后透传真实 `receive`；字节序、长度、内容类型与客户端发出的**完全一致**：

- 业务侧 `await request.body() / request.json() / request.form()` 不需要任何改动（**调用方协议不变**），不会出现“防护层提前消费导致业务读到空体/残体”；
- 被限流（429）、被规则拒绝（403）、无法完成内容判定（403）、超接收上限（413）等情况下业务入口**绝不会被执行**（测试用副作用端点 `POST /api/side-effect` 断言）。

示例业务入口（可直接作为接入参考）：

| 入口 | 方法 | 说明 |
| --- | --- | --- |
| `/api/submit/json` | POST | 读取原始字节后由业务自行 JSON 解析，回显长度/类型/载荷 |
| `/api/submit/form` | POST/PUT/PATCH | `request.form()`，支持 urlencoded 与 multipart |
| `/api/upload/raw` | POST/PUT/PATCH | 任意二进制，回显长度、Content-Type 与 base64 全文 |
| `/api/side-effect` | GET/POST/PUT/PATCH | 带调用计数，供测试断言“拒绝时业务不执行” |

**兼容范围（不要求调用方改协议）：**

- 读入口（GET 等）行为与旧版本一致：不触碰请求体、不改变状态码与错误体（既有 70 个用例零修改通过）；
- 写入口继续使用标准 `Content-Type` 与正文编码（JSON / `x-www-form-urlencoded` / `multipart/form-data` / 任意二进制），业务侧仍用 FastAPI 原生的 `request.body()/json()/form()` 读取；
- 唯一新增的**默认行为差异**：POST/PUT/PATCH 现在会受到接收上限（默认 1 MiB）与检查上限（默认 64 KiB）保护——超过检查上限默认 403。历史上需要更大正文检查范围的入口，应通过 `PUT /admin/policy` 调大 `inspect_limit`（或在确认安全后关闭 `content_check_enabled`），并按需调大 `receive_limit`；这是有界防护的显式取舍，不需要改客户端协议。

### 3.2 两个上限：语义严格区分

| 策略字段 | 含义 | 触发结果 |
| --- | --- | --- |
| `inspect_limit`（检查上限，默认 64 KiB） | 内容规则的匹配范围。body 规则只在这个前缀内匹配；防护层为下结论会读到正文结束，但只把该前缀交给规则/审计 | 正文超过它但未超接收上限 => **403 `content_inspection_incomplete`**：“太大，无法完成内容判定”（默认 fail-closed，不猜测未检查部分，**不分片/流式都一致**） |
| `receive_limit`（接收上限，默认 1 MiB） | 服务愿意接收的正文总大小（判定在业务执行**之前**完成） | 超过它 => **413 `body_too_large`**：“太大，不接受”，越界字节不缓冲、不透传、业务不执行；**有无 `Content-Length`、是否分片结论一致** |

两类“太大”在 **HTTP 状态码（403 vs 413）与原因码**两个维度都可区分，审计记录中的 `body_meta` 还会给出 `content_length / content_type / inspected_bytes / total_bytes / exceeds_inspect_limit / inspect_limit / receive_limit`。

边界语义（自动测试覆盖，整包与分片双通道各断言一遍）：

- 正文长度 `< inspect_limit` 与 `== inspect_limit`：正常进入内容判定（边界不误伤，64 字节按 `[64]`、`[32,32]`、`[1]×64` 等多种切法都放行）；
- `> inspect_limit` 且内容判定开关开启：一律 `content_inspection_incomplete`；即使触发规则的特征串写在第 64 字节之后，也不能靠分片摆放把它“藏到检查范围外”绕过；
- 声明的 `Content-Length > receive_limit`：**一个字节都不读取**直接 413；
- 没有 `Content-Length` 的分块/流式请求：预取持续计量，累计字节越过 `receive_limit` 的当下立即 413（不再像旧实现那样拖到下游重放阶段），`== receive_limit` 仍按检查上限口径处理、不误伤。

### 3.3 有界性：内存、耗时、并发都有上限

- **内存有界**：为了对“正文到底有多大、在哪里结束”给出与送达方式无关的确定结论，预取会读到正文结束或越过接收上限；读取在越界点立即停止，因此**单请求缓冲 ≤ `receive_limit`（硬天花板 16 MiB）**，最坏总缓冲 ≈ `inflight × receive_limit`，绝不会因为客户端持续推流而无界增长。放行重放只使用已保留的原始事件，不额外复制；
- **耗时有界**：预取每次 `receive` 受 `REQUEST_DEFENSE_BODY_TIMEOUT_MS`（默认 5000ms）约束，慢发送不能挂死连接，超时返回 **408 `body_receive_timeout`**；
- **并发有界**：在途带正文请求受 `REQUEST_DEFENSE_BODY_INFLIGHT`（默认 32）名额限制，名额耗尽立即 **503 `body_concurrency_limited`** 背压，不排队堆积；
- **不绕过来源额度**：无论正文多大、怎么分片，限流预检都最先执行，且与读入口共用同一窗口与配额。

### 3.4 运行时容量与内容策略变更（不重启）

- `GET /admin/policy`：查看当前 `version / inspect_limit / receive_limit / content_check_enabled`；
- `PUT /admin/policy`：整体校验后在同一把锁内**原子替换**不可变快照，版本号 `+1`；
- 非法配置（非正整数、`inspect_limit > receive_limit`、超过硬天花板 1 MiB/16 MiB、布尔非法）一律 **422 `invalid_policy`**（带 `field` 与 `current_version`），**旧策略继续生效，不会半更新**；
- 规则快照在规则判定时取一次，整次规则求值对应同一个 `rule_version`；**正文策略在预取的每个 ASGI 事件后重新取快照**：整包请求读到的是进入时的策略，正在分段/流式送达的请求，其**尚未读到的部分立即按新上限判定**（调大、调小都适用），结论与审计记录中的 `policy_version` 即最终实际适用的版本，不会一半旧一半新；
- `content_check_enabled=false` 时 `field_name == "body"` 的规则整体不参与判定（来源/路径/头/查询规则照常），便于在确认入口安全后临时对大正文放开内容判定；此时流式正文仍会完整重放给业务（逐字节一致），**接收上限始终生效**（越界仍 413）。

```bash
curl -X PUT http://127.0.0.1:8000/admin/policy \
  -H "Authorization: Bearer change-me" -H "Content-Type: application/json" \
  -d '{"inspect_limit":131072,"receive_limit":4194304,"content_check_enabled":true}'
```

相关环境变量（仅初始值，之后都可以用 `/admin/policy` 在线调整，除在途名额外）：

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `REQUEST_DEFENSE_INSPECT_LIMIT` | 65536 | 初始内容检查上限（字节） |
| `REQUEST_DEFENSE_RECEIVE_LIMIT` | 1048576 | 初始接收上限（字节） |
| `REQUEST_DEFENSE_INSPECT_DISABLED` | 0 | 为 1 时初始关闭内容判定 |
| `REQUEST_DEFENSE_BODY_TIMEOUT_MS` | 5000 | 单请求正文接收时间预算 |
| `REQUEST_DEFENSE_BODY_INFLIGHT` | 32 | 并发带正文请求在途名额 |

## 四、规则故障隔离与降级策略

- **单条规则抛异常**：引擎捕获后把该规则记为 `error`（带异常类型名，如 `RuntimeError`），**其余规则继续求值**；请求不会因为某条规则出错而整体 500。
- **规则故障与服务故障严格分开**：规则自身错误是 `rule_evaluation_error`（403 类），只有线程池/队列等引擎基础设施故障才是 `engine_internal_error`（500 类），两类在响应、审计、日志中均可区分。
- **时间上限**：整次规则求值受 `REQUEST_DEFENSE_TIMEOUT_MS`（默认 200ms）总预算约束，逐条递减；超时的规则记 `rule_timeout`，不允许无界等待。规则在线程池中执行，线程池有界（4 worker），在途信号量上限 8，队列饱和按 `engine_internal_error` 降级，不无界占用资源。
- **数量上限**：`REQUEST_DEFENSE_MAX_RULES`（默认 64）。管理接口在写入侧拒绝超量规则集；引擎在求值侧对快照规则数做二次检查（纵深防御）。
- **失败后的状态**：规则对象无状态、请求特征不可变，单条规则失败/超时不写入任何共享状态；应用关闭时调用 `engine.shutdown()` 取消在途任务，无线程残留。
- **fail-open 仅作为显式可选项**：默认 fail-closed（规则故障即拒绝）；只有显式设置 `REQUEST_DEFENSE_FAIL_OPEN=1` 时，纯规则故障才降级为放行，且响应/审计中的原因码不变（仍然是 `rule_evaluation_error` / `rule_timeout`），放行与故障同时可解释。

## 五、管理接口安全

- 仅接受 `Authorization: Bearer <token>`，使用 `hmac.compare_digest` 常量时间比较；
- 未配置管理令牌时管理能力全部关闭（fail-closed）；
- 未授权/凭据错误统一返回 `401 {"error":"unauthorized","message":"unauthorized"}`，不区分"缺失/格式错/令牌错"，不回显规则数、版本等任何内部状态；
- 审计日志只记录令牌的不可逆短摘要（`sha256:xxxxxxxx`），`authorization` / `x-admin-token` / `cookie` / `proxy-authorization` 头一律脱敏，完整凭据与令牌不会出现在任何日志中。

## 六、审计与日志

每次判定输出一条 JSON 结构化日志（放行 INFO，限流/拒绝 WARNING），包含：

- `decision`（allow / rate_limited / deny）与可区分的 `reason`；
- `input`：来源、方法、路径、查询参数、**脱敏后**的请求头、body 检查前缀（日志中截断到前 512 字节）与 `body_meta`（声明长度/内容类型/检查字节数/已读总字节数/是否超过检查上限/两档上限）——足以复现判定，且不记录完整正文；
- `basis`：`rule_version`、每条规则的结论/优先级/动作/错误类型/耗时、限流剩余配额与 retry_after；
- `elapsed_ms`：单请求总耗时。

## 七、验证方法

```bash
uv run pytest -v          # 全量用例（含分片/流式一致性、在途调参、并发冲击、异常规则）
```

重点场景：

- **分片/流式正文一致性（本次新增）**：`tests/test_streaming_body.py`
  - 同一份 100 字节正文分别按 `[100] / [50,50] / [1,1,98] / [40,40,20] / [1]×100 / [64,36]`
    等切法、以**不带 Content-Length 的异步流**（每数据事件 `more_body=True` + 末尾独立空
    收尾事件，精确复现旧实现漏判形态）提交，全部稳定判 **403 `content_inspection_incomplete`**；
  - 257/400 字节按多种切法流式提交，全部 **413 `body_too_large`**，业务计数不增加；
  - 0/1/63/64 字节（含 64 字节按 `[64]/[32,32]/[1]×64` 切）与多段拼接放行，业务侧收到的
    字节逐字节一致、内容类型不改写；
  - 规则特征写在检查范围**之后**时，整包/分片/逐字节三种送法都 fail-closed，不能绕过；
  - 20 来源并发流式大正文只出现 200/403/413、无 5xx，被拒请求业务不执行；
  - 正文在途时调小 `inspect_limit` / `receive_limit`（403/413 各自验证）与调大
    `receive_limit`，在途的分段请求完整按新策略走完，结论带新的 `policy_version`；
  - 关闭内容判定后流式 200 字节完整透传、257 字节仍 413；慢流式晚到分片 => 408；
- **带正文入口**：`tests/test_body.py`
  - `TestPassthroughIntegrity`：JSON / urlencoded / multipart / 二进制四类正文，
    断言放行时业务侧收到的字节、长度、内容类型与发送**完全一致**（含 0/1/63/64 字节边界、PUT/PATCH）；
  - `TestBlockedNeverReachesBusiness`：限流 429 与 body 规则 403 时副作用端点
    （`/api/side-effect`）计数不增加——业务入口确实未执行；
  - `TestBoundedBody`：413 `body_too_large` 与 403 `content_inspection_incomplete`
    状态/原因可区分、恰好等于上限放行、慢发送 408 `body_receive_timeout`；
  - `TestConcurrentLargeBodies`：在途名额满时 503 `body_concurrency_limited`，
    并发大正文只出现 200/503、无 5xx；
  - `TestRuntimePolicyChanges`：策略运行时生效、非法配置 422 整体拒绝且旧策略保留、
    关闭/重开内容判定、并发更新版本集合完整无重复、管理鉴权；
- **有界接收原语**：`tests/test_bodyguard.py`（直接测读取/重放：
  httpx 式“数据事件全 more_body=True + 独立空收尾”在 65/100/256 字节下稳定超限、
  64/63 字节边界不误伤、声明超限零读取、超时、无长度流式越界在预取阶段直接 413、
  `policy_provider` 在途调小检查/接收上限即时生效、PolicyStore 原子性）；
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
  REQUEST_DEFENSE_INSPECT_LIMIT=64 REQUEST_DEFENSE_RECEIVE_LIMIT=256 \
  uv run uvicorn main:app
curl -s localhost:8000/api/echo                 # 200
for i in 1 2 3 4; do curl -s -o /dev/null -w "%{http_code}\n" localhost:8000/api/echo; done
# 200 200 200 429（第 4 个起 rate_limit_quota_exhausted）
curl -s localhost:8000/admin/rules              # 401
curl -s -H "Authorization: Bearer change-me" localhost:8000/admin/rules   # 200 + 当前规则版本

# 带正文：JSON 原样到达业务
curl -s -X POST localhost:8000/api/submit/json -H 'Content-Type: application/json' -d '{"a":1}'
# 二进制（64 字节 == 检查上限）放行；100 字节 403 content_inspection_incomplete；300 字节 413 body_too_large
head -c 64  /dev/urandom | curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  localhost:8000/api/upload/raw -H 'Content-Type: application/octet-stream' --data-binary @-
head -c 100 /dev/zero    | curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8000/api/upload/raw --data-binary @-
head -c 300 /dev/zero    | curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8000/api/upload/raw --data-binary @-
# 不重启调大检查/接收上限后，100 字节变为 200
curl -s -X PUT localhost:8000/admin/policy -H 'Authorization: Bearer change-me' \
  -H 'Content-Type: application/json' \
  -d '{"inspect_limit":128,"receive_limit":1024,"content_check_enabled":true}'
```

用 curl 强制分块传输（`Expect:` 去掉 100-continue，`-T -` 走 chunked，无 Content-Length），
验证同一份正文“整包 vs 流式”结论一致：

```bash
head -c 100 /dev/zero | curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  localhost:8000/api/upload/raw -H 'Content-Type: application/octet-stream' \
  -H 'Expect:' -T -                            # 403（chunked，无长度）
head -c 100 /dev/zero | curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  localhost:8000/api/upload/raw --data-binary @-   # 403（带 Content-Length，结论相同）
head -c 300 /dev/zero | curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  localhost:8000/api/upload/raw -H 'Expect:' -T -   # 413（chunked 同样按接收上限拒）

# 自动化复现（与真实分片服务器事件形态一致：数据事件全 more_body=True + 末尾空收尾）
uv run pytest tests/test_streaming_body.py -v
uv run pytest -v   # 全量回归
```
