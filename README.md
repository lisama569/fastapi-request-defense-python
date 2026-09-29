# 本地请求防护层（FastAPI Request Defense）

在现有 HTTP 服务前增加的一层**本地请求防护**，把三件事结合起来并给出一致、可解释的处置结论：

1. **来源限流** —— 按来源标识的滑动时间窗配额；
2. **请求特征规则** —— 多条规则组合判定（命中/未命中/冲突）；
3. **判定审计** —— 每次判定输出结论、原因、依据与输入摘要。

所有入口（除豁免的运维路径与管理路径外）都经过同一套中间件，因此正常、被限流、可疑流量的处置口径完全一致。**POST/PUT/PATCH 等带正文的提交、上传入口与 GET 读入口走同一套来源额度、特征规则和审计口径**；放行时业务侧拿到客户端原本发出的完整正文（字节、长度、内容类型不被消费、截断或改写），被限流或被规则拒绝时业务入口不会被执行。

## 目录结构

```
request_defense/
  types.py         # Decision / Reason / RuleVerdict / RuleConfig / RequestFeatures 等核心类型
  ratelimiter.py   # 线程安全的滑动时间窗限流器
  rule.py          # 单条特征规则：编译（正则校验）与无状态求值
  store.py         # 规则集不可变快照 + 整体校验 + 原子替换（版本单调递增）
  policy.py        # 内容策略（检查/接收上限、内容判定开关）不可变快照 + 整体校验 + 原子替换
  ingress.py       # 带正文入口的有界接收（内存有界、可落盘）与原样回放
  middleware.py    # 纯 ASGI 防护中间件：读/写入口统一限流+内容接收+规则+审计+回放
  engine.py        # 限流 + 规则组合判定 + 超时/异常隔离 + 资源上限
  auth.py          # 管理接口 Bearer 令牌校验（常量时间比较、fail-closed）
  audit.py         # 结构化审计日志（敏感头脱敏）
  config.py        # 环境变量配置
  app.py           # FastAPI 装配：防护中间件 + 读/写业务入口 + /admin 管理接口
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

支持的特征字段：`source`、`path`、`method`、`body`（写入口取正文**检查前缀**，长度由内容策略 `inspect_limit_bytes` 决定，默认 64KiB；读入口取前 512 字节）、`header:<名称>`、`query:<名称>`；缺失的头/查询按空串处理，不抛异常。关闭内容判定时 `body` 规则不参与求值。

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

## 三、带正文入口（POST/PUT/PATCH）

提交、上传类入口与读入口**共用同一套防护口径**，业务协议无需任何改动：客户端照常发 JSON、表单（urlencoded / multipart）或任意二进制。

### 业务入口（示例，业务侧自行解析正文）

| 方法 | 路径 | 内容类型 | 说明 |
| --- | --- | --- | --- |
| `POST` | `/api/submit/json` | `application/json` | JSON 提交，业务侧读原始字节后自行 `json.loads` |
| `PATCH` | `/api/submit/json` | `application/json` | 与 POST 完全相同的防护口径 |
| `POST` | `/api/submit/form` | `application/x-www-form-urlencoded` 或 `multipart/form-data` | 表单提交 |
| `PUT` | `/api/upload/binary` | `multipart/form-data` | 二进制文件上传 |

这些入口回显 `length`、`content_type` 与正文 `raw_sha256`，便于调用方/测试核对业务侧收到的内容与发送**逐字节一致**。

### 处理顺序（确定、可解释）

1. 豁免/管理路径直接透传；
2. 抽取来源、方法、路径、头、查询，并**同时取规则快照与内容策略快照**（之后整次处理只用这两个固定版本）；
3. **来源限流先行**：配额耗尽直接 `429`，不缓冲任何正文、不触达业务；
4. 有界接收正文（见下方两类上限），得到相互可区分的接收结论；
5. 超过检查上限无法完成内容判定时按内容策略处理（默认 fail-closed）；随后按内容策略决定是否做内容规则匹配；
6. 放行后把**与客户端所发完全一致**的正文原样回放给业务（长度/内容类型/字节不被消费、截断或改写）。

### 两类上限与可区分的容量/降级结论

- **接收上限 `receive_limit`（硬上限）**：声明 `Content-Length` 已超限时**不读取正文**直接拒绝；分块（chunked）正文在读取中越界也立即停止。结论为 **`413 body_too_large`（"内容太大不接受"）**。
- **检查上限 `inspect_limit`（检测范围）**：内容规则只匹配前 `inspect_limit` 字节。正文长度落在 `(inspect_limit, receive_limit]` 区间时，正文仍被完整接收，但无法完成内容判定，结论为 **`422 body_inspection_incomplete`（"内容太大无法完成内容判定"）**——与 `413` 明确区分。该结论默认 fail-closed（拒绝），管理侧可通过"关闭内容判定开关"显式放行此类正文（正文仍完整转发，只是不做内容规则匹配）。命中串若只可能出现在检查前缀之外，也会落到该结论，**不会被静默放行绕过**。
- **接收时间预算**：单请求正文接收超过 `REQUEST_DEFENSE_BODY_TIMEOUT_MS`（默认 10s）即 **`408 body_receive_timeout`**，不无限等待。
- **并发在途容量**：同时缓冲正文的请求数受 `REQUEST_DEFENSE_BODY_INGRESS_CONCURRENCY`（默认 32）限制；在接收预算内拿不到容量返回 **`503 body_ingress_busy`**，不无界排队、不拖垮服务。
- **客户端中途断连**：直接结束，不触达业务。

| 情况 | HTTP | 错误码（`reason`） | 业务是否执行 |
| --- | --- | --- | --- |
| 正文超过接收上限（声明/实际） | 413 | `body_too_large` | 否 |
| 超过检查上限、无法完成内容判定 | 422 | `body_inspection_incomplete` | 否（关闭内容判定后可放行） |
| 正文接收超时 | 408 | `body_receive_timeout` | 否 |
| 并发接收容量饱和 | 503 | `body_ingress_busy` | 否 |
| 来源配额耗尽 | 429 | `rate_limit_quota_exhausted` | 否 |
| 内容/特征规则拒绝 | 403 | `rule_match_deny` / `rule_conflict_deny` | 否 |

### 内存与耗时有界

- 完整正文写入 `SpooledTemporaryFile`，内存阈值等于检查上限；超过检查上限的部分**自动落盘**，因此**无论正文多大，防护层单请求内存占用都以检查上限为界**，不会把整个大对象堆在内存里；
- 检查前缀最多 `inspect_limit` 字节保存在内存，供内容规则与审计使用（审计仍只记录前 512 字节摘要及总长度 `body_length`、是否检查完整 `body_fully_inspected`）；
- 接收总耗时受单请求时间预算约束，并发缓冲受全局信号量约束，双重有界。

### 运行时容量与内容策略变更（无需重启）

- `GET /admin/content-policy`：查看当前内容策略版本与三项设置；
- `PUT /admin/content-policy`：**整体**提交 `inspect_limit_bytes` / `receive_limit_bytes` / `content_check_enabled`，服务端整体校验通过后在同一把锁内原子替换不可变快照，版本号 `+1`；
- **整集拒绝**：上限非正整数、`inspect_limit > receive_limit` 中任一情况，整个更新被拒绝（`422 invalid_content_policy`，带 `field` 与 `current_version`），**旧策略继续生效，不存在半更新**；
- 正在处理的请求在进入时取一次内容策略快照，随后整次接收、判定、审计都对应同一版本，**要么完整使用旧配置、要么完整使用新配置**，不会一半旧一半新；
- 单请求接收超时与并发在途容量为启动期配置（`REQUEST_DEFENSE_BODY_TIMEOUT_MS` / `REQUEST_DEFENSE_BODY_INGRESS_CONCURRENCY`）；运行时可调的是检查上限、接收上限与内容判定开关三项。

```bash
curl -X PUT http://127.0.0.1:8000/admin/content-policy \
  -H "Authorization: Bearer change-me" -H "Content-Type: application/json" \
  -d '{"inspect_limit_bytes":4096,"receive_limit_bytes":1048576,"content_check_enabled":true}'
```

### 兼容范围

- 仅对 `POST` / `PUT` / `PATCH` 启用有界正文接收与回放；`GET`/`DELETE` 等读入口行为与既有实现保持一致（无正文不提前消费接收通道）；
- 不改写任何请求头或正文：`Content-Length`、`Content-Type`、multipart boundary、二进制字节全部保持原样，回放仅可能按固定块（64KiB）切分 `http.request` 帧，业务侧用标准 `Request.body()`/`json()`/表单解析得到的完整内容与客户端所发一致；
- 中间件为纯 ASGI 实现，避免了 `BaseHTTPMiddleware` 在中间件内消费流后下游拿到空体的问题；
- 相关环境变量均有安全默认值，未设置时服务行为对既有读流量零变化。


### 规则集运行时变更（无需重启）

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
- `input`：来源、方法、路径、查询参数、**脱敏后**的请求头、body 检查摘要（至多 512 字节）、`body_length`（正文总字节数）与 `body_fully_inspected`（检查前缀是否覆盖完整正文）——足以复现判定；
- `basis`：`rule_version`、`content_policy_version`、每条规则的结论/优先级/动作/错误类型/耗时、限流剩余配额与 retry_after；
- `elapsed_ms`：单请求总耗时。

## 七、验证方法

```bash
uv run pytest -v          # 全量 133 个用例，单测日志会打印每个用例的输入与判定依据
```

重点场景：

- **带正文入口逐字节一致**：`tests/test_body_entrypoints.py::TestPassThroughFidelity`
  （JSON / urlencoded 表单 / multipart 二进制 / PATCH，断言业务侧 `raw_sha256` 与发送完全一致、长度与内容类型原样）；
- **限流/拒绝不触达业务**：`tests/test_body_entrypoints.py::TestBlockedNeverReachesBusiness`
  （打满配额后 POST 得 429、body 内容规则命中得 403）；
- **容量与降级**：`tests/test_body_entrypoints.py::TestCapacityAndDegradation`
  （声明/分块超限得 413、超过检查上限得 422，两类状态与原因严格可区分；
  接收超时 408 由 `tests/test_ingress.py` 与 ASGI 直连用例覆盖、并发饱和得 503）；
- **并发大正文**：`tests/test_body_entrypoints.py::TestConcurrentLargeBodies`
  （16 线程并发上传，断言无 5xx、小正文全部字节一致、大正文一律 422）与
  `test_policy_switch_under_traffic_never_half_updates`（策略切换与请求并发，只允许 200/422 且两套策略都被观测到）；
- **运行时内容策略**：`tests/test_body_entrypoints.py::TestRuntimeContentPolicy`
  与 `tests/test_policy.py`（整体生效、非法整体拒绝、版本单调、快照自洽、开关可降级）；
- **有界接收/回放**：`tests/test_ingress.py`（前缀严格有界、落盘后内存有界、超时释放槽位、容量饱和不误释放、回放逐字节一致）；
- **并发冲击（读）**：`tests/test_ratelimiter.py::test_concurrent_burst_no_overcount_no_overgrant`、
  `tests/test_engine.py::TestConcurrentCountingAndRuleChanges`、`tests/test_app.py::TestConcurrencyViaHttp`；
- **异常规则 / 非法规则集**：`tests/test_engine.py::TestRuleFaultIsolation`、
  `tests/test_rules_store.py::TestRuleStore::test_invalid_set_rejected_entirely`、
  `tests/test_app.py::TestRuntimeRuleChanges::test_invalid_rule_set_rejected_entirely`。

手动验证：

```bash
REQUEST_DEFENSE_ADMIN_TOKEN=change-me REQUEST_DEFENSE_RATE_LIMIT=3 \
  uv run uvicorn main:app
curl -s localhost:8000/api/echo                 # 200
for i in 1 2 3 4; do curl -s -o /dev/null -w "%{http_code}\n" localhost:8000/api/echo; done
# 200 200 200 429（第 4 个起 rate_limit_quota_exhausted）

# 带正文入口（JSON 原样到达业务，回显 sha256/length/content_type）
curl -s -X POST localhost:8000/api/submit/json \
  -H "Content-Type: application/json" -d '{"name":"hello"}'

# 运行时调整检查/接收上限（无需重启）
curl -s -X PUT localhost:8000/admin/content-policy \
  -H "Authorization: Bearer change-me" -H "Content-Type: application/json" \
  -d '{"inspect_limit_bytes":4096,"receive_limit_bytes":1048576,"content_check_enabled":true}'
```

可设置的环境变量（均带安全默认值）：

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `REQUEST_DEFENSE_RATE_LIMIT` / `REQUEST_DEFENSE_WINDOW_MS` | 100 / 60000 | 每窗口来源配额 / 窗口毫秒 |
| `REQUEST_DEFENSE_MAX_RULES` / `REQUEST_DEFENSE_TIMEOUT_MS` | 64 / 200 | 规则数量上限 / 规则求值预算 ms |
| `REQUEST_DEFENSE_FAIL_OPEN` | `0` | 规则故障时是否降级放行 |
| `REQUEST_DEFENSE_INSPECT_LIMIT_BYTES` | 65536 | 内容检查上限（检测范围，也等于单请求内存缓冲阈值） |
| `REQUEST_DEFENSE_RECEIVE_LIMIT_BYTES` | 2097152 | 正文接收硬上限（超过即 413） |
| `REQUEST_DEFENSE_CONTENT_CHECK_ENABLED` | `1` | 是否启用内容判定（关闭后超限正文可转发，仅不做内容规则匹配） |
| `REQUEST_DEFENSE_BODY_TIMEOUT_MS` | 10000 | 单请求正文接收时间预算（超过即 408） |
| `REQUEST_DEFENSE_BODY_INGRESS_CONCURRENCY` | 32 | 同时缓冲正文的请求数上限（饱和即 503） |
| `REQUEST_DEFENSE_ADMIN_TOKEN` | 空 | 管理令牌；未配置时管理能力全部关闭 |

