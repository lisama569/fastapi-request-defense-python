# 本地请求防护层（FastAPI Request Defense）

在现有 HTTP 服务前增加的一层**本地请求防护**，把三件事结合起来并给出一致、可解释的处置结论：

1. **来源限流** —— 按来源标识的滑动时间窗配额；
2. **请求特征规则** —— 多条规则组合判定（命中/未命中/冲突）；
3. **判定审计** —— 每次判定输出结论、原因、依据与输入摘要。

所有入口（除豁免的运维路径与管理路径外）都经过同一套中间件，因此正常、被限流、可疑流量的处置口径完全一致；**带正文入口（POST/PUT/PATCH）与读入口共用同一套来源额度、特征规则与审计口径**，放行时业务侧拿到客户端原始正文（不消费、不截断、不改写）。

## 目录结构

```
request_defense/
  types.py         # Decision / Reason / RuleVerdict / RuleConfig / RequestFeatures 等核心类型
  ratelimiter.py   # 线程安全的滑动时间窗限流器
  rule.py          # 单条特征规则：编译（正则校验）与无状态求值
  store.py         # 规则集不可变快照 + 整体校验 + 原子替换（版本单调递增）
  policy.py        # 正文容量/内容策略（BodyPolicy）：不可变快照 + 整体校验 + 原子替换
  bodyguard.py     # 完整有界接收（内存+磁盘假脱机）+ ASGI receive 按原分片重放 + 接收上限/超时
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

带正文入口与 GET 等读入口走**完全相同**的防护链：先做来源额度预检（被限流直接 429，不读取正文、不执行业务），再做**与送达方式无关**的有界正文接收与内容判定，最后才进入业务。

### 3.0 判定与“正文怎么送达”完全无关（整包 / 分片 / 流式）

防护层**先把正文完整、有界地接收下来，再下结论**（读到 ASGI `http.request` 的 `more_body=False` 才分类）。因此同一份正文，无论客户端：

- 一次性发完整包（`bytes` + `Content-Length`）；
- 分多片推送、带长度声明（多次 `http.request`，`Content-Length` 已知）；
- **不带长度**一段段推（`Transfer-Encoding: chunked`，无 `Content-Length`）；
- 第一片就是整段、或每片仅 1 字节；

最终结论严格一致：

| 正文总长度 | 结论（任何送达方式都相同） |
| --- | --- |
| `< inspect_limit`、`== inspect_limit` | 放行（边界不误伤） |
| `inspect_limit < 长度 <= receive_limit` | **403 `content_inspection_incomplete`**（无法完成内容判定） |
| `> receive_limit` | **413 `body_too_large`**（不接受） |

> 历史实现只预取检查前缀、用 `more_body` 标志“再探测一个事件”来猜测后面还有没有数据。但不同 ASGI 服务器对同一份正文给出的分片/标志组合不同（例如整包可能是 `100B+more=True` 后接空收尾，也可能直接 `100B+more=False`），导致分片/流式发送时超检查上限的正文被误判成“恰好读满、没问题”而**静默放行**。新实现读完整个正文再分类，从根上消除了这一类差异。

### 3.1 放行即透传：业务侧拿到原始正文

防护层在**纯 ASGI 层包装 `receive`**（不使用会缓冲整个请求体的 BaseHTTPMiddleware）：

- 正文先写入一个有界缓冲（小正文驻留内存，超过检查上限的部分**自动假脱机到临时文件**，见 3.3），放行时按**接收时的原始 ASGI 分片边界**逐段重放给下游，字节序、长度、内容类型与客户端发出的**完全一致**（包括跨边界分片，不再拆分/合并改写）；
- 因此业务侧 `await request.body() / request.json() / request.form()` 不需要任何改动（**调用方协议不变**），不会出现“防护层提前消费导致业务读到空体/残体”；
- 被限流（429）、被规则拒绝（403）、超检查上限（403）、超接收上限（413）等情况下业务入口**绝不会被执行**（测试用副作用端点 `POST /api/side-effect` 断言）——即使是无 `Content-Length` 的分块流，413 也在**接收阶段、进入业务之前**给出，超量字节不会透传给业务。

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

### 3.2 两个上限：语义严格区分，且都在进业务之前判定

| 策略字段 | 含义 | 触发结果 |
| --- | --- | --- |
| `inspect_limit`（检查上限，默认 64 KiB） | 内容规则的匹配范围。只有正文完整长度不超过它时，才对**整份正文**完成内容判定 | 正文超过它但未超接收上限 => **403 `content_inspection_incomplete`**：“太大，无法完成内容判定”（默认 fail-closed，不猜测未检查部分） |
| `receive_limit`（接收上限，默认 1 MiB） | 服务愿意接收的正文总大小 | 超过它 => **413 `body_too_large`**：“太大，不接受”，业务不执行 |

- **检查范围之外的内容不会被当成“检查过了、没问题”**：只要总长度 `> inspect_limit`，就一定给出 403，写在第 65 字节之后的正文规则不可能因为分片/流式发送而被绕过；
- **两类“太大”始终可区分**：HTTP 状态码（403 vs 413）与原因码两个维度都不同；审计记录的 `body_meta` 给出 `content_length / content_type / inspected_bytes / total_bytes / exceeds_inspect_limit / inspect_limit / receive_limit`；
- **接收上限对任何送达方式生效**：声明的 `Content-Length > receive_limit` 时**一个字节都不读**直接 413；无 `Content-Length` 的分块流在接收过程中按**最新**接收上限累计计量，越界立即 413（不再依赖业务侧透传读取才发现）；
- 当一份正文同时满足“超检查上限”与“超接收上限”时，结论取更严的 **413**（先检查接收上限）。

边界语义（自动测试覆盖）：正文长度 `< inspect_limit` 与 `== inspect_limit` 正常进入内容判定（边界不误伤）；`> inspect_limit` 且内容判定开关开启时给出 `content_inspection_incomplete`；`== receive_limit` 仍可接收，`> receive_limit` 才 413。以上结论对整包、分多片、无长度流式**逐一参数化断言一致**。

### 3.3 有界性：内存、耗时、并发都有上限

- **内存有界（与正文总大小解耦）**：正文写入 `tempfile.SpooledTemporaryFile`，驻留内存阈值取本次请求入口时的 `inspect_limit`——放行的小正文全程留内存（快路径），超过检查上限的部分自动假脱机到操作系统临时文件。单请求防护侧驻留内存 ≤ `inspect_limit`，最坏总驻留 ≈ `inflight × inspect_limit`，不会因为客户端推一个超大正文就把它整体堆进内存；请求结束（放行重放完成或拒绝）立即关闭并删除临时文件；
- **耗时有界**：每次 `receive` 受 `REQUEST_DEFENSE_BODY_TIMEOUT_MS`（默认 5000ms）约束，慢分片发送不能挂死连接，超时返回 **408 `body_receive_timeout`**；
- **并发有界**：在途带正文请求受 `REQUEST_DEFENSE_BODY_INFLIGHT`（默认 32）名额限制，名额耗尽立即 **503 `body_concurrency_limited`** 背压，不排队堆积；
- **不绕过来源额度**：无论正文多大、怎么分片，限流预检都最先执行，且与读入口共用同一窗口与配额（并发分块大正文的测试断言同来源仍精确限额）。

### 3.4 运行时容量与内容策略变更（不重启）

- `GET /admin/policy`：查看当前 `version / inspect_limit / receive_limit / content_check_enabled`；
- `PUT /admin/policy`：整体校验后在同一把锁内**原子替换**不可变快照，版本号 `+1`；
- 非法配置（非正整数、`inspect_limit > receive_limit`、超过硬天花板 1 MiB/16 MiB、布尔非法）一律 **422 `invalid_policy`**（带 `field` 与 `current_version`），**旧策略继续生效，不会半更新**；
- **对正在处理的分段/流式请求也完整按新策略生效**：正文接收期间每收到一个 ASGI 分片就重新取一次最新策略快照，接收上限与检查上限都按**当前最新值**计量和分类——请求处理途中调小 `receive_limit`，后续尚未到达的分片立即按新上限判 413；调大/调小 `inspect_limit`，最终的“完整长度 vs 检查上限”结论按新上限给出，不会出现“前半段按旧策略、后半段按新策略”。响应与审计中的 `policy_version` 即最终分类实际使用的版本；
- `content_check_enabled=false` 时 `field_name == "body"` 的规则整体不参与判定（来源/路径/头/查询规则照常），便于在确认入口安全后临时对大正文放开内容判定；**接收上限始终生效**（即使关闭内容判定，超 `receive_limit` 的分块流仍在进业务之前被 413 拒绝）。

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
- `input`：来源、方法、路径、查询参数、**脱敏后**的请求头、body 检查前缀（日志中截断到前 512 字节）与 `body_meta`（长度/内容类型/检查字节数/是否超过检查上限/两档上限）——足以复现判定，且不记录完整正文；
- `basis`：`rule_version`、每条规则的结论/优先级/动作/错误类型/耗时、限流剩余配额与 retry_after；
- `elapsed_ms`：单请求总耗时。

## 七、验证方法

```bash
uv run pytest -v          # 全量 147 个用例，单测日志会打印每个用例的输入与判定依据
# 只跑分段/流式一致性
uv run pytest tests/test_body_streaming.py tests/test_bodyguard.py -v
```

重点场景：

- **分段/流式一致性**：`tests/test_body_streaming.py`
  - `TestStreamingVerdictConsistency::test_same_body_same_verdict_regardless_of_delivery`：
    同一份正文（0/1/63/64/65/100/256/257/300/400 字节）× 10 种送达方式
    （整包、1/7/32/64 字节分片带或不带 `Content-Length`、第一片整段），
    断言结论完全一致：≤64 放行、65~256 一律 403、>256 一律 413；
  - `test_allowed_streamed_body_arrives_byte_exact`：分片/流式放行时业务收到的字节与发送逐字节一致；
  - `test_rejected_streamed_body_never_reaches_business`：403/413 时副作用端点计数为 0；
  - `test_chunked_receive_limit_classifies_413_not_403` / `..._declared_...`：
    无长度/带长度分块超**接收**上限必须是 413，不能被误判成 403；
  - `TestRulesBehindInspectBoundary`：命中点写在检查范围之后的正文规则，
    分片发送时也不能静默放行（fail-closed 403）；
  - `TestStreamingMultiSegment`：多种分片大小拼接的多段正文逐字节一致；
  - `TestStreamingConcurrentLargeBodies`：并发分块大正文结论有界（200/503/403/413，无 5xx、
    不出现“分片就 200 放行”），且同来源并发不绕过滑动窗口配额；
  - `TestStreamingSlowSender`：慢分片推送命中 408 且业务不执行；
  - `TestRuntimePolicyDuringSegmentedRequest`：**在途**分段请求处理途中调小接收上限
    （后续片 413）、调大/调小检查上限（结论按新策略完整生效），业务不被半旧半新绕过；
- **带正文入口（整包/带长度，既有用例零回归）**：`tests/test_body.py`
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
- **有界接收原语**：`tests/test_bodyguard.py`（不经过 HTTP 直接测接收/重放：
  判定与分片方式无关、跨边界分片字节序、无 Content-Length 分块重放、声明超限零读取、
  **分块超限在接收阶段直接 BodyTooLarge**、恰好等于上限不误伤、超时、
  **在途策略切换按最新上限计量**、超阈值正文假脱机临时文件后仍逐字节重放、
  `http.disconnect` 原样只重放一次、PolicyStore 原子性）；
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

**手动复现分段/流式（无 `Content-Length`，每片之间停顿）**——结论必须与整包一致：

```bash
# 100 字节，分 10 片、Transfer-Encoding: chunked、每片间隔 0.2s
# 旧实现这里会错误地 200 放行；修复后与整包一致 => 403 content_inspection_incomplete
( for i in $(seq 1 10); do
    printf 'a\n0a\r\n'; head -c 10 /dev/zero | tr '\0' 'y'; printf '\r\n'
    sleep 0.2
  done
  printf '0\r\n\r\n'
) | curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    localhost:8000/api/upload/raw -H "Transfer-Encoding: chunked" --data-binary @-

# 更直观的方式：用 Python 迭代器分多次推送（自动化测试即采用这种方式）
uv run python - <<'PY'
import asyncio, httpx
from request_defense.app import create_app
from request_defense.config import DefenseConfig
app = create_app(DefenseConfig(body_inspect_limit=64, body_receive_limit=256, rate_limit=1000))
async def main():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as ac:
        async def chunks(data, n):
            for i in range(0, len(data), n):
                await asyncio.sleep(0.05); yield data[i:i+n]
        for label, data, n in [("inspect", b"y"*100, 3), ("receive", b"z"*400, 100)]:
            r = await ac.post("http://t/api/upload/raw", content=chunks(data, n),
                              headers={"X-Forwarded-For": "10.0.0.1"})
            print(label, r.status_code, r.json()["error"])   # inspect 403 / receive 413
asyncio.run(main())
PY
```
