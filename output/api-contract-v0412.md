# 御端（YuDuan）中枢 REST API 契约 v0.4.12

> 提取自后端中枢 Go 代码（`dev/internal/hub/` 下 `wave3.go` / `wave4.go` / `wave5a.go` / `wave5b.go`）。
> 所有端点前缀均为 `/api/v1/`。所有 JSON 响应统一信封：成功 `{ "code": 0, ... 业务字段 }`；失败 `{ "code": <非零错误码>, "message": "<描述>" }`。
> 错误码为各模块自定义整数（如 swdist 3001-3024、filesync/batchcmd 4010-4040、合规 5201-5242、外设/NAC 2501-2521）。
>
> **通用约定**
> - RBAC 守卫：`h.guard(perm, handler)` 包裹；下方每个端点标注其 `auth.PermXxx` 守卫名。
> - 时间字段统一为 RFC3339 UTC（JSON 经 `time.Time` 默认序列化，带 `Z`）。
> - 列表端点一般按稳定字段排序，并返回 `{ "total": N, "<集合名>": [...] }`。

---

## 1. 分发任务（swdist）— `wave3.go`
**全部端点守卫：`auth.PermSoftwareMgmt`**（路由：`mux.HandleFunc("/api/v1/swdist/...", h.guard(auth.PermSoftwareMgmt, ...))`）

### 1.1 模板库 `swdist/templates`

- **GET** `/api/v1/swdist/templates`
  - 响应：`{ "code":0, "total":int, "templates":[ W3Template ] }`
  - `W3Template`: `{ "platform":string, "pkg_type":string, "args":string, "desc":string?, "builtin":bool, "updated_at":time, "updated_by":string? }`
  - 列表按 `platform` 升序、再按 `pkg_type` 升序。

- **POST** `/api/v1/swdist/templates` （**upsert**：按 platform+pkg_type 创建或覆盖）
  - 请求：`{ "platform":string(必填), "pkg_type":string(必填), "args":string, "desc":string }`
  - 校验：`platform`、`pkg_type` 必填；`pkg_type` 须为 `proto.PkgTypes()` = `msi|exe|dmg|pkg|deb|rpm|zip`；`platform` 归一为小写（`windows|macos|linux`）。
  - 响应：`{ "code":0, "template": W3Template }`

- **GET** `/api/v1/swdist/templates/{platform}/{pkg_type}` （详情）
  - 响应：`{ "code":0, "template": W3Template }`；不存在返回 `code:3004`。

- **PUT / POST** `/api/v1/swdist/templates/{platform}/{pkg_type}` （更新）
  - 请求：`{ "args":string, "desc":string }`（均可为空，仅更新传入字段语义同 upsert）
  - 响应：`{ "code":0, "template": W3Template }`

- **DELETE** `/api/v1/swdist/templates/{platform}/{pkg_type}` （删除）
  - 响应：`{ "code":0, "ok":true }`；不存在返回 `code:3004`。

- **POST** `/api/v1/swdist/templates/reset` （恢复内置默认模板）
  - 响应：`{ "code":0, "ok":true, "total":int }`

- **GET** `/api/v1/swdist/templates/resolve?platform=&pkg_type=&custom_args=` （解析最终静默参数）
  - 查询参数：`platform`(必填)、`pkg_type`(必填)、`custom_args`(可选)
  - 响应：`{ "code":0, "platform":string, "pkg_type":string, "template_args":string, "custom_args":string, "resolved_args":string, "found":bool }`
  - 规则：`custom_args` 非空时 `resolved_args = custom_args`，否则取模板 `args`。

### 1.2 分发任务 `swdist/tasks`

- **GET** `/api/v1/swdist/tasks` （列表）
  - 响应：`{ "code":0, "total":int, "tasks":[ W3DistTask ] }`（按 `created_at` 倒序；列表接口 `records` 为 nil）。

- **POST** `/api/v1/swdist/tasks` （创建）
  - 请求（字段默认值见校验）：
    ```
    {
      "repo_id":string,            // 仓库软件包 ID（可选；填了会补全 version/platform/url）
      "software_url":string,       // 外部下载地址
      "sha256":string,             // 外部 URL 强制完整性摘要（仓库包自动填充）
      "pkg_name":string(必填),     // 包名
      "version":string,
      "platform":string,           // windows/macos/linux/any
      "pkg_type":string,           // msi/exe/dmg/pkg/deb/rpm/zip（缺省按扩展名推断）
      "custom_args":string,        // 覆盖模板静默参数
      "target_version":string,     // 期望达标版本（用于比对/卸载旧版）
      "uninstall_old":bool,        // 是否先卸载旧版
      "targets": W3Targets,        // 见下
      "schedule_at":string,        // RFC3339 或秒级时间戳；空=立即
      "mode":string,               // forced(默认)|optional
      "max_retry":int,             // <=0 取默认
      "retry_interval_sec":int,     // <=0 取默认
      "retry_backoff":string        // fixed(默认)|exponential
    }
    ```
    `W3Targets`: `{ "device_ids":[string]?, "group":{ "department":string?, "floor":string?, "batch":string?, "tag":string? }?, "all":bool? }`
  - 校验：`pkg_name` 必填；`targets` 须指定 `device_ids` / `group` / `all` 之一；`mode` 仅 `forced` 或 `optional`。
  - 响应：`{ "code":0, "task": W3DistTask }`（带 `records`）。

- **GET** `/api/v1/swdist/tasks/{id}` （详情）
  - 响应：`{ "code":0, "task": W3DistTask }`（含 `records`）。

- **POST** `/api/v1/swdist/tasks/{id}/cancel` （取消任务）
  - 响应：`{ "code":0, "ok":true }`；不存在/已结束返回 `code:3022`。

- **GET** `/api/v1/swdist/tasks/{id}/records` （逐设备执行记录）
  - 响应：`{ "code":0, "total":int, "records":[ W3Record ] }`。

- **POST** `/api/v1/swdist/tasks/{id}/records/{rid}/confirm` （终端用户确认，仅 `optional` 模式用）
  - 请求：`{ "confirm":bool }`
  - 响应：`{ "code":0, "ok":true }`。

**`W3DistTask` 字段**（来自 struct 标签）：
`id, repo_id?, software_url?, sha256?, pkg_name, version?, platform?, pkg_type?, custom_args?, target_version?, uninstall_old?, targets, schedule_at?, mode, max_retry, retry_interval_sec, retry_backoff?, state, created_by, created_at, started_at?, finished_at?, total, success, failed, skipped, records?`

**`W3Record` 字段**：
`id, task_id, device_id, device_name?, state, attempt, exit_code, output?, reason?, current_version?, uninstalled?, confirmed?, next_retry_at?, created_at, updated_at`

**任务状态 `state` 枚举**：`pending`(已创建/待到点) · `running`(派发中) · `done`(全部成功/跳过) · `partially_done` · `failed` · `cancelled`

**记录状态 `state` 枚举**：`pending` · `dispatching` · `retry_waiting` · `success` · `failed` · `permanently_failed` · `skipped` · `awaiting_confirm` · `cancelled`

> ⚠️ 注：代码当前**仅注册**了列表/创建/详情/取消/记录/确认/模板端点。需求中提到的「灰度」「回滚」「任务删除」**在 `wave3.go` 中未实现**，前端勿依赖。

---

## 2. 文件同步（filesync）— `wave4.go`
**全部端点守卫：`auth.PermDeviceCmd`**

### 2.1 `filesync/tasks`

- **GET** `/api/v1/filesync/tasks` （列表）
  - 响应：`{ "code":0, "total":int, "tasks":[ W4FileTask ] }`（按 `created_at` 倒序）。

- **POST** `/api/v1/filesync/tasks` （创建）
  - 请求：`{ "kind":string(必填, push|pull|sync), "name":string, "source":string, "dest":string, "device_ids":[string](必填), "interval_sec":int }`
  - 校验：`kind∈{push,pull,sync}`；`device_ids` 必填；`push`/`sync` 需 `source`；`pull` 需 `dest`（`name` 缺省自动生成）。
  - 响应：`{ "code":0, "id":string, "task": W4FileTask }`。

- **GET** `/api/v1/filesync/tasks/{id}` （详情）
  - 响应：`{ "code":0, "task": W4FileTask }`。

- **POST** `/api/v1/filesync/tasks/{id}/cancel` （取消，仅 `pending`/`running` 可取消）
  - 响应：`{ "code":0 }`；不存在返回 `code:4040`。

**`W4FileTask` 字段**：
`id, kind, name, source?, dest?, device_ids?, interval_sec?, state, result?, error?, created_at, updated_at, records?`

**`W4FileRec` 字段**（单设备执行结果）：
`device_id, state, bytes?, sha256?, msg?`

**任务状态 `state` 枚举**：`pending` · `running` · `success` · `failed` · `cancelled`
**记录状态 `state` 枚举**：`success` · `failed` · `skipped`

> ⚠️ 无暂停/恢复之外的「删除」；取消即终态。创建后**立即异步执行**（`go h.w4RunFileTask`）。

---

## 3. 批量命令（batchcmd）— `wave4.go`
**全部端点守卫：`auth.PermDeviceCmd`**

### 3.1 `batchcmd/tasks`

- **GET** `/api/v1/batchcmd/tasks` （列表）
  - 响应：`{ "code":0, "total":int, "tasks":[ W4BatchTask ] }`（按 `created_at` 倒序）。

- **POST** `/api/v1/batchcmd/tasks` （创建）
  - 请求：`{ "script":string(必填), "device_ids":[string](必填), "keyword":string, "confirmed":bool }`
  - 逻辑：若命中危险命令规则（`w4MatchDanger`）且 `confirmed=false` → 仅创建 `awaiting_approval` 任务、不执行，并返回 `danger` 提示；`confirmed=true` 才执行。
  - 响应（正常）：`{ "code":0, "id":string, "task": W4BatchTask }`
  - 响应（命中危险待确认）：`{ "code":0, "id":string, "task": W4BatchTask, "danger":true, "rule":string, "confirmed":false, "message":string }`

- **GET** `/api/v1/batchcmd/tasks/{id}` （详情）
  - 响应：`{ "code":0, "task": W4BatchTask }`。

- **POST** `/api/v1/batchcmd/tasks/{id}/confirm` （危险命令二次确认后放行）
  - 请求：`{ "confirmed":bool }`
  - 响应：`{ "code":0 }`（仅当 `danger && state==awaiting_approval && confirmed` 时执行）。

**`W4BatchTask` 字段**：
`id, script, device_ids, keyword?, danger, danger_rule?, confirmed, approval_id?, state, created_by, created_at, results:[W4BatchItem], summary:W4BatchSummary`

**`W4BatchItem`**：`device_id, state, exit_code:int, output?, abnormal:bool`
**`W4BatchSummary`**：`total, success, failed, abnormal`

**任务状态 `state` 枚举**：`pending` · `awaiting_approval` · `running` · `success` · `failed` · `cancelled`

> ⚠️ 代码未注册「停止」「删除」端点；`keyword` 默认匹配 `error|fail|denied|not found|permission` 用于判定 `abnormal`。

---

## 4. 安全合规（整合页面）

### 4.1 合规基线 `compliance/baselines` — `wave5a.go`
- 列表/详情：`GET` 守卫 `auth.PermDeviceView`；创建/更新/删除：`POST`/`PUT`/`DELETE` 守卫 `auth.PermDeviceCmd`。

- **GET** `/api/v1/compliance/baselines` — 列表
  - 响应：`{ "code":0, "total":int, "baselines":[ ComplianceBaseline ] }`

- **POST** `/api/v1/compliance/baselines` — 创建
  - 请求体即 `ComplianceBaseline`：`{ "name":string(必填), "platform":string?, "department":string?, "enabled":bool, "rules":[ BaselineRule ](必填) }`
  - 响应：`{ "code":0, "baseline": ComplianceBaseline }`

- **GET** `/api/v1/compliance/baselines/{id}` — 详情；**PUT/POST** — 更新（部分字段；`?enabled=false` 可关闭）；**DELETE** — 删除 `{ "code":0, "id":string }`

**`ComplianceBaseline`**：`id, name, platform?, department?, enabled:bool, rules:[BaselineRule], created_at, updated_at`
**`BaselineRule`**：`key:string, name?, operator:string(eq|ne|on|off|gte|lte|exists), expected?, weight:int, severity?(info|warning|critical)`

- **GET** `/api/v1/compliance/overview` （评估概览，`PermDeviceView`）
  - 响应 `overview`：`{ "devices":int, "scored_devices":int, "avg_score":int, "passed_devices":int, "failed_devices":int, "violations":int, "unknowns":int, "by_category":map<string,int>, "by_severity":map<string,int>, "worst_devices":[{ "device_id","device_name","score","violations" }], "baselines":int, "blacklist_rules":int, "blacklist_hits":int, "vuln_rules":int, "vuln_open":int }`

- **POST** `/api/v1/compliance/report` （上报/软件清单补录，`PermDeviceCmd`）
  - 请求 `ComplianceReportPayload`：`{ "device_id":string(必填), "platform"?, "collected_at"?:int64, "items":[ ComplianceItem ], "software":[ InstalledSoftware ]? }`
  - 响应：`{ "code":0, "device_id":string, "compliance":DeviceCompliance?, "blacklist_hits":int, "vuln_items":int }`

- **GET** `/api/v1/compliance/violations?device_id=&category=&severity=` （违规列表，`PermDeviceView`，支持过滤）
  - 响应：`{ "code":0, "total":int, "violations":[ { "device_id","device_name","key","name","category","severity","expected","actual","detail" } ] }`

- **GET** `/api/v1/compliance/devices?department=&platform=` （设备合规列表，`PermDeviceView`，支持按部门/平台过滤）
  - 响应：`{ "code":0, "total":int, "devices":[ { "device_id","device_name","platform","department","score":int,"violations":int,"baseline_id","updated_at" } ] }`

- **GET** `/api/v1/compliance/devices/{id}` （设备合规详情，`PermDeviceView`）→ `{ "code":0, "compliance": DeviceCompliance }`
- **POST** `/api/v1/compliance/devices/{id}/collect` （触发采集，`PermDeviceCmd`）→ `{ "code":0, "compliance": DeviceCompliance }`

**`DeviceCompliance`**：`device_id, device_name?, platform?, department?, baseline_id?, score:int(0-100，-1=无数据), items:[ComplianceItem], violations:[ComplianceViolation], unknowns:[ComplianceViolation], updated_at`
**`ComplianceItem`**：`key, name, category, state(pass|fail|unknown), actual, expected?, detail?`
**`ComplianceViolation`**：`key, name, category, severity, expected, actual, detail?, weight:int, state(fail|unknown)`

**枚举**
- 合规分类 `category`：`patch`(系统补丁) · `antivirus`(杀毒/EDR) · `firewall`(防火墙) · `screensaver`(屏保/锁屏) · `disk_encrypt`(磁盘加密)
- 合规项 `state`：`pass` · `fail` · `unknown`
- 严重度 `severity`：`info` · `warning` · `critical`

### 4.2 违规软件黑名单 `blacklist/rules` — `wave5a.go`
- 列表/详情：`GET` 守卫 `PermDeviceView`；创建/更新/删除/导入：`POST`/`PUT`/`DELETE` 守卫 `PermSoftwareMgmt`；导出：`GET` 守卫 `PermDeviceView`。

- **GET** `/api/v1/blacklist/rules` — 规则列表 `{ "code":0, "total":int, "rules":[ BlacklistRule ] }`
- **POST** `/api/v1/blacklist/rules` — 创建（校验：`pattern` 必填；`match_type` 默认 `exact`；`action` 默认 `alert`；`severity` 默认 `warning`）
  - 请求 `BlacklistRule`：`{ "name":string, "match_type":string(exact|contains|regex), "pattern":string(必填), "severity":string(info|warning|critical), "action":string(alert|block|uninstall), "enabled":bool }`
  - 响应：`{ "code":0, "rule": BlacklistRule }`
- **GET** `/api/v1/blacklist/rules/{id}` — 详情；**PUT/POST** — 更新（`?enabled=false` 可关闭）；**DELETE** — 删除 `{ "code":0, "id":string }`
- **POST** `/api/v1/blacklist/import` — 批量导入 `{ "rules":[ BlacklistRule ] }` → `{ "code":0, "imported":int }`
- **GET** `/api/v1/blacklist/export` — 导出规则 `{ "code":0, "total":int, "rules":[ BlacklistRule ] }`
- **GET** `/api/v1/blacklist/hits?device_id=&rule_id=` （命中记录，`PermDeviceView`）→ `{ "code":0, "total":int, "hits":[ BlacklistHit ] }`

**`BlacklistRule`**：`id, name, match_type, pattern, severity, action, enabled:bool, created_at, updated_at`
**`BlacklistHit`**：`id:int64, rule_id, rule_name, device_id, device_name?, software, version?, severity, action, action_taken, detected_at`

> 另注册但未列入主清单的端点（可用）：`GET /api/v1/blacklist/by-device`（按设备聚合命中）、`GET /api/v1/blacklist/by-software`（按软件聚合命中）、`POST /api/v1/blacklist/scan/{id}`（对设备重新做黑名单匹配，可选 body `{ "software":[InstalledSoftware] }`）。

### 4.3 漏洞规则 `vuln/rules` — `wave5a.go`
- 列表/详情：`GET` 守卫 `PermDeviceView`；创建/更新/删除/导入/扫描/例外：`POST`/`PUT`/`DELETE` 守卫 `PermSoftwareMgmt`；导出/汇总/项：`GET` 守卫 `PermDeviceView`。

- **GET** `/api/v1/vuln/rules` — 规则列表 `{ "code":0, "total":int, "rules":[ VulnRule ] }`
- **POST** `/api/v1/vuln/rules` — 创建（校验：`software` 与 `cve` 必填；`severity` 默认 `warning`）
  - 请求 `VulnRule`：`{ "cve":string(必填), "software":string(必填), "affected_versions":string, "severity":string, "fix_version":string, "advisory"?:string, "enabled":bool }`
- **GET** `/api/v1/vuln/rules/{id}` — 详情；**PUT/POST** — 更新；**DELETE** — 删除
- **POST** `/api/v1/vuln/rules/import` — 批量导入 `{ "rules":[ VulnRule ] }` → `{ "code":0, "imported":int }`

- **GET** `/api/v1/vuln/items?device_id=&cve=&severity=&state=` （漏洞项，`PermDeviceView`，多条件过滤）→ `{ "code":0, "total":int, "items":[ VulnItem ] }`
- **GET** `/api/v1/vuln/items/{id}` — 详情；**POST** `/api/v1/vuln/items/{id}/accept` — 接受风险（状态置 `accepted`）→ `{ "code":0, "item": VulnItem }`
- **POST** `/api/v1/vuln/scan/{id}` — 重新扫描（`PermSoftwareMgmt`，可选 body `{ "software":[InstalledSoftware] }`）→ `{ "code":0, "device_id":string, "items":[VulnItem], "total":int }`
- **GET** `/api/v1/vuln/summary` — 聚合视图（`PermDeviceView`）→ `{ "code":0, "summary":{ "open":int, "by_state":map, "by_severity":[{ "key","count" }], "by_cve":[...], "by_device":[...] } }`

- **GET/POST** `/api/v1/vuln/exceptions` — 例外名单（GET `PermDeviceView` / POST `PermSoftwareMgmt`）
  - POST 请求 `VulnException`：`{ "software"?:string, "cve"?:string, "device_id"?:string, "reason"?:string }`（`software` 与 `cve` 至少其一）；响应 `{ "code":0, "exception": VulnException }`
  - GET 响应：`{ "code":0, "total":int, "exceptions":[ VulnException ] }`

- **GET/POST** `/api/v1/vuln/tasks` — 补丁修复任务（GET `PermDeviceView` / POST `PermSoftwareMgmt`）
  - POST 请求 `PatchTask`（创建）：`{ "device_id":string(必填), "software":string(必填), "target_version"?:string, "repo_item_id"?:string, "item_ids":[string]?, "note"?:string }`；`item_ids` 为空时自动关联该设备该软件的全部 `open` 漏洞项，`target_version` 缺省取 `fix_version`。
  - 响应：`{ "code":0, "task": PatchTask }`
- **GET** `/api/v1/vuln/tasks/{id}` — 详情（`PermDeviceView`）
- **POST** `/api/v1/vuln/tasks/{id}/dispatch` — 下发修复（`PermSoftwareMgmt`）→ `{ "code":0, "task":PatchTask, "dispatched":bool }`
- **POST** `/api/v1/vuln/tasks/{id}/verify` — 校验是否达标（`PermSoftwareMgmt`）→ `{ "code":0, "task":PatchTask, "patched":bool }`

**`VulnRule`**：`id, cve, software, affected_versions, severity, fix_version, advisory?, enabled:bool, created_at, updated_at`
**`VulnItem`**：`id, rule_id, device_id, device_name?, software, version, cve, severity, fix_version, advisory?, state(open|patched|accepted), task_id?, detected_at, updated_at`
**`VulnException`**：`id, software?, cve?, device_id?, reason?, created_at`
**`PatchTask`**：`id, device_id, device_name?, software, target_version, repo_item_id?, item_ids:[string], state(pending|dispatched|closed|failed), note?, result?, created_at, updated_at`

**枚举**
- 漏洞项 `state`：`open` · `patched` · `accepted`
- 修复任务 `state`：`pending`(已创建) · `dispatched`(已下发) · `closed`(达标) · `failed`
- 严重度 `severity`：`info` · `warning` · `critical`

### 4.4 外设策略 `peripheral/policies` — `wave5b.go`
- 列表/详情/状态：`GET` 守卫 `PermDeviceView`；创建/更新/删除/按策略下发：`POST`/`PUT`/`DELETE` 守卫 `PermDeviceCmd`；手动补发 `POST /peripheral/apply`：`PermDeviceCmd`。

- **GET** `/api/v1/peripheral/policies?scope_type=&enabled=` — 列表（支持 `scope_type` 与 `enabled=1|true` 过滤）→ `{ "code":0, "total":int, "policies":[ PeripheralPolicy ] }`
- **POST** `/api/v1/peripheral/policies` — 创建
  - 请求：`{ "name":string(必填), "scope_type":string(必填: department|floor|batch|tag|device), "scope_value":string(必填), "usb_storage":string(block|allow|readonly), "optical":string(block|allow), "bluetooth":string(block|allow), "enabled":bool? }`
  - 响应：`{ "code":0, "policy": PeripheralPolicy }`
- **GET** `/api/v1/peripheral/policies/{id}` — 详情；**PUT** — 更新；**DELETE** — 删除 `{ "code":0, "deleted":string }`
- **POST** `/api/v1/peripheral/policies/{id}/apply` — 按作用域下发（可选 body `{ "device_id":string }` 限定单台）→ `{ "code":0, "policy_id":string, "summary":map, "results":[ PeripheralApplyState ] }`
- **GET** `/api/v1/peripheral/policies/{id}/status` — 策略生效状态 → `{ "code":0, "policy_id":string, "summary":map, "states":[ PeripheralApplyState ] }`
- **POST** `/api/v1/peripheral/apply` — 手动重新下发（补发，body `{ "device_id":string(必填), "policy_id"?:string }`）→ `{ "code":0, "device_id":string, "total":int, "results":[ PeripheralApplyState ] }`
- **GET** `/api/v1/peripheral/status?device_id=&department=&policy_id=` — 状态总览 → `{ "code":0, "total":int, "pending":int, "states":[ PeripheralApplyState ] }`

**`PeripheralPolicy`**：`id, name, scope_type, scope_value, usb_storage(block|allow|readonly), optical(block|allow), bluetooth(block|allow), enabled:bool, created_at, updated_at`
**`PeripheralApplyState`**：`device_id, device_name?, policy_id, policy_name?, status(applied|partial|failed|unsupported|offline|pending), usb_storage, optical, bluetooth, items?:[PeripheralItemResult], message?, dry_run:bool, applied_at?`
**`PeripheralItemResult`**：`item(usb_storage|optical|bluetooth), desired, applied?, state(applied|dry_run|unsupported|failed), reason?`

**策略生效状态 `status` 枚举**：`pending`(已创建待回执) · `applied`(全部生效) · `partial`(部分生效) · `failed` · `unsupported`(平台不支持) · `offline`(设备离线未下发) · `dry_run`(演练)

### 4.5 网络准入 `nac/actions` — `wave5b.go`
- 列表：`GET` 守卫 `PermDeviceView`；apply/release/evaluate：`POST` 守卫 `PermDeviceCmd`。

- **GET** `/api/v1/nac/actions?device_id=&action=&active=` — 列表（`active=1|true` 过滤掉 `allow` 项）→ `{ "code":0, "total":int, "threshold":int, "actions":[ NACAction ] }`
- **POST** `/api/v1/nac/apply` — 显式下发准入动作
  - 请求：`{ "device_id":string(必填), "action":string(allow|quarantine|block 必填), "reason":string?, "expire_in_sec":int? }`
  - 响应：`{ "code":0, "action": NACAction }`
- **POST** `/api/v1/nac/release` — 解除限制（恢复到 `allow`）→ `{ "code":0, "action": NACAction }`（body `{ "device_id":string(必填), "reason"?:string }`）
- **POST** `/api/v1/nac/evaluate` — 按合规阈值评估并（可选）下发
  - 请求：`{ "device_id"?:string, "threshold"?:int, "apply"?:bool(默认 true) }`
  - 响应：`{ "code":0, "threshold":int, "baseline":"wave5b_heuristic", "total":int, "non_compliant":int, "applied":bool, "items":[ { "device_id","device_name"?, "department"?, "score":int, "compliant":bool, "reasons":[string], "action":string, "state"?:string, "message"?:string } ] }`

**`NACAction`**：`id, device_id, device_name?, action(allow|quarantine|block), reason, expire_at?, state(applied|partial|unsupported|failed|pending|offline|expired), applied:bool, message?, score?:int, trigger?(manual|threshold|api), dry_run:bool, created_at, updated_at`

**枚举**
- 准入动作 `action`：`allow`(放行/解除终态) · `quarantine`(隔离) · `block`(阻断)
- 准入状态 `state`：`applied` · `partial` · `unsupported` · `failed` · `pending` · `offline` · `expired`
- 合规评分（评估用）为内置启发式基线 `baseline="wave5b_heuristic"`（在线40/分组20/软件清单20/副端版本10/生命周期10，0-100）；阈值由 `w5bNACThreshold()` 配置，低于阈值判为不合规 → `quarantine`。

---

## 5. 报表统计（stats）— `wave5b.go`
**全部端点守卫：`auth.PermDeviceView`**

### 5.1 `stats/overview`

- **GET** `/api/v1/stats/overview` （仪表盘综合概览）
  - 响应 `overview`：
    ```
    {
      "generated_at":string(RFC3339),
      "coverage": { "total_devices":int, "managed":int, "alive":int, "offline":int,
                    "coverage_rate":float, "by_department":[{ "department","total","online" }],
                    "by_os":{ "<os>":int } },
      "online":   { "window_hours":int, "online":int, "total":int, "online_rate":float,
                    "buckets":[{ "bucket":string, "count":int }], "note":string },
      "compliance":{ "available":bool, "baseline":"wave5b_heuristic", "threshold":int,
                     "scored_devices":int, "compliant":int, "non_compliant":int,
                     "compliance_rate":float, "avg_score":float,
                     "by_device":[{ "device_id","hostname","department","score":int,"compliant":bool,"reasons":[string] }],
                     "note":string },
      "vuln":     { "available":false, "total":0, "by_severity":{ "critical":0,"high":0,"medium":0,"low":0 }, "note":string },
      "rc":       { "sessions_total":int, "sessions_ended":int, "sessions_active":int,
                    "total_duration_sec":int, "avg_duration_sec":int,
                    "by_operator":[{ "operator":string,"sessions":int }], "note":string }
    }
    ```
  > 说明：当前 `compliance` 使用启发式基线，`vuln` 为占位（`available:false`，波次 5a 未接入漏洞数据源）。

### 5.2 `stats/export`

- **GET** `/api/v1/stats/export?format=csv|xlsx&type=coverage|online|compliance|vuln|rc`
  - **该端点返回文件下载，不是 JSON 信封**：`format=xlsx` → `Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`，文件名 `yuduan-stats-{type}.xlsx`；默认（`csv`）→ `Content-Type: text/csv; charset=utf-8`，文件名 `yuduan-stats-{type}.csv`。
  - 默认 `type=coverage`；未知 `type` 返回 `{ "code":2521, "message":... }`。
  - 可用 `type`：`coverage`(覆盖率) · `online`(在线率) · `compliance`(合规) · `vuln`(漏洞) · `rc`(远控会话)。

---

## 附：未实现的预期端点（前端勿依赖）
- **分发任务**：需求提及的「灰度发布 / 回滚 / 任务删除」在 `wave3.go` 中**未注册任何路由**（仅 cancel/records/confirm）。
- **文件同步 / 批量命令**：无「删除 / 停止」端点；文件同步为「取消即终态」，批量命令无显式停止（执行中任务由协程跑完）。

## 附：错误码区间
- swdist：`3001-3024` ｜ filesync/batchcmd：`4010-4040` ｜ 合规/黑名单/漏洞：`5201-5242` ｜ 外设/NAC/报表：`2501-2521`
