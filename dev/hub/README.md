# 中枢（Hub）说明

中枢是御端的服务端控制平面，M2/M3 已实现并通过本地验证。

## 职责
- **Agent 纳管**：`/ws/agent` WebSocket 端点，处理 `register / heartbeat / result`。
- **管理 REST API**（供主端调用）：
  - `GET  /api/v1/devices` —— 资产台账列表
  - `GET  /api/v1/devices/:id` —— 单设备详情
  - `GET  /api/v1/report` —— 汇总报表（总量 / 在线 / 离线 / 按 OS）
  - `POST /api/v1/devices/:id/commands` —— 下发指令（`{action, command}`），同步等待结果（15s 超时）
- **控制台静态页**：`/` 提供 `console/index.html`。
- **离线回收**：每 60s 将超过 90s 无心跳的设备标记为离线。

## 实现要点
- 文件：`internal/hub/hub.go`
- 存储：`internal/store`（接口化，当前内存实现）
- 监听：`cmd/hub/main.go` 默认 `:8080`

## 后续
- 接 PostgreSQL（schema 见 `dev/proto/schema.sql`）
- 全链路 TLS（铁律 4）
- RBAC / AD 同步（M6）
- 远控信令中继（M4）
