package store

// store_wave5b.go —— 波次 5b（W5-3 外设管控 / W5-4 网络准入）的数据模型与持久化扩展点。
//
// 设计约束：不得修改既有 store.go / postgres.go，故本文件只做「新增」——
//   1. 定义 W5-3/W5-4 的模型结构与常量；
//   2. 通过 RegisterMigrate 注册幂等建表语句（仅 PostgreSQL 模式生效）。
// 运行时状态在 dev/internal/hub/wave5b.go 内以内存态为权威（e2e 默认内存模式），
// PostgreSQL 模式下中枢对策略/准入动作做尽力而为的双写（写失败不影响主流程）。

import "time"

// ---- W5-3 外设管控：策略模型 ----

// 外设策略的作用域类型（scope_type）。
const (
	ScopeDepartment = "department" // 按部门
	ScopeFloor      = "floor"      // 按楼层
	ScopeBatch      = "batch"      // 按批次
	ScopeTag        = "tag"        // 按标签
	ScopeDevice     = "device"     // 指定设备（ScopeValue 可为逗号分隔的多个设备 ID）
)

// 外设管控项的取值（usb_storage 支持只读，其余二类仅 block/allow）。
const (
	PeripheralBlock    = "block"
	PeripheralAllow    = "allow"
	PeripheralReadOnly = "readonly"
)

// 受管控的三类外设。
const (
	PeripheralUSBStorage = "usb_storage"
	PeripheralOptical    = "optical"
	PeripheralBluetooth  = "bluetooth"
)

// 策略在单台设备上的整体生效状态。
const (
	PolicyStatusApplied     = "applied"     // 全部项按要求生效
	PolicyStatusPartial     = "partial"     // 部分项生效（其余为 unsupported/failed/dry_run）
	PolicyStatusFailed      = "failed"      // 指令下发或执行失败
	PolicyStatusUnsupported = "unsupported" // 平台完全不支持（三项全部 unsupported）
	PolicyStatusOffline     = "offline"     // 设备离线，策略未下发（待补发）
	PolicyStatusPending     = "pending"     // 已创建但尚未收到回执
	PolicyStatusDryRun      = "dry_run"     // 演练模式：已评估可执行性并回告计划值，未实际改动系统
)

// 单管控项的执行结果状态（副端诚实回告）。
const (
	ItemStateApplied     = "applied"     // 已实际生效
	ItemStateDryRun      = "dry_run"     // 演练模式：仅回告计划值，未执行系统操作
	ItemStateUnsupported = "unsupported" // 平台不支持，未执行（附原因）
	ItemStateFailed      = "failed"      // 已尝试执行但失败（附原因）
)

// PeripheralPolicy 是一条外设管控策略（PRD 5.6）。
type PeripheralPolicy struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ScopeType  string    `json:"scope_type"`  // department/floor/batch/tag/device
	ScopeValue string    `json:"scope_value"` // 部门名/楼层/批次/标签/设备ID（device 支持逗号分隔）
	USBStorage string    `json:"usb_storage"` // block/allow/readonly
	Optical    string    `json:"optical"`     // block/allow
	Bluetooth  string    `json:"bluetooth"`   // block/allow
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PeripheralItemResult 单个管控项的执行/回告结果。
type PeripheralItemResult struct {
	Item    string `json:"item"`              // usb_storage/optical/bluetooth
	Desired string `json:"desired"`           // 期望值
	Applied string `json:"applied,omitempty"` // 实际生效值（dry_run 时为计划值）
	State   string `json:"state"`             // applied/dry_run/unsupported/failed
	Reason  string `json:"reason,omitempty"`  // unsupported/failed 的原因说明
}

// PeripheralApplyState 某条策略在某台设备上的生效状态与回执。
type PeripheralApplyState struct {
	DeviceID   string                  `json:"device_id"`
	DeviceName string                  `json:"device_name,omitempty"`
	PolicyID   string                  `json:"policy_id"`
	PolicyName string                  `json:"policy_name,omitempty"`
	Status     string                  `json:"status"` // applied/partial/failed/unsupported/offline/pending
	USBStorage string                  `json:"usb_storage"`
	Optical    string                  `json:"optical"`
	Bluetooth  string                  `json:"bluetooth"`
	Items      []PeripheralItemResult  `json:"items,omitempty"`
	Message    string                  `json:"message,omitempty"`
	DryRun     bool                    `json:"dry_run"`
	AppliedAt  time.Time               `json:"applied_at,omitempty"`
}

// ---- W5-4 网络准入 ----

// 准入动作类型。
const (
	NACAllow      = "allow"      // 放行（也是解除后的终态）
	NACQuarantine = "quarantine" // 隔离（仅可访问中枢/修复资源）
	NACBlock      = "block"      // 阻断内网访问
)

// 准入动作状态。
const (
	NACStateApplied     = "applied"     // 副端已执行生效
	NACStatePartial     = "partial"     // 副端部分执行/演练
	NACStateUnsupported = "unsupported" // 平台不支持，未生效（附原因）
	NACStateFailed      = "failed"      // 执行失败
	NACStatePending     = "pending"     // 已下发待回执
	NACStateOffline     = "offline"     // 设备离线未下发
	NACStateExpired     = "expired"     // 已到期并自动解除
)

// NACAction 是网络准入动作（PRD 5.6 可选能力：不合规终端限制内网访问）。
// ExpireAt 为零值表示永不自动解除；到期由中枢惰性扫描（查询时判定）自动恢复到 allow。
type NACAction struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name,omitempty"`
	Action     string    `json:"action"` // allow/quarantine/block
	Reason     string    `json:"reason"`
	ExpireAt   time.Time `json:"expire_at,omitempty"`
	State      string    `json:"state"`  // applied/partial/unsupported/failed/pending/offline/expired
	Applied    bool      `json:"applied"`
	Message    string    `json:"message,omitempty"`
	Score      int       `json:"score,omitempty"`     // 触发时的合规评分（0-100；-1=未提供）
	Trigger    string    `json:"trigger,omitempty"`   // manual/threshold/api
	DryRun     bool      `json:"dry_run"`             // 副端演练模式回执
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ---- PostgreSQL 持久化扩展点（幂等建表）----

func init() {
	RegisterMigrate(func(p *PostgresStore) error {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS peripheral_policies (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				scope_type TEXT NOT NULL,
				scope_value TEXT NOT NULL,
				usb_storage TEXT NOT NULL DEFAULT 'allow',
				optical TEXT NOT NULL DEFAULT 'allow',
				bluetooth TEXT NOT NULL DEFAULT 'allow',
				enabled BOOLEAN NOT NULL DEFAULT TRUE,
				created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
				updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
			)`,
			`CREATE TABLE IF NOT EXISTS peripheral_apply_state (
				device_id TEXT NOT NULL,
				policy_id TEXT NOT NULL,
				status TEXT NOT NULL,
				usb_storage TEXT NOT NULL DEFAULT '',
				optical TEXT NOT NULL DEFAULT '',
				bluetooth TEXT NOT NULL DEFAULT '',
				message TEXT NOT NULL DEFAULT '',
				dry_run BOOLEAN NOT NULL DEFAULT FALSE,
				applied_at TIMESTAMPTZ,
				PRIMARY KEY (device_id, policy_id)
			)`,
			`CREATE TABLE IF NOT EXISTS nac_actions (
				id TEXT PRIMARY KEY,
				device_id TEXT NOT NULL,
				action TEXT NOT NULL,
				reason TEXT NOT NULL DEFAULT '',
				expire_at TIMESTAMPTZ,
				state TEXT NOT NULL,
				applied BOOLEAN NOT NULL DEFAULT FALSE,
				message TEXT NOT NULL DEFAULT '',
				score INT NOT NULL DEFAULT -1,
				trigger_src TEXT NOT NULL DEFAULT 'manual',
				created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
				updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
			)`,
			`CREATE INDEX IF NOT EXISTS idx_nac_actions_device ON nac_actions(device_id)`,
		}
		for _, s := range stmts {
			if err := p.Exec(s); err != nil {
				return err
			}
		}
		return nil
	})
}
