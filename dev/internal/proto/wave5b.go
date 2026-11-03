package proto

// wave5b.go —— 波次 5b 新增协议载荷类型（W5-3 外设管控 / W5-4 网络准入）。
//
// 传输方式：复用既有 TypeCommand 信封（副端 main.go 的 handleCommand →
// dispatchWaveAction 只分发 TypeCommand，新增消息类型副端收不到），
// 具体动作以 CommandPayload.Action 区分，结构化参数 JSON 序列化后放在
// CommandPayload.Command 字段（该字段本就是自由文本，语义上即"指令参数"）。
// 回执同样复用 TypeResult 信封：结构化结果 JSON 放在 ResultPayload.OutputLog，
// 中枢按 "{" 前缀判定并解析（解析失败则按纯文本处理）。

// 波次 5b 新增指令动作（CommandPayload.Action）。
const (
	ActionPeripheralApply = "peripheral_apply" // W5-3 下发外设管控策略
	ActionNACApply        = "nac_apply"        // W5-4 下发网络准入动作
)

// 受管控的三类外设（与 store 侧常量同值；放协议层供副端直接引用）。
const (
	PeripheralUSBStorage = "usb_storage"
	PeripheralOptical    = "optical"
	PeripheralBluetooth  = "bluetooth"
)

// 管控项取值。
const (
	PeripheralBlock    = "block"
	PeripheralAllow    = "allow"
	PeripheralReadOnly = "readonly"
)

// 管控项回执状态（诚实回告口径）。
const (
	ItemStateApplied     = "applied"     // 已实际生效
	ItemStateDryRun      = "dry_run"     // 演练：仅评估，未执行系统操作
	ItemStateUnsupported = "unsupported" // 平台不支持，未执行（附原因）
	ItemStateFailed      = "failed"      // 已尝试执行但失败（附原因）
)

// 准入动作类型。
const (
	NACAllow      = "allow"      // 放行（解除后的终态）
	NACQuarantine = "quarantine" // 隔离
	NACBlock      = "block"      // 阻断内网访问
)

// PeripheralApplyPayload —— 中枢→副端：下发一条外设管控策略。
type PeripheralApplyPayload struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name,omitempty"`
	USBStorage string `json:"usb_storage"` // block/allow/readonly
	Optical    string `json:"optical"`     // block/allow
	Bluetooth  string `json:"bluetooth"`   // block/allow
	// DryRun=true 时副端只评估可执行性并回告计划值，不执行任何系统变更
	// （e2e 与默认部署均走该模式，避免误禁用本机设备）。
	DryRun bool `json:"dry_run"`
}

// PeripheralItemResult —— 单个管控项的执行结果（诚实回告）。
type PeripheralItemResult struct {
	Item    string `json:"item"`              // usb_storage/optical/bluetooth
	Desired string `json:"desired"`           // 期望值
	Applied string `json:"applied,omitempty"` // 实际生效值（dry_run 为计划值）
	State   string `json:"state"`             // applied/dry_run/unsupported/failed
	Reason  string `json:"reason,omitempty"`  // unsupported/failed 原因（严禁伪造成功）
}

// PeripheralApplyResult —— 副端→中枢：外设策略执行回执（放在 ResultPayload.OutputLog）。
type PeripheralApplyResult struct {
	PolicyID string                 `json:"policy_id"`
	Platform string                 `json:"platform"` // windows/macos/linux
	DryRun   bool                   `json:"dry_run"`
	Items    []PeripheralItemResult `json:"items"`
	Message  string                 `json:"message,omitempty"`
}

// NACApplyPayload —— 中枢→副端：下发一个网络准入动作。
type NACApplyPayload struct {
	Action  string `json:"action"`             // allow/quarantine/block
	Reason  string `json:"reason,omitempty"`
	ExpireAt string `json:"expire_at,omitempty"` // RFC3339；空=不自动解除
	DryRun  bool   `json:"dry_run"`
}

// NACApplyResult —— 副端→中枢：准入动作执行回执（放在 ResultPayload.OutputLog）。
type NACApplyResult struct {
	DeviceID string `json:"device_id"`
	Action   string `json:"action"`            // 请求执行的动作
	Applied  bool   `json:"applied"`           // 是否真实生效（dry_run 时为 false）
	State    string `json:"state"`             // applied/dry_run/unsupported/failed
	Reason   string `json:"reason,omitempty"`
	Platform string `json:"platform"`
	DryRun   bool   `json:"dry_run"`
}
