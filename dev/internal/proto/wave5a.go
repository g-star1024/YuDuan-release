// 波次 5a（终端安全合规域）协议载荷（PRD 5.6）。
//
// 约定：本文件只新增类型与常量，不改动 proto.go 既有定义（多波次并行集成纪律）。
// 副端上报合规采集结果走「中枢下发指令 → 副端 result 回执」通道（复用既有
// TypeCommand/TypeResult 信封），因此合规载荷不新增消息类型。
package proto

// 合规项分类（W5-1 合规基线检查的四类基线 + 扩展项）。
const (
	ComplianceCategoryPatch       = "patch"        // 系统补丁/更新状态
	ComplianceCategoryAntivirus   = "antivirus"    // 杀毒/EDR
	ComplianceCategoryFirewall    = "firewall"     // 防火墙
	ComplianceCategoryScreensaver = "screensaver"  // 屏保/锁屏策略
	ComplianceCategoryEncrypt     = "disk_encrypt" // 磁盘加密（扩展项，三平台尽力采集）
)

// 合规项状态：pass=符合 / fail=不符合 / unknown=平台不支持或采集失败（诚实回告，不伪造）。
const (
	ComplianceStatePass    = "pass"
	ComplianceStateFail    = "fail"
	ComplianceStateUnknown = "unknown"
)

// ComplianceItem 是一条合规采集结果（副端→中枢）。
// Key 为稳定标识（基线按 Key 比对）；Actual 为实测值；Expected 为副端侧默认期望（中枢
// 以基线为准，此字段仅作展示兜底）；Detail 为采集依据（命令/注册表键/进程名等），
// 便于管理员复核「为什么判定为不合规」。
type ComplianceItem struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Category string `json:"category"`
	State    string `json:"state"` // pass/fail/unknown
	Actual   string `json:"actual"`
	Expected string `json:"expected,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// ComplianceReportPayload 是合规采集结果上报载荷。
// 载体：副端以 result 回执的 OutputLog（JSON 文本）返回；中枢侧导入接口亦直接接收本结构。
// DeviceID/Platform 可为空（副端回执场景由中枢按连接归属补齐）。
type ComplianceReportPayload struct {
	DeviceID    string            `json:"device_id,omitempty"`
	Platform    string            `json:"platform,omitempty"`
	CollectedAt int64             `json:"collected_at,omitempty"`
	Items       []ComplianceItem  `json:"items"`
	Software    []InstalledSoftware `json:"software,omitempty"` // 中枢侧补录入口（可选）
}

// ---- 波次 5a 指令动作名（复用 CommandPayload；扩展参数以 Command 字段承载紧凑 JSON）----

const (
	// ActionComplianceCollect —— 中枢→副端：采集合规项并以 result.OutputLog 回传 JSON。
	ActionComplianceCollect = "compliance_collect"
	// ActionPatchApply —— 中枢→副端：补丁修复任务（software/fix_version/repo_item）。
	// 副端如实回告：未配置分发包或无法安装时返回 dry-run 说明，绝不伪造「已安装」。
	ActionPatchApply = "patch_apply"
	// ActionSwUninstall 在中继分发波次（wave3.go）中声明为 "sw_uninstall"，
	// 本波次（W5-2 违规软件卸载 / W5-5 补丁前置卸载）复用同一 action，保持语义一致。
)

// Wave5aCommand 是 ActionComplianceCollect / ActionPatchApply / ActionSwUninstall
// 在 CommandPayload.Command 字段内承载的紧凑参数（JSON）。
type Wave5aCommand struct {
	Software     string `json:"software,omitempty"`      // patch_apply / sw_uninstall：目标软件名
	TargetVer    string `json:"target_version,omitempty"` // patch_apply：目标修复版本
	RepoItemID   string `json:"repo_item_id,omitempty"`   // patch_apply：仓库软件包 ID
	RuleID       string `json:"rule_id,omitempty"`        // sw_uninstall：命中的黑名单规则
	DryRun       bool   `json:"dry_run,omitempty"`        // true=仅演练，不实际执行
}
