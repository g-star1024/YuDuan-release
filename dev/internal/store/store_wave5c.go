package store

// store_wave5c.go —— 波次 5c（W5-6 策略中心：模板/分组差异化/灰度+回滚/生效统计）的数据模型与持久化扩展点。
//
// 设计约束：不得修改既有 store.go / postgres.go，故本文件只做「新增」——
//   1. 定义 W5-6 的策略模板 / 绑定模型与常量；
//   2. 通过 RegisterMigrate 注册幂等建表（采用 id/doc JSON 形式，与 wave5a 一致，
//      供 hub.w5aPGSave / w5aPGDelete 直接复用做 PG 尽力双写）。
// 运行时状态在 dev/internal/hub/wave5c.go 内以内存态为权威（e2e 默认内存模式），
// PostgreSQL 模式下对模板/绑定做尽力而为的双写（写失败不影响主流程）。

import "time"

// ---- W5-6 策略模板：可组合的策略项域类型 ----

// 模板可引用的策略项来源域（与 wave5a/5b 既有域对应）。
const (
	StratDomainCompliance = "compliance" // 合规基线规则（W5-1）
	StratDomainBlacklist  = "blacklist"  // 违规软件黑名单规则（W5-2）
	StratDomainVuln       = "vuln"       // 漏洞规则（W5-5）
	StratDomainPeripheral = "peripheral" // 外设策略（W5-3）
	StratDomainNAC        = "nac"        // 网络准入动作（W5-4）
)

// 模板状态（灰度生命周期）。
const (
	StratStatusDraft      = "draft"       // 草稿（未下发）
	StratStatusActive     = "active"      // 灰度进行中/已到目标
	StratStatusPaused     = "paused"      // 灰度暂停
	StratStatusRolledBack = "rolled_back" // 已回滚（全部撤销）
)

// 设备×模板绑定状态。
const (
	BindingApplied    = "applied"     // 策略已对设备生效
	BindingRolledBack = "rolled_back" // 已回滚撤销
)

// StrategyRuleRef 模板内一条策略项引用（指向某个已存在的策略规则/动作）。
type StrategyRuleRef struct {
	Domain string `json:"domain"`           // compliance/blacklist/vuln/peripheral/nac
	RefID  string `json:"ref_id"`           // 被引用策略的 ID（如 compliance 基线 ID、peripheral 策略 ID）
	Name   string `json:"name"`             // 展示名（冗余，便于列表渲染，避免跨域查详情）
	Action string `json:"action,omitempty"` // enforce/review（默认 enforce）
}

// StrategyTemplate 策略模板：组合多域策略项 + 分组过滤（差异化）+ 灰度配置。
type StrategyTemplate struct {
	ID    string            `json:"id"`
	Name  string            `json:"name"`
	Desc  string            `json:"desc,omitempty"`
	Rules []StrategyRuleRef `json:"rules"`
	// 分组过滤（差异化）：任一维度命中即入选目标设备组；全空 = 全部设备。
	Departments []string `json:"departments,omitempty"`
	Floors      []string `json:"floors,omitempty"`
	Batches     []string `json:"batches,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	// 灰度：目标百分比（0-100）与当前进度。
	TargetPct  int       `json:"target_pct"`
	CurrentPct int       `json:"current_pct"`
	Status     string    `json:"status"` // draft/active/paused/rolled_back
	CreatedBy  string    `json:"created_by,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// StrategyBinding 设备×模板绑定（灰度推进逐步建立，回滚撤销）。
type StrategyBinding struct {
	ID         string    `json:"id"`
	TemplateID string    `json:"template_id"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name,omitempty"`
	Status     string    `json:"status"` // applied/rolled_back
	AppliedAt  time.Time `json:"applied_at"`
}

func init() {
	RegisterMigrate(func(p *PostgresStore) error {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS strategy_templates (
				id TEXT PRIMARY KEY,
				doc TEXT NOT NULL DEFAULT '{}',
				updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
			)`,
			`CREATE TABLE IF NOT EXISTS strategy_bindings (
				id TEXT PRIMARY KEY,
				doc TEXT NOT NULL DEFAULT '{}',
				updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
			)`,
		}
		for _, s := range stmts {
			if err := p.Exec(s); err != nil {
				return err
			}
		}
		return nil
	})
}
