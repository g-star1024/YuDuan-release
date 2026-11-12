// 波次 5a：终端安全合规域（PRD 5.6）——合规基线检查 / 违规软件黑名单 / 漏洞扫描与补丁闭环。
//
// 覆盖范围：
//   - W5-1 合规基线检查：副端采集合规项（补丁/杀毒/防火墙/屏保/磁盘加密），中枢按
//     可按平台·部门差异化的基线与权重比对，产出 violations 与 compliance_score(0-100)；
//     不合规项进告警中心。
//   - W5-2 违规软件黑名单：规则库（精确名/包含/正则）+ 导入导出 + 命中记录 + 按设备/按软件视图；
//     命中即告警，action=uninstall 可自动下发卸载指令（默认 dry-run，避免不可逆破坏）。
//   - W5-5 漏洞扫描 + 补丁闭环：本地漏洞规则库（版本区间表达式）匹配设备软件清单，
//     产出漏洞项；修复任务跟踪「下发补丁 → 软件版本更新 → 漏洞转 patched」；
//     支持 accepted（接受风险）与例外名单。
//
// 集成纪律：本文件不修改 hub.go / store.go；状态挂载在包级 map[*Hub]，持久化在 PG 模式下
// 经 store.RegisterMigrate 建表并双写（内存模式完整可用，为 e2e 默认）。
//
// 边界：不依赖波次 3 的「分发任务」；补丁下发用自有轻量修复任务模型表达（见 PatchTask），
// 与波次 3 的集成点在 w5aDispatchPatch 的「仓库包 → 安装指令」处，见文件末尾说明。
package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/proto"
	"yuduan/internal/store"
)

// ---- 告警类型（W5-1/W5-2/W5-5 进告警中心；合规类复用 store.AlertCompliance）----

const (
	alertTypeBlacklist = "blacklist_hit" // W5-2 违规软件命中
	alertTypeVuln      = "vuln"          // W5-5 软件漏洞
)

// ===================== 数据模型 =====================

// ComplianceIssue 是合规问题（跨单元契约：W5-6 策略中心调用 ComplianceIssues 获取）。
// 字段稳定，新增字段只追加不删除。
type ComplianceIssue struct {
	Key      string `json:"key"`      // 合规项 Key（如 firewall.enabled）
	Name     string `json:"name"`     // 合规项名称
	Category string `json:"category"` // patch/antivirus/firewall/screensaver/disk_encrypt
	State    string `json:"state"`    // fail（ComplianceIssues 只返回已判定不合规项）
	Severity string `json:"severity"` // info/warning/critical（来自基线规则）
	Expected string `json:"expected"` // 基线期望值
	Actual   string `json:"actual"`   // 实测值
	Detail   string `json:"detail"`   // 判定依据（采集命令/注册表键等）
}

// BaselineRule 是基线内的一条检查规则。
type BaselineRule struct {
	Key      string `json:"key"`                // 合规项 Key
	Name     string `json:"name,omitempty"`     // 展示名（缺省取采集项 Name）
	Operator string `json:"operator"`           // eq/ne/on/off/gte/lte/exists（默认 eq）
	Expected string `json:"expected,omitempty"` // 期望值
	Weight   int    `json:"weight"`             // 权重（合规分按权重加权）
	Severity string `json:"severity,omitempty"` // info/warning/critical
}

// ComplianceBaseline 是合规基线（按平台/部门差异化；platform/department 为空=通用）。
type ComplianceBaseline struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Platform   string         `json:"platform,omitempty"`   // macos/windows/linux，空=全平台
	Department string         `json:"department,omitempty"` // 空=全部门
	Enabled    bool           `json:"enabled"`
	Rules      []BaselineRule `json:"rules"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// ComplianceViolation 是一次基线比对的结论（不合规或无法判定）。
type ComplianceViolation struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Detail   string `json:"detail,omitempty"`
	Weight   int    `json:"weight"`
	State    string `json:"state"` // fail / unknown
}

// DeviceCompliance 是设备合规快照（最新一次评估结论）。
type DeviceCompliance struct {
	DeviceID   string                 `json:"device_id"`
	DeviceName string                 `json:"device_name,omitempty"`
	Platform   string                 `json:"platform,omitempty"`
	Department string                 `json:"department,omitempty"`
	BaselineID string                 `json:"baseline_id,omitempty"`
	Score      int                    `json:"score"` // 0-100；-1=无可评估数据
	Items      []proto.ComplianceItem `json:"items"`
	Violations []ComplianceViolation  `json:"violations"`
	Unknowns   []ComplianceViolation  `json:"unknowns"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// BlacklistRule 是违规软件黑名单规则（W5-2）。
type BlacklistRule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`       // 规则名（如「远控类软件」）
	MatchType string    `json:"match_type"` // exact / contains / regex
	Pattern   string    `json:"pattern"`    // 匹配串（软件名）
	Severity  string    `json:"severity"`   // info/warning/critical
	Action    string    `json:"action"`     // alert / block / uninstall
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BlacklistHit 是一次黑名单命中记录（W5-2）。
type BlacklistHit struct {
	ID          int64     `json:"id"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	DeviceID    string    `json:"device_id"`
	DeviceName  string    `json:"device_name,omitempty"`
	Software    string    `json:"software"`
	Version     string    `json:"version,omitempty"`
	Severity    string    `json:"severity"`
	Action      string    `json:"action"`
	ActionTaken string    `json:"action_taken"` // alerted / uninstall_dispatched(...) / dispatch_failed(...)
	DetectedAt  time.Time `json:"detected_at"`
}

// VulnRule 是本地漏洞规则（W5-5）。AffectedVersions 形如 "<1.2.3" 或 ">=1.0,<2.0"。
type VulnRule struct {
	ID               string    `json:"id"`
	CVE              string    `json:"cve"`
	Software         string    `json:"software"`
	AffectedVersions string    `json:"affected_versions"`
	Severity         string    `json:"severity"` // info/warning/critical
	FixVersion       string    `json:"fix_version"`
	Advisory         string    `json:"advisory,omitempty"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// VulnItem 是一条设备漏洞项（W5-5）。State: open/patched/accepted。
type VulnItem struct {
	ID         string    `json:"id"`
	RuleID     string    `json:"rule_id"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name,omitempty"`
	Software   string    `json:"software"`
	Version    string    `json:"version"`
	CVE        string    `json:"cve"`
	Severity   string    `json:"severity"`
	FixVersion string    `json:"fix_version"`
	Advisory   string    `json:"advisory,omitempty"`
	State      string    `json:"state"`
	TaskID     string    `json:"task_id,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// VulnException 是漏洞例外名单（W5-5）：命中例外的软件/CVE/设备不再产生 open 漏洞项。
type VulnException struct {
	ID        string    `json:"id"`
	Software  string    `json:"software,omitempty"`  // 空=不限软件
	CVE       string    `json:"cve,omitempty"`       // 空=不限 CVE
	DeviceID  string    `json:"device_id,omitempty"` // 空=不限设备
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// PatchTask 是补丁修复任务（W5-5 补丁闭环）。
// State: pending（已创建）/ dispatched（已下发副端，等待版本更新）/ closed（版本达标，漏洞转 patched）/ failed。
type PatchTask struct {
	ID            string    `json:"id"`
	DeviceID      string    `json:"device_id"`
	DeviceName    string    `json:"device_name,omitempty"`
	Software      string    `json:"software"`
	TargetVersion string    `json:"target_version"`
	RepoItemID    string    `json:"repo_item_id,omitempty"` // 仓库软件包（波次 3 分发集成点）
	ItemIDs       []string  `json:"item_ids"`               // 关联的漏洞项
	State         string    `json:"state"`
	Note          string    `json:"note,omitempty"`
	Result        string    `json:"result,omitempty"` // 副端回执摘要
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// 修复任务状态常量。
const (
	PatchTaskPending    = "pending"
	PatchTaskDispatched = "dispatched"
	PatchTaskClosed     = "closed"
	PatchTaskFailed     = "failed"
)

// 漏洞项状态常量。
const (
	VulnStateOpen     = "open"
	VulnStatePatched  = "patched"
	VulnStateAccepted = "accepted"
)

// w5aSoftwareMatch 宽松软件名匹配：与扫描的 contains 语义一致（item 存完整匹配名，
// 查询多为规则短名，如 item="Zoom Workplace" 对 query="Zoom"）。空串恒不匹配。
func w5aSoftwareMatch(itemSoftware, query string) bool {
	a := strings.ToLower(strings.TrimSpace(itemSoftware))
	b := strings.ToLower(strings.TrimSpace(query))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.Contains(a, b)
}

// ===================== 状态容器 =====================

type wave5aState struct {
	mu sync.Mutex

	baselines  map[string]*ComplianceBaseline
	snapshots  map[string]*DeviceCompliance
	blacklist  map[string]*BlacklistRule
	hits       map[string]*BlacklistHit
	vulnRules  map[string]*VulnRule
	vulnItems  map[string]*VulnItem
	tasks      map[string]*PatchTask
	exceptions map[string]*VulnException

	seq     map[string]int64
	softFP  map[string]string // deviceID -> 软件清单指纹（变化即触发重扫）
	loaded  bool              // PG 装载标记
	bootstr bool              // 默认基线已注入
}

var (
	w5aMu      sync.Mutex
	w5aStates  = map[*Hub]*wave5aState{}
	w5aSweepOn sync.Map // *Hub -> true（每中枢只启动一个扫描协程）
)

// w5a 取（必要时创建并装载）当前中枢的波次 5a 状态。
func w5a(h *Hub) *wave5aState {
	w5aMu.Lock()
	s := w5aStates[h]
	if s == nil {
		s = &wave5aState{
			baselines:  map[string]*ComplianceBaseline{},
			snapshots:  map[string]*DeviceCompliance{},
			blacklist:  map[string]*BlacklistRule{},
			hits:       map[string]*BlacklistHit{},
			vulnRules:  map[string]*VulnRule{},
			vulnItems:  map[string]*VulnItem{},
			tasks:      map[string]*PatchTask{},
			exceptions: map[string]*VulnException{},
			seq:        map[string]int64{},
			softFP:     map[string]string{},
		}
		w5aStates[h] = s
	}
	w5aMu.Unlock()
	s.bootstrap(h)
	return s
}

// bootstrap 注入内置默认基线并从 PG 装载（仅一次）。
func (s *wave5aState) bootstrap(h *Hub) {
	s.mu.Lock()
	if s.bootstr {
		s.mu.Unlock()
		return
	}
	s.bootstr = true
	s.mu.Unlock()

	if pg := w5aPG(h); pg != nil {
		s.loadFromPG(h)
	}
	s.mu.Lock()
	if len(s.baselines) == 0 {
		b := defaultBaseline()
		s.baselines[b.ID] = &b
		w5aPGSave(h, "w5a_baselines", b.ID, b)
		log.Printf("[hub][w5a] 已注入默认合规基线 %s（%d 条规则）", b.ID, len(b.Rules))
	}
	s.mu.Unlock()
}

// defaultBaseline 内置默认基线：覆盖 PRD 5.6 四类基线 + 磁盘加密扩展项。
func defaultBaseline() ComplianceBaseline {
	now := time.Now().UTC()
	return ComplianceBaseline{
		ID: "baseline-default", Name: "默认合规基线", Enabled: true,
		CreatedAt: now, UpdatedAt: now,
		Rules: []BaselineRule{
			{Key: "firewall.enabled", Name: "防火墙已开启", Operator: "on", Expected: "on", Weight: 30, Severity: store.SeverityCritical},
			{Key: "antivirus.installed", Name: "杀毒/EDR 已安装", Operator: "exists", Weight: 25, Severity: store.SeverityCritical},
			{Key: "antivirus.running", Name: "杀毒/EDR 运行中", Operator: "exists", Weight: 15, Severity: store.SeverityWarning},
			{Key: "patch.pending_updates", Name: "无待安装补丁", Operator: "eq", Expected: "0", Weight: 10, Severity: store.SeverityWarning},
			{Key: "patch.automatic_check", Name: "系统更新自动检查", Operator: "on", Expected: "on", Weight: 5, Severity: store.SeverityInfo},
			{Key: "screensaver.enabled", Name: "屏保已启用", Operator: "on", Expected: "on", Weight: 10, Severity: store.SeverityWarning},
			{Key: "screensaver.timeout_sec", Name: "屏保超时≤600秒", Operator: "lte", Expected: "600", Weight: 10, Severity: store.SeverityWarning},
			{Key: "disk_encrypt.enabled", Name: "磁盘加密已开启", Operator: "on", Expected: "on", Weight: 5, Severity: store.SeverityInfo},
		},
	}
}

// ===================== 持久化（PG 双写；内存模式自动跳过）=====================

func w5aPG(h *Hub) *store.PostgresStore {
	pg, _ := h.store.(*store.PostgresStore)
	return pg
}

// w5aPGSave 以「id + JSON 文档」形式幂等写入（PG 不可用时静默降级为纯内存）。
func w5aPGSave(h *Hub, table, id string, v any) {
	pg := w5aPG(h)
	if pg == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = pg.Exec(fmt.Sprintf(
		"INSERT INTO %s (id, doc, updated_at) VALUES ($1,$2,now()) ON CONFLICT (id) DO UPDATE SET doc=$2, updated_at=now()",
		table), id, string(b))
}

func w5aPGDelete(h *Hub, table, id string) {
	if pg := w5aPG(h); pg != nil {
		_ = pg.Exec(fmt.Sprintf("DELETE FROM %s WHERE id=$1", table), id)
	}
}

// loadFromPG 首次访问时把 PG 中的波次 5a 数据装载进内存（内存模式下不调用）。
func (s *wave5aState) loadFromPG(h *Hub) {
	tables := []struct {
		name string
		fn   func(id, doc string)
	}{
		{"w5a_baselines", func(id, doc string) {
			var v ComplianceBaseline
			if json.Unmarshal([]byte(doc), &v) == nil {
				s.baselines[id] = &v
			}
		}},
		{"w5a_device_compliance", func(id, doc string) {
			var v DeviceCompliance
			if json.Unmarshal([]byte(doc), &v) == nil {
				s.snapshots[id] = &v
			}
		}},
		{"w5a_blacklist_rules", func(id, doc string) {
			var v BlacklistRule
			if json.Unmarshal([]byte(doc), &v) == nil {
				s.blacklist[id] = &v
			}
		}},
		{"w5a_blacklist_hits", func(id, doc string) {
			var v BlacklistHit
			if json.Unmarshal([]byte(doc), &v) == nil {
				s.hits[id] = &v
			}
		}},
		{"w5a_vuln_rules", func(id, doc string) {
			var v VulnRule
			if json.Unmarshal([]byte(doc), &v) == nil {
				s.vulnRules[id] = &v
			}
		}},
		{"w5a_vuln_items", func(id, doc string) {
			var v VulnItem
			if json.Unmarshal([]byte(doc), &v) == nil {
				s.vulnItems[id] = &v
			}
		}},
		{"w5a_vuln_tasks", func(id, doc string) {
			var v PatchTask
			if json.Unmarshal([]byte(doc), &v) == nil {
				s.tasks[id] = &v
			}
		}},
		{"w5a_vuln_exceptions", func(id, doc string) {
			var v VulnException
			if json.Unmarshal([]byte(doc), &v) == nil {
				s.exceptions[id] = &v
			}
		}},
	}
	for _, t := range tables {
		rows, err := w5aPG(h).QueryRows(fmt.Sprintf("SELECT id, doc FROM %s", t.name))
		if err != nil {
			log.Printf("[hub][w5a] 装载 %s 失败（降级为内存）: %v", t.name, err)
			continue
		}
		for _, r := range rows {
			if len(r) >= 2 {
				t.fn(r[0], r[1])
			}
		}
	}
	s.mu.Lock()
	s.loaded = true
	s.mu.Unlock()
}

// ===================== W5-1：基线比对与评估 =====================

// pickBaseline 按「平台+部门精确 > 平台 > 部门 > 通用」选基线。
func (s *wave5aState) pickBaseline(platform, department string) *ComplianceBaseline {
	var best *ComplianceBaseline
	bestScore := -1
	for _, b := range s.baselines {
		if !b.Enabled {
			continue
		}
		sc := 0
		if b.Platform != "" {
			if !strings.EqualFold(b.Platform, platform) {
				continue // 平台不匹配且非通用 → 不适用
			}
			sc += 2
		}
		if b.Department != "" {
			if b.Department != department {
				continue // 部门不匹配且非通用 → 不适用
			}
			sc += 1
		}
		if sc > bestScore {
			bestScore, best = sc, b
		}
	}
	return best
}

// w5aEvalRule 按基线规则判定单个采集项，返回 pass/fail/unknown。
func w5aEvalRule(item proto.ComplianceItem, r BaselineRule) string {
	actual := strings.TrimSpace(item.Actual)
	if actual == "" || strings.EqualFold(actual, "unknown") {
		return proto.ComplianceStateUnknown
	}
	op := strings.ToLower(strings.TrimSpace(r.Operator))
	if op == "" {
		op = "eq"
	}
	switch op {
	case "on", "true", "enabled", "yes":
		if v, ok := w5aTruthy(actual); ok {
			if v {
				return proto.ComplianceStatePass
			}
			return proto.ComplianceStateFail
		}
		// 非开关型取值（如杀毒软件名）：存在即视为开启
		return proto.ComplianceStatePass
	case "off", "false", "disabled":
		if v, ok := w5aTruthy(actual); ok {
			if !v {
				return proto.ComplianceStatePass
			}
			return proto.ComplianceStateFail
		}
		return proto.ComplianceStatePass
	case "exists", "set", "installed", "running":
		low := strings.ToLower(actual)
		if actual != "" && low != "none" && low != "unknown" && low != "off" && low != "false" && low != "0" {
			return proto.ComplianceStatePass
		}
		return proto.ComplianceStateFail
	case "ne":
		if !strings.EqualFold(actual, r.Expected) {
			return proto.ComplianceStatePass
		}
		return proto.ComplianceStateFail
	case "gte", "lte", "gt", "lt":
		c, ok := w5aCompareNumOrVer(actual, r.Expected)
		if !ok {
			return proto.ComplianceStateUnknown
		}
		switch op {
		case "gte":
			if c >= 0 {
				return proto.ComplianceStatePass
			}
		case "lte":
			if c <= 0 {
				return proto.ComplianceStatePass
			}
		case "gt":
			if c > 0 {
				return proto.ComplianceStatePass
			}
		case "lt":
			if c < 0 {
				return proto.ComplianceStatePass
			}
		}
		return proto.ComplianceStateFail
	default: // eq
		if strings.EqualFold(actual, r.Expected) {
			return proto.ComplianceStatePass
		}
		return proto.ComplianceStateFail
	}
}

func w5aTruthy(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on", "enabled", "active", "running", "installed":
		return true, true
	case "0", "false", "no", "off", "disabled", "inactive", "stopped", "none":
		return false, true
	}
	return false, false
}

// w5aCompareNumOrVer 先按数值比较，失败再按版本号比较。
func w5aCompareNumOrVer(a, b string) (int, bool) {
	af, ae := strconv.ParseFloat(strings.TrimSpace(a), 64)
	bf, be := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if ae == nil && be == nil {
		switch {
		case af < bf:
			return -1, true
		case af > bf:
			return 1, true
		default:
			return 0, true
		}
	}
	if len(w5aSplitVer(a)) == 0 || len(w5aSplitVer(b)) == 0 {
		return 0, false
	}
	return compareVersions(a, b), true
}

// w5aApplyCompliance 用采集项比对基线，产出快照、告警与审计。
func (h *Hub) w5aApplyCompliance(dev store.Device, items []proto.ComplianceItem) *DeviceCompliance {
	s := w5a(h)
	base := s.pickBaseline(dev.OS, dev.Department)

	snap := &DeviceCompliance{
		DeviceID: dev.ID, DeviceName: dev.Hostname, Platform: dev.OS,
		Department: dev.Department, Score: -1, Items: items,
		Violations: []ComplianceViolation{}, Unknowns: []ComplianceViolation{},
		UpdatedAt: time.Now().UTC(),
	}
	if base != nil {
		snap.BaselineID = base.ID
	}
	total, got := 0, 0
	worst := store.SeverityInfo
	if base != nil {
		for _, r := range base.Rules {
			var item *proto.ComplianceItem
			for i := range items {
				if items[i].Key == r.Key {
					item = &items[i]
					break
				}
			}
			v := ComplianceViolation{
				Key: r.Key, Category: w5aCategoryOf(r.Key), Severity: r.Severity,
				Expected: r.Expected, Weight: r.Weight, State: proto.ComplianceStateFail,
			}
			if item == nil {
				v.Name = r.Name
				v.State = proto.ComplianceStateUnknown
				v.Detail = "副端未上报该采集项（平台不支持或旧版本副端）"
				snap.Unknowns = append(snap.Unknowns, v)
				continue
			}
			v.Name = item.Name
			if v.Name == "" {
				v.Name = r.Name
			}
			v.Category = item.Category
			v.Actual = item.Actual
			v.Detail = item.Detail
			st := w5aEvalRule(*item, r)
			if st == proto.ComplianceStateUnknown || item.State == proto.ComplianceStateUnknown {
				v.State = proto.ComplianceStateUnknown
				snap.Unknowns = append(snap.Unknowns, v)
				continue
			}
			total += r.Weight
			if st == proto.ComplianceStatePass {
				got += r.Weight
				continue
			}
			if v.Severity == "" {
				v.Severity = store.SeverityWarning
			}
			snap.Violations = append(snap.Violations, v)
			if w5aSevRank(v.Severity) > w5aSevRank(worst) {
				worst = v.Severity
			}
		}
	}
	if total > 0 {
		snap.Score = got * 100 / total
	}

	s.mu.Lock()
	s.snapshots[dev.ID] = snap
	s.mu.Unlock()
	w5aPGSave(h, "w5a_device_compliance", dev.ID, snap)

	if len(snap.Violations) > 0 {
		var names []string
		for _, v := range snap.Violations {
			names = append(names, v.Name)
		}
		h.addAlert(store.Alert{
			Type: store.AlertCompliance, Severity: worst,
			DeviceID: dev.ID, DeviceName: dev.Hostname,
			Message: fmt.Sprintf("终端合规基线不合规（%d 项）", len(snap.Violations)),
			Detail:  "不合规项: " + strings.Join(names, "、") + fmt.Sprintf("；合规分=%d", snap.Score),
		})
		h.audit("system", "compliance_violation", dev.ID,
			fmt.Sprintf("基线=%s 不合规=%d 合规分=%d", snap.BaselineID, len(snap.Violations), snap.Score), "success")
	}
	log.Printf("[hub][w5a] 合规评估 dev=%s 基线=%s 分=%d 违规=%d 未知=%d",
		dev.ID, snap.BaselineID, snap.Score, len(snap.Violations), len(snap.Unknowns))
	return snap
}

func w5aSevRank(s string) int {
	switch s {
	case store.SeverityCritical:
		return 3
	case store.SeverityWarning:
		return 2
	default:
		return 1
	}
}

func w5aCategoryOf(key string) string {
	switch {
	case strings.HasPrefix(key, "patch"):
		return proto.ComplianceCategoryPatch
	case strings.HasPrefix(key, "antivirus"):
		return proto.ComplianceCategoryAntivirus
	case strings.HasPrefix(key, "firewall"):
		return proto.ComplianceCategoryFirewall
	case strings.HasPrefix(key, "screensaver"):
		return proto.ComplianceCategoryScreensaver
	case strings.HasPrefix(key, "disk_encrypt"):
		return proto.ComplianceCategoryEncrypt
	}
	return "other"
}

// ---- 导出契约（W5-6 策略中心集成点）----

// ComplianceIssues 返回指定设备的当前合规问题列表（空切片 = 无问题或无数据）。
// 只含「已判定不合规」项；无法判定（unknown）不列入，避免策略中心误拦。
func ComplianceIssues(h *Hub, deviceID string) []ComplianceIssue {
	if h == nil {
		return []ComplianceIssue{}
	}
	s := w5a(h)
	s.mu.Lock()
	snap, ok := s.snapshots[deviceID]
	s.mu.Unlock()
	if !ok || snap == nil {
		return []ComplianceIssue{}
	}
	out := make([]ComplianceIssue, 0, len(snap.Violations))
	for _, v := range snap.Violations {
		out = append(out, ComplianceIssue{
			Key: v.Key, Name: v.Name, Category: v.Category, State: proto.ComplianceStateFail,
			Severity: v.Severity, Expected: v.Expected, Actual: v.Actual, Detail: v.Detail,
		})
	}
	return out
}

// DeviceComplianceScore 返回指定设备合规分（0-100）；无数据返回 -1。
func DeviceComplianceScore(h *Hub, deviceID string) int {
	if h == nil {
		return -1
	}
	s := w5a(h)
	s.mu.Lock()
	snap, ok := s.snapshots[deviceID]
	s.mu.Unlock()
	if !ok || snap == nil {
		return -1
	}
	return snap.Score
}

// ===================== W5-1：副端采集触发 =====================

// w5aRequestCompliance 向在线副端下发 compliance_collect 指令并解析回执。
func (h *Hub) w5aRequestCompliance(deviceID string) ([]proto.ComplianceItem, error) {
	if !h.deviceOnlineLocal(deviceID) {
		return nil, fmt.Errorf("device offline")
	}
	taskID := newTaskID()
	cmd := proto.CommandPayload{Action: proto.ActionComplianceCollect, TaskID: taskID}
	env, err := proto.NewEnvelope(proto.TypeCommand, 0, cmd)
	if err != nil {
		return nil, err
	}
	h.sign(&env)
	raw, _ := json.Marshal(env)
	// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
	res, err := h.awaitTaskResult(taskID, 20*time.Second, func() error {
		if !h.sendToDevice(deviceID, raw) {
			return fmt.Errorf("send failed")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var rep proto.ComplianceReportPayload
	if err := json.Unmarshal([]byte(res.OutputLog), &rep); err != nil {
		return nil, fmt.Errorf("bad payload: %v", err)
	}
	return rep.Items, nil
}

// w5aCollectCompliance 触发采集并评估（用于定时扫描与按需接口）。
func (h *Hub) w5aCollectCompliance(dev store.Device) (*DeviceCompliance, error) {
	items, err := h.w5aRequestCompliance(dev.ID)
	if err != nil {
		return nil, err
	}
	return h.w5aApplyCompliance(dev, items), nil
}

// ===================== W5-2：黑名单匹配 =====================

// w5aMatchSoftware 按规则匹配类型判定软件名是否命中。
func w5aMatchSoftware(r *BlacklistRule, name string) bool {
	if name == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.MatchType)) {
	case "regex":
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return false
		}
		return re.MatchString(name)
	case "contains":
		return strings.Contains(strings.ToLower(name), strings.ToLower(r.Pattern))
	default: // exact
		return strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(r.Pattern))
	}
}

// w5aScanBlacklist 对设备软件清单做黑名单匹配：新命中落记录 + 告警 + 处置。
func (h *Hub) w5aScanBlacklist(dev store.Device) []BlacklistHit {
	s := w5a(h)
	sw := dev.SoftwareList()
	var fresh []*BlacklistHit

	s.mu.Lock()
	for _, rule := range s.blacklist {
		if !rule.Enabled {
			continue
		}
		for _, it := range sw {
			if !w5aMatchSoftware(rule, it.Name) {
				continue
			}
			dup := false
			for _, ex := range s.hits {
				if ex.DeviceID == dev.ID && ex.RuleID == rule.ID &&
					ex.Software == it.Name && ex.Version == it.Version {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
			s.seq["hit"]++
			hit := &BlacklistHit{
				ID: s.seq["hit"], RuleID: rule.ID, RuleName: rule.Name,
				DeviceID: dev.ID, DeviceName: dev.Hostname,
				Software: it.Name, Version: it.Version,
				Severity: rule.Severity, Action: rule.Action,
				ActionTaken: "alerted", DetectedAt: time.Now().UTC(),
			}
			s.hits[itoa(int(hit.ID))] = hit
			fresh = append(fresh, hit)
		}
	}
	s.mu.Unlock()

	for _, hit := range fresh {
		h.addAlert(store.Alert{
			Type: alertTypeBlacklist, Severity: hit.Severity,
			DeviceID: hit.DeviceID, DeviceName: hit.DeviceName,
			Message: "违规软件命中黑名单: " + hit.Software,
			Detail:  fmt.Sprintf("规则=%s 版本=%s 处置=%s", hit.RuleName, hit.Version, hit.Action),
		})
		h.audit("system", "blacklist_hit", hit.DeviceID,
			fmt.Sprintf("软件=%s 版本=%s 规则=%s 处置=%s", hit.Software, hit.Version, hit.RuleName, hit.Action), "success")
		if strings.EqualFold(hit.Action, "uninstall") {
			ok, note := h.w5aDispatchUninstall(dev.ID, hit)
			if ok {
				hit.ActionTaken = "uninstall_dispatched"
			} else {
				hit.ActionTaken = "dispatch_failed"
			}
			if note != "" {
				hit.ActionTaken += "(" + note + ")"
			}
			s.mu.Lock()
			s.hits[itoa(int(hit.ID))] = hit
			s.mu.Unlock()
		}
		w5aPGSave(h, "w5a_blacklist_hits", itoa(int(hit.ID)), hit)
	}
	out := make([]BlacklistHit, 0, len(fresh))
	for _, x := range fresh {
		out = append(out, *x)
	}
	return out
}

// w5aDispatchUninstall 下发卸载指令（W5-2 action=uninstall）。
// 安全姿态：默认 dry-run（副端不真正卸载），需副端侧 YUDUAN_W5A_UNINSTALL=1 才实际执行。
func (h *Hub) w5aDispatchUninstall(deviceID string, hit *BlacklistHit) (bool, string) {
	if !h.deviceOnlineLocal(deviceID) {
		return false, "offline"
	}
	taskID := newTaskID()
	arg := proto.Wave5aCommand{Software: hit.Software, RuleID: hit.RuleID, DryRun: true}
	argJSON, _ := json.Marshal(arg)
	cmd := proto.CommandPayload{
		Action: proto.ActionSwUninstall, TaskID: taskID,
		PkgName: hit.Software, Command: string(argJSON),
	}
	env, err := proto.NewEnvelope(proto.TypeCommand, 0, cmd)
	if err != nil {
		return false, "envelope"
	}
	h.sign(&env)
	raw, _ := json.Marshal(env)
	// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
	res, err := h.awaitTaskResult(taskID, 20*time.Second, func() error {
		if !h.sendToDevice(deviceID, raw) {
			return fmt.Errorf("send failed")
		}
		return nil
	})
	if err != nil {
		return false, "timeout"
	}
	note := strings.TrimSpace(res.OutputLog)
	if len(note) > 60 {
		note = note[:60]
	}
	return res.State == "success", note
}

// ===================== W5-5：漏洞匹配与补丁闭环 =====================

// compareVersions 比较版本号：逐段数值优先，非数值按字典序；相等返回 0。
func compareVersions(a, b string) int {
	as, bs := w5aSplitVer(a), w5aSplitVer(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xn, xe := strconv.Atoi(x)
		yn, ye := strconv.Atoi(y)
		if xe == nil && ye == nil {
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
			continue
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// w5aSplitVer 切分版本号为段（去 build 后缀，按 . _ 分隔）。
func w5aSplitVer(s string) []string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, r := range s {
		if r == '.' || r == '_' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// versionInRange 判定版本是否落在受影响区间表达式内（如 "<1.2.3"、">=1.0,<2.0"）。
// 版本为空（未知）返回 false——不可判定即不谎报漏洞。
func versionInRange(ver, expr string) bool {
	ver = strings.TrimSpace(ver)
	if ver == "" || strings.EqualFold(ver, "unknown") {
		return false
	}
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "*" {
		return true
	}
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		op := "=="
		switch {
		case strings.HasPrefix(part, ">="):
			op, part = ">=", part[2:]
		case strings.HasPrefix(part, "<="):
			op, part = "<=", part[2:]
		case strings.HasPrefix(part, "=="):
			op, part = "==", part[2:]
		case strings.HasPrefix(part, "!="):
			op, part = "!=", part[2:]
		case strings.HasPrefix(part, "="):
			op, part = "==", part[1:]
		case strings.HasPrefix(part, ">"):
			op, part = ">", part[1:]
		case strings.HasPrefix(part, "<"):
			op, part = "<", part[1:]
		}
		part = strings.TrimSpace(part)
		c := compareVersions(ver, part)
		switch op {
		case ">=":
			if c < 0 {
				return false
			}
		case "<=":
			if c > 0 {
				return false
			}
		case ">":
			if c <= 0 {
				return false
			}
		case "<":
			if c >= 0 {
				return false
			}
		case "==":
			if c != 0 {
				return false
			}
		case "!=":
			if c == 0 {
				return false
			}
		}
	}
	return true
}

// exceptionHit 判定漏洞是否被例外名单豁免。
func (s *wave5aState) exceptionHit(software, cve, deviceID string) bool {
	for _, e := range s.exceptions {
		if e.CVE != "" && !strings.EqualFold(e.CVE, cve) {
			continue
		}
		if e.Software != "" && !strings.EqualFold(e.Software, software) {
			continue
		}
		if e.DeviceID != "" && e.DeviceID != deviceID {
			continue
		}
		return true
	}
	return false
}

// w5aScanVulns 用漏洞规则库匹配设备软件清单，产出/更新漏洞项。
func (h *Hub) w5aScanVulns(dev store.Device) []VulnItem {
	s := w5a(h)
	sw := dev.SoftwareList()
	var fresh []*VulnItem

	s.mu.Lock()
	for _, rule := range s.vulnRules {
		if !rule.Enabled {
			continue
		}
		var target *proto.InstalledSoftware
		for i := range sw {
			if strings.EqualFold(strings.TrimSpace(sw[i].Name), strings.TrimSpace(rule.Software)) {
				target = &sw[i]
				break
			}
		}
		if target == nil {
			for i := range sw { // 回退：包含匹配（兼容带后缀的软件名）
				if strings.Contains(strings.ToLower(sw[i].Name), strings.ToLower(rule.Software)) {
					target = &sw[i]
					break
				}
			}
		}
		if target == nil {
			continue
		}
		if s.exceptionHit(target.Name, rule.CVE, dev.ID) {
			continue
		}
		vulnerable := versionInRange(target.Version, rule.AffectedVersions)

		// 已有同设备+同规则的漏洞项 → 更新（版本达标即转 patched）
		var existing *VulnItem
		for _, it := range s.vulnItems {
			if it.DeviceID == dev.ID && it.RuleID == rule.ID && it.Software == target.Name {
				existing = it
				break
			}
		}
		if existing != nil {
			existing.Version = target.Version
			existing.UpdatedAt = time.Now().UTC()
			if existing.State != VulnStateAccepted && !vulnerable {
				existing.State = VulnStatePatched
			}
			w5aPGSave(h, "w5a_vuln_items", existing.ID, existing)
			continue
		}
		if !vulnerable {
			continue
		}
		s.seq["vuln"]++
		item := &VulnItem{
			ID:     "vi-" + itoa(int(s.seq["vuln"])) + "-" + randHex(4),
			RuleID: rule.ID, DeviceID: dev.ID, DeviceName: dev.Hostname,
			Software: target.Name, Version: target.Version, CVE: rule.CVE,
			Severity: rule.Severity, FixVersion: rule.FixVersion, Advisory: rule.Advisory,
			State: VulnStateOpen, DetectedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
		s.vulnItems[item.ID] = item
		fresh = append(fresh, item)
	}
	s.mu.Unlock()

	for _, it := range fresh {
		w5aPGSave(h, "w5a_vuln_items", it.ID, it)
		h.addAlert(store.Alert{
			Type: alertTypeVuln, Severity: it.Severity,
			DeviceID: it.DeviceID, DeviceName: it.DeviceName,
			Message: "软件漏洞待修复: " + it.Software + " " + it.Version,
			Detail:  fmt.Sprintf("%s 修复版本=%s %s", it.CVE, it.FixVersion, it.Advisory),
		})
		h.audit("system", "vuln_detected", it.DeviceID,
			fmt.Sprintf("%s %s %s 修复版本=%s", it.CVE, it.Software, it.Version, it.FixVersion), "success")
	}
	out := make([]VulnItem, 0, len(fresh))
	for _, x := range fresh {
		out = append(out, *x)
	}
	return out
}

// w5aAutoVerifyTasks 软件清单更新后自动校验进行中的修复任务：版本达标即闭环。
func (h *Hub) w5aAutoVerifyTasks(dev store.Device) {
	s := w5a(h)
	s.mu.Lock()
	var pending []*PatchTask
	for _, t := range s.tasks {
		if t.DeviceID == dev.ID && (t.State == PatchTaskDispatched || t.State == PatchTaskPending) {
			pending = append(pending, t)
		}
	}
	s.mu.Unlock()
	for _, t := range pending {
		h.w5aVerifyTask(t.ID)
	}
}

// w5aVerifyTask 校验单个修复任务：目标软件版本达到 target_version → 漏洞转 patched，任务 closed。
func (h *Hub) w5aVerifyTask(taskID string) (*PatchTask, bool) {
	s := w5a(h)
	s.mu.Lock()
	t, ok := s.tasks[taskID]
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	dev, ok := h.store.Get(t.DeviceID)
	if !ok {
		return t, false
	}
	cur := ""
	for _, it := range dev.SoftwareList() {
		if strings.EqualFold(strings.TrimSpace(it.Name), strings.TrimSpace(t.Software)) {
			cur = it.Version
			break
		}
	}
	met := cur != "" && t.TargetVersion != "" && compareVersions(cur, t.TargetVersion) >= 0
	s.mu.Lock()
	t.UpdatedAt = time.Now().UTC()
	if met {
		t.State = PatchTaskClosed
		t.Note = fmt.Sprintf("软件版本已更新至 %s，漏洞已修复", cur)
		for _, id := range t.ItemIDs {
			if it, ok := s.vulnItems[id]; ok && it.State != VulnStateAccepted {
				it.State = VulnStatePatched
				it.Version = cur
				it.UpdatedAt = time.Now().UTC()
				w5aPGSave(h, "w5a_vuln_items", it.ID, it)
			}
		}
		// 未显式关联的漏洞项（同设备+同软件）一并闭环
		for _, it := range s.vulnItems {
			if it.DeviceID == t.DeviceID && w5aSoftwareMatch(it.Software, t.Software) && it.State == VulnStateOpen {
				it.State = VulnStatePatched
				it.Version = cur
				it.UpdatedAt = time.Now().UTC()
				w5aPGSave(h, "w5a_vuln_items", it.ID, it)
			}
		}
	}
	s.mu.Unlock()
	w5aPGSave(h, "w5a_vuln_tasks", t.ID, t)
	if met {
		h.audit("system", "patch_task_closed", t.DeviceID,
			fmt.Sprintf("任务=%s 软件=%s 版本=%s 目标=%s", t.ID, t.Software, cur, t.TargetVersion), "success")
	}
	return t, met
}

// w5aDispatchPatch 向副端下发补丁修复指令（软件分发集成点）。
// 本波次不依赖波次 3 的分发任务：副端收到 patch_apply 后如实回告（未配置分发包时为 dry-run），
// 任务保持 dispatched，待软件版本更新后由 w5aVerifyTask 闭环。
func (h *Hub) w5aDispatchPatch(t *PatchTask) bool {
	if !h.deviceOnlineLocal(t.DeviceID) {
		t.State = PatchTaskFailed
		t.Note = "设备离线，无法下发补丁"
		t.UpdatedAt = time.Now().UTC()
		w5aPGSave(h, "w5a_vuln_tasks", t.ID, t)
		return false
	}
	taskID := newTaskID()
	arg := proto.Wave5aCommand{Software: t.Software, TargetVer: t.TargetVersion, RepoItemID: t.RepoItemID}
	argJSON, _ := json.Marshal(arg)
	cmd := proto.CommandPayload{
		Action: proto.ActionPatchApply, TaskID: taskID,
		PkgName: t.Software, Command: string(argJSON),
	}
	env, err := proto.NewEnvelope(proto.TypeCommand, 0, cmd)
	if err != nil {
		return false
	}
	h.sign(&env)
	raw, _ := json.Marshal(env)
	// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
	res, err := h.awaitTaskResult(taskID, 25*time.Second, func() error {
		if !h.sendToDevice(t.DeviceID, raw) {
			return fmt.Errorf("指令下发失败")
		}
		return nil
	})
	t.UpdatedAt = time.Now().UTC()
	if err != nil {
		t.State = PatchTaskFailed
		if strings.Contains(err.Error(), "timeout") {
			t.Note = "副端超时未回执"
		} else {
			t.Note = err.Error()
		}
	} else {
		t.State = PatchTaskDispatched
		t.Result = strings.TrimSpace(res.OutputLog)
		if len(t.Result) > 200 {
			t.Result = t.Result[:200]
		}
		t.Note = "已下发副端，等待软件版本更新后自动闭环"
	}
	w5aPGSave(h, "w5a_vuln_tasks", t.ID, t)
	h.audit("system", "patch_task_dispatch", t.DeviceID,
		fmt.Sprintf("任务=%s 软件=%s 目标=%s 结果=%s", t.ID, t.Software, t.TargetVersion, t.State), "success")
	return t.State == PatchTaskDispatched
}

// ===================== 定时扫描（注册/心跳触发的等价替代）=====================
//
// 说明：hub.go 的 register/heartbeat 分支不可修改（并行集成纪律），因此以「周期性扫描 +
// 软件清单指纹变化即触发」实现「上报后实时匹配」的等价语义：设备注册后首个扫描周期即完成
// 合规评估、黑名单匹配与漏洞匹配；软件清单变化（重注册上报新清单）立即重扫。
// 周期与 TTL：YUDUAN_W5A_SCAN_SEC（默认 20s）、YUDUAN_W5A_TTL_SEC（默认 300s）。

func (h *Hub) startWave5aSweeper() {
	if _, loaded := w5aSweepOn.LoadOrStore(h, true); loaded {
		return
	}
	go func() {
		interval := time.Duration(envInt("YUDUAN_W5A_SCAN_SEC", 20)) * time.Second
		if interval < time.Second {
			interval = time.Second
		}
		for {
			time.Sleep(interval)
			h.wave5aSweep()
		}
	}()
	log.Printf("[hub][w5a] 合规域定时扫描已启动（周期=%ds）", envInt("YUDUAN_W5A_SCAN_SEC", 20))
}

func (h *Hub) wave5aSweep() {
	ttl := time.Duration(envInt("YUDUAN_W5A_TTL_SEC", 300)) * time.Second
	s := w5a(h)
	for _, d := range h.store.List() {
		fp := w5aSoftwareFP(d)
		s.mu.Lock()
		old := s.softFP[d.ID]
		s.mu.Unlock()
		if fp != old {
			s.mu.Lock()
			s.softFP[d.ID] = fp
			s.mu.Unlock()
			h.w5aScanBlacklist(d)
			h.w5aScanVulns(d)
			h.w5aAutoVerifyTasks(d)
		}
		if !h.deviceOnlineLocal(d.ID) {
			continue
		}
		s.mu.Lock()
		snap := s.snapshots[d.ID]
		s.mu.Unlock()
		if snap != nil && time.Since(snap.UpdatedAt) < ttl {
			continue
		}
		if _, err := h.w5aCollectCompliance(d); err != nil {
			if strings.Contains(err.Error(), "timeout") {
				log.Printf("[hub][w5a] 合规采集本轮超时跳过（dev=%s；环境/时序相关，下轮扫描自动重试自愈，无需人工干预）: %v", d.ID, err)
			} else {
				log.Printf("[hub][w5a] 合规采集失败 dev=%s: %v", d.ID, err)
			}
		}
	}
}

// w5aSoftwareFP 计算软件清单指纹（名称@版本排序后拼接）。
func w5aSoftwareFP(d store.Device) string {
	sw := d.SoftwareList()
	names := make([]string, 0, len(sw))
	for _, it := range sw {
		names = append(names, it.Name+"@"+it.Version)
	}
	sort.Strings(names)
	return strings.Join(names, "|")
}

// ===================== HTTP：路由 =====================

// wave5aRoutes 挂载波次 5a 的全部 REST 路由（由 hub.go → wave5.go 调用）。
func wave5aRoutes(mux *http.ServeMux, h *Hub) {
	// W5-1 合规基线
	mux.HandleFunc("/api/v1/compliance/baselines", h.w5aGuardBaselines)
	mux.HandleFunc("/api/v1/compliance/baselines/", h.w5aGuardBaselineItem)
	mux.HandleFunc("/api/v1/compliance/overview", h.guard(auth.PermDeviceView, h.w5aOverview))
	mux.HandleFunc("/api/v1/compliance/devices", h.guard(auth.PermDeviceView, h.w5aDeviceList))
	mux.HandleFunc("/api/v1/compliance/devices/", h.w5aGuardDeviceItem)
	mux.HandleFunc("/api/v1/compliance/report", h.guard(auth.PermDeviceCmd, h.w5aReport))
	mux.HandleFunc("/api/v1/compliance/violations", h.guard(auth.PermDeviceView, h.w5aViolations))

	// W5-2 违规软件黑名单
	mux.HandleFunc("/api/v1/blacklist/rules", h.w5aGuardBlacklistRules)
	mux.HandleFunc("/api/v1/blacklist/rules/", h.w5aGuardBlacklistItem)
	mux.HandleFunc("/api/v1/blacklist/import", h.guard(auth.PermSoftwareMgmt, h.w5aBlacklistImport))
	mux.HandleFunc("/api/v1/blacklist/export", h.guard(auth.PermDeviceView, h.w5aBlacklistExport))
	mux.HandleFunc("/api/v1/blacklist/hits", h.guard(auth.PermDeviceView, h.w5aBlacklistHits))
	mux.HandleFunc("/api/v1/blacklist/by-device", h.guard(auth.PermDeviceView, h.w5aBlacklistByDevice))
	mux.HandleFunc("/api/v1/blacklist/by-software", h.guard(auth.PermDeviceView, h.w5aBlacklistBySoftware))
	mux.HandleFunc("/api/v1/blacklist/scan/", h.guard(auth.PermSoftwareMgmt, h.w5aBlacklistScan))

	// W5-5 漏洞与补丁闭环
	mux.HandleFunc("/api/v1/vuln/rules", h.w5aGuardVulnRules)
	mux.HandleFunc("/api/v1/vuln/rules/", h.w5aGuardVulnRuleItem)
	mux.HandleFunc("/api/v1/vuln/rules/import", h.guard(auth.PermSoftwareMgmt, h.w5aVulnRuleImport))
	mux.HandleFunc("/api/v1/vuln/items", h.guard(auth.PermDeviceView, h.w5aVulnItems))
	mux.HandleFunc("/api/v1/vuln/items/", h.w5aGuardVulnItemByID)
	mux.HandleFunc("/api/v1/vuln/scan/", h.guard(auth.PermSoftwareMgmt, h.w5aVulnScan))
	mux.HandleFunc("/api/v1/vuln/summary", h.guard(auth.PermDeviceView, h.w5aVulnSummary))
	mux.HandleFunc("/api/v1/vuln/tasks", h.w5aGuardPatchTasks)
	mux.HandleFunc("/api/v1/vuln/tasks/", h.w5aGuardPatchTaskItem)
	mux.HandleFunc("/api/v1/vuln/exceptions", h.w5aGuardExceptions)

	h.startWave5aSweeper()
}

// ---- 通用 helpers ----

func writeErr5a(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, map[string]any{"code": code, "msg": msg, "message": msg})
}

func w5aDecode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ===================== HTTP：W5-1 处理函数 =====================

func (h *Hub) w5aGuardBaselines(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aListBaselines).ServeHTTP(w, r)
	case http.MethodPost:
		h.guard(auth.PermDeviceCmd, h.w5aCreateBaseline).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aGuardBaselineItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aGetBaseline).ServeHTTP(w, r)
	case http.MethodPut, http.MethodPost:
		h.guard(auth.PermDeviceCmd, h.w5aUpdateBaseline).ServeHTTP(w, r)
	case http.MethodDelete:
		h.guard(auth.PermDeviceCmd, h.w5aDeleteBaseline).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aListBaselines(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	out := make([]*ComplianceBaseline, 0, len(s.baselines))
	for _, b := range s.baselines {
		out = append(out, b)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "baselines": out})
}

func (h *Hub) w5aCreateBaseline(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in ComplianceBaseline
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5201, "invalid body: "+err.Error())
		return
	}
	if in.Name == "" {
		writeErr5a(w, 5202, "name required")
		return
	}
	if len(in.Rules) == 0 {
		writeErr5a(w, 5203, "rules required")
		return
	}
	now := time.Now().UTC()
	in.ID = "bl-" + randHex(6)
	in.CreatedAt, in.UpdatedAt = now, now
	in.Enabled = true
	s := w5a(h)
	s.mu.Lock()
	s.baselines[in.ID] = &in
	s.mu.Unlock()
	w5aPGSave(h, "w5a_baselines", in.ID, in)
	h.audit(claims.Username, "compliance_baseline_create", in.ID, "name="+in.Name+" rules="+itoa(len(in.Rules)), "success")
	writeJSON(w, map[string]any{"code": 0, "baseline": in})
}

func (h *Hub) w5aGetBaseline(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/compliance/baselines/")
	s := w5a(h)
	s.mu.Lock()
	b, ok := s.baselines[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5204, "baseline not found")
		return
	}
	writeJSON(w, map[string]any{"code": 0, "baseline": b})
}

func (h *Hub) w5aUpdateBaseline(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/compliance/baselines/")
	s := w5a(h)
	s.mu.Lock()
	b, ok := s.baselines[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5204, "baseline not found")
		return
	}
	var in ComplianceBaseline
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5201, "invalid body: "+err.Error())
		return
	}
	s.mu.Lock()
	if in.Name != "" {
		b.Name = in.Name
	}
	if in.Platform != "" {
		b.Platform = in.Platform
	}
	if in.Department != "" {
		b.Department = in.Department
	}
	if len(in.Rules) > 0 {
		b.Rules = in.Rules
	}
	b.Enabled = in.Enabled || r.URL.Query().Get("enabled") != "false"
	b.UpdatedAt = time.Now().UTC()
	cp := *b
	s.mu.Unlock()
	w5aPGSave(h, "w5a_baselines", cp.ID, cp)
	h.audit(claims.Username, "compliance_baseline_update", cp.ID, "name="+cp.Name, "success")
	writeJSON(w, map[string]any{"code": 0, "baseline": cp})
}

func (h *Hub) w5aDeleteBaseline(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/compliance/baselines/")
	s := w5a(h)
	s.mu.Lock()
	_, ok := s.baselines[id]
	if ok {
		delete(s.baselines, id)
	}
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5204, "baseline not found")
		return
	}
	w5aPGDelete(h, "w5a_baselines", id)
	h.audit(claims.Username, "compliance_baseline_delete", id, "", "success")
	writeJSON(w, map[string]any{"code": 0, "id": id})
}

// w5aGuardDeviceItem 设备合规详情（GET）/ 触发采集（POST .../collect）。
func (h *Hub) w5aGuardDeviceItem(w http.ResponseWriter, r *http.Request) {
	rest := idAfterPrefix(r.URL.Path, "/api/v1/compliance/devices/")
	if strings.HasSuffix(rest, "/collect") && r.Method == http.MethodPost {
		h.guard(auth.PermDeviceCmd, h.w5aDeviceCollect).ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodGet {
		h.guard(auth.PermDeviceView, h.w5aDeviceDetail).ServeHTTP(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *Hub) w5aDeviceDetail(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/compliance/devices/")
	if _, ok := h.store.Get(id); !ok {
		writeErr5a(w, 5205, "device not found")
		return
	}
	s := w5a(h)
	s.mu.Lock()
	snap := s.snapshots[id]
	s.mu.Unlock()
	if snap == nil {
		writeJSON(w, map[string]any{"code": 0, "device_id": id, "score": -1,
			"items": []proto.ComplianceItem{}, "violations": []ComplianceViolation{},
			"note": "尚无合规数据（等待副端上报或手动触发采集）"})
		return
	}
	writeJSON(w, map[string]any{"code": 0, "compliance": snap})
}

func (h *Hub) w5aDeviceCollect(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := strings.TrimSuffix(idAfterPrefix(r.URL.Path, "/api/v1/compliance/devices/"), "/collect")
	dev, ok := h.store.Get(id)
	if !ok {
		writeErr5a(w, 5205, "device not found")
		return
	}
	snap, err := h.w5aCollectCompliance(dev)
	if err != nil {
		writeErr5a(w, 5206, "collect failed: "+err.Error())
		return
	}
	h.audit(claims.Username, "compliance_collect", id,
		fmt.Sprintf("合规分=%d 违规=%d", snap.Score, len(snap.Violations)), "success")
	writeJSON(w, map[string]any{"code": 0, "compliance": snap})
}

func (h *Hub) w5aDeviceList(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	type row struct {
		DeviceID   string    `json:"device_id"`
		DeviceName string    `json:"device_name"`
		Platform   string    `json:"platform"`
		Department string    `json:"department"`
		Score      int       `json:"score"`
		Violations int       `json:"violations"`
		BaselineID string    `json:"baseline_id"`
		UpdatedAt  time.Time `json:"updated_at"`
	}
	var rows []row
	for _, d := range h.store.List() {
		r := row{DeviceID: d.ID, DeviceName: d.Hostname, Platform: d.OS, Department: d.Department, Score: -1}
		if snap := s.snapshots[d.ID]; snap != nil {
			r.Score = snap.Score
			r.Violations = len(snap.Violations)
			r.BaselineID = snap.BaselineID
			r.UpdatedAt = snap.UpdatedAt
		}
		rows = append(rows, r)
	}
	s.mu.Unlock()
	q := r.URL.Query()
	if v := q.Get("department"); v != "" {
		var f []row
		for _, x := range rows {
			if x.Department == v {
				f = append(f, x)
			}
		}
		rows = f
	}
	if v := q.Get("platform"); v != "" {
		var f []row
		for _, x := range rows {
			if strings.EqualFold(x.Platform, v) {
				f = append(f, x)
			}
		}
		rows = f
	}
	if rows == nil {
		rows = []row{}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].DeviceID < rows[j].DeviceID })
	writeJSON(w, map[string]any{"code": 0, "total": len(rows), "devices": rows})
}

// w5aOverview 全局合规概览（按分类/严重度聚合违规、均分、最差设备 Top5）。
func (h *Hub) w5aOverview(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	type agg struct {
		Devices    int              `json:"devices"`
		Scored     int              `json:"scored_devices"`
		AvgScore   int              `json:"avg_score"`
		Passed     int              `json:"passed_devices"`
		Failed     int              `json:"failed_devices"`
		Violations int              `json:"violations"`
		Unknowns   int              `json:"unknowns"`
		ByCategory map[string]int   `json:"by_category"`
		BySeverity map[string]int   `json:"by_severity"`
		WorstTop5  []map[string]any `json:"worst_devices"`
		Baselines  int              `json:"baselines"`
		BlacklistN int              `json:"blacklist_rules"`
		BlackHits  int              `json:"blacklist_hits"`
		VulnRules  int              `json:"vuln_rules"`
		VulnOpen   int              `json:"vuln_open"`
	}
	a := agg{ByCategory: map[string]int{}, BySeverity: map[string]int{}, WorstTop5: []map[string]any{}}
	type kv struct {
		id    string
		name  string
		score int
		viol  int
	}
	var all []kv
	sum := 0
	for _, d := range h.store.List() {
		a.Devices++
		snap := s.snapshots[d.ID]
		if snap == nil {
			continue
		}
		a.Scored++
		sum += snap.Score
		if len(snap.Violations) == 0 {
			a.Passed++
		} else {
			a.Failed++
		}
		a.Violations += len(snap.Violations)
		a.Unknowns += len(snap.Unknowns)
		for _, v := range snap.Violations {
			a.ByCategory[v.Category]++
			a.BySeverity[v.Severity]++
		}
		all = append(all, kv{d.ID, d.Hostname, snap.Score, len(snap.Violations)})
	}
	a.Baselines = len(s.baselines)
	a.BlacklistN = len(s.blacklist)
	a.BlackHits = len(s.hits)
	a.VulnRules = len(s.vulnRules)
	for _, it := range s.vulnItems {
		if it.State == VulnStateOpen {
			a.VulnOpen++
		}
	}
	s.mu.Unlock()
	if a.Scored > 0 {
		a.AvgScore = sum / a.Scored
	}
	sort.Slice(all, func(i, j int) bool { return all[i].score < all[j].score })
	for i, x := range all {
		if i >= 5 {
			break
		}
		a.WorstTop5 = append(a.WorstTop5, map[string]any{
			"device_id": x.id, "device_name": x.name, "score": x.score, "violations": x.viol})
	}
	writeJSON(w, map[string]any{"code": 0, "overview": a})
}

func (h *Hub) w5aViolations(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	s := w5a(h)
	q := r.URL.Query()
	wantDev, wantCat, wantSev := q.Get("device_id"), q.Get("category"), q.Get("severity")
	type row struct {
		DeviceID   string `json:"device_id"`
		DeviceName string `json:"device_name"`
		Key        string `json:"key"`
		Name       string `json:"name"`
		Category   string `json:"category"`
		Severity   string `json:"severity"`
		Expected   string `json:"expected"`
		Actual     string `json:"actual"`
		Detail     string `json:"detail"`
	}
	rows := []row{}
	s.mu.Lock()
	for id, snap := range s.snapshots {
		if wantDev != "" && id != wantDev {
			continue
		}
		for _, v := range snap.Violations {
			if wantCat != "" && v.Category != wantCat {
				continue
			}
			if wantSev != "" && v.Severity != wantSev {
				continue
			}
			rows = append(rows, row{DeviceID: id, DeviceName: snap.DeviceName, Key: v.Key, Name: v.Name,
				Category: v.Category, Severity: v.Severity, Expected: v.Expected, Actual: v.Actual, Detail: v.Detail})
		}
	}
	s.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DeviceID != rows[j].DeviceID {
			return rows[i].DeviceID < rows[j].DeviceID
		}
		return rows[i].Key < rows[j].Key
	})
	writeJSON(w, map[string]any{"code": 0, "total": len(rows), "violations": rows})
}

// w5aReport 合规/软件上报入口：副端采集结果或中枢侧补录（含软件清单）均由此进入评估。
func (h *Hub) w5aReport(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in proto.ComplianceReportPayload
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5201, "invalid body: "+err.Error())
		return
	}
	if in.DeviceID == "" {
		writeErr5a(w, 5207, "device_id required")
		return
	}
	dev, ok := h.store.Get(in.DeviceID)
	if !ok {
		writeErr5a(w, 5205, "device not found")
		return
	}
	// 软件清单补录（可选）：更新设备台账后触发黑名单/漏洞实时匹配
	if len(in.Software) > 0 {
		dev.SetSoftware(in.Software)
		dev = h.store.Upsert(dev)
		hits := h.w5aScanBlacklist(dev)
		h.w5aScanVulns(dev)
		h.w5aAutoVerifyTasks(dev)
		h.audit(claims.Username, "software_report", dev.ID,
			fmt.Sprintf("软件数=%d 命中=%d", len(in.Software), len(hits)), "success")
	}
	var snap *DeviceCompliance
	if len(in.Items) > 0 {
		snap = h.w5aApplyCompliance(dev, in.Items)
		h.audit(claims.Username, "compliance_report", dev.ID,
			fmt.Sprintf("采集项=%d 合规分=%d", len(in.Items), snap.Score), "success")
	}
	s := w5a(h)
	s.mu.Lock()
	if snap == nil {
		snap = s.snapshots[dev.ID]
	}
	hits, vulns := len(s.hits), len(s.vulnItems)
	s.mu.Unlock()
	writeJSON(w, map[string]any{"code": 0, "device_id": dev.ID, "compliance": snap,
		"blacklist_hits": hits, "vuln_items": vulns})
}

// ===================== HTTP：W5-2 处理函数 =====================

func (h *Hub) w5aGuardBlacklistRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aBlacklistList).ServeHTTP(w, r)
	case http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5aBlacklistCreate).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aGuardBlacklistItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aBlacklistGet).ServeHTTP(w, r)
	case http.MethodPut, http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5aBlacklistUpdate).ServeHTTP(w, r)
	case http.MethodDelete:
		h.guard(auth.PermSoftwareMgmt, h.w5aBlacklistDelete).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aBlacklistList(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	out := make([]*BlacklistRule, 0, len(s.blacklist))
	for _, r := range s.blacklist {
		out = append(out, r)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "rules": out})
}

func (h *Hub) w5aBlacklistCreate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in BlacklistRule
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5211, "invalid body: "+err.Error())
		return
	}
	if in.Pattern == "" {
		writeErr5a(w, 5212, "pattern required")
		return
	}
	if in.Name == "" {
		in.Name = in.Pattern
	}
	if in.MatchType == "" {
		in.MatchType = "exact"
	}
	if in.Action == "" {
		in.Action = "alert"
	}
	if in.Severity == "" {
		in.Severity = store.SeverityWarning
	}
	now := time.Now().UTC()
	in.ID = "bkl-" + randHex(6)
	in.Enabled = true
	in.CreatedAt, in.UpdatedAt = now, now
	s := w5a(h)
	s.mu.Lock()
	s.blacklist[in.ID] = &in
	s.mu.Unlock()
	w5aPGSave(h, "w5a_blacklist_rules", in.ID, in)
	h.audit(claims.Username, "blacklist_rule_create", in.ID,
		in.Name+" ["+in.MatchType+"] "+in.Pattern+" action="+in.Action, "success")
	writeJSON(w, map[string]any{"code": 0, "rule": in})
}

func (h *Hub) w5aBlacklistGet(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/blacklist/rules/")
	s := w5a(h)
	s.mu.Lock()
	rule, ok := s.blacklist[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5213, "rule not found")
		return
	}
	writeJSON(w, map[string]any{"code": 0, "rule": rule})
}

func (h *Hub) w5aBlacklistUpdate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/blacklist/rules/")
	s := w5a(h)
	s.mu.Lock()
	rule, ok := s.blacklist[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5213, "rule not found")
		return
	}
	var in BlacklistRule
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5211, "invalid body: "+err.Error())
		return
	}
	s.mu.Lock()
	if in.Name != "" {
		rule.Name = in.Name
	}
	if in.MatchType != "" {
		rule.MatchType = in.MatchType
	}
	if in.Pattern != "" {
		rule.Pattern = in.Pattern
	}
	if in.Severity != "" {
		rule.Severity = in.Severity
	}
	if in.Action != "" {
		rule.Action = in.Action
	}
	rule.Enabled = in.Enabled || r.URL.Query().Get("enabled") != "false"
	rule.UpdatedAt = time.Now().UTC()
	cp := *rule
	s.mu.Unlock()
	w5aPGSave(h, "w5a_blacklist_rules", cp.ID, cp)
	h.audit(claims.Username, "blacklist_rule_update", cp.ID, cp.Name+" enabled="+itoa(boolInt(cp.Enabled)), "success")
	writeJSON(w, map[string]any{"code": 0, "rule": cp})
}

func (h *Hub) w5aBlacklistDelete(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/blacklist/rules/")
	s := w5a(h)
	s.mu.Lock()
	_, ok := s.blacklist[id]
	if ok {
		delete(s.blacklist, id)
	}
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5213, "rule not found")
		return
	}
	w5aPGDelete(h, "w5a_blacklist_rules", id)
	h.audit(claims.Username, "blacklist_rule_delete", id, "", "success")
	writeJSON(w, map[string]any{"code": 0, "id": id})
}

// w5aBlacklistImport 批量导入（JSON）：{"rules":[{...}]}，逐条 upsert。
func (h *Hub) w5aBlacklistImport(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in struct {
		Rules []BlacklistRule `json:"rules"`
	}
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5211, "invalid body: "+err.Error())
		return
	}
	if len(in.Rules) == 0 {
		writeErr5a(w, 5214, "rules empty")
		return
	}
	now := time.Now().UTC()
	s := w5a(h)
	n := 0
	s.mu.Lock()
	for _, r := range in.Rules {
		if r.Pattern == "" {
			continue
		}
		if r.ID == "" {
			r.ID = "bkl-" + randHex(6)
		}
		if r.MatchType == "" {
			r.MatchType = "exact"
		}
		if r.Action == "" {
			r.Action = "alert"
		}
		if r.Severity == "" {
			r.Severity = store.SeverityWarning
		}
		r.Enabled = true
		r.CreatedAt, r.UpdatedAt = now, now
		cp := r
		s.blacklist[cp.ID] = &cp
		w5aPGSave(h, "w5a_blacklist_rules", cp.ID, cp)
		n++
	}
	s.mu.Unlock()
	h.audit(claims.Username, "blacklist_import", "", "导入规则="+itoa(n), "success")
	writeJSON(w, map[string]any{"code": 0, "imported": n})
}

func (h *Hub) w5aBlacklistExport(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	out := make([]*BlacklistRule, 0, len(s.blacklist))
	for _, r := range s.blacklist {
		out = append(out, r)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "rules": out})
}

func (h *Hub) w5aBlacklistHits(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	wantDev, wantRule := r.URL.Query().Get("device_id"), r.URL.Query().Get("rule_id")
	s := w5a(h)
	s.mu.Lock()
	out := make([]*BlacklistHit, 0, len(s.hits))
	for _, x := range s.hits {
		if wantDev != "" && x.DeviceID != wantDev {
			continue
		}
		if wantRule != "" && x.RuleID != wantRule {
			continue
		}
		out = append(out, x)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "hits": out})
}

// w5aBlacklistByDevice 按设备聚合违规视图。
func (h *Hub) w5aBlacklistByDevice(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	m := map[string][]BlacklistHit{}
	for _, x := range s.hits {
		m[x.DeviceID] = append(m[x.DeviceID], *x)
	}
	s.mu.Unlock()
	out := make([]map[string]any, 0, len(m))
	for devID, list := range m {
		name := ""
		if len(list) > 0 {
			name = list[0].DeviceName
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID > list[j].ID })
		out = append(out, map[string]any{"device_id": devID, "device_name": name, "hits": len(list), "software": list})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["hits"].(int) > out[j]["hits"].(int) })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "devices": out})
}

// w5aBlacklistBySoftware 按软件聚合违规视图。
func (h *Hub) w5aBlacklistBySoftware(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	m := map[string]int{}
	devs := map[string]map[string]bool{}
	for _, x := range s.hits {
		m[x.Software]++
		if devs[x.Software] == nil {
			devs[x.Software] = map[string]bool{}
		}
		devs[x.Software][x.DeviceID] = true
	}
	s.mu.Unlock()
	out := make([]map[string]any, 0, len(m))
	for sw, n := range m {
		out = append(out, map[string]any{"software": sw, "hits": n, "devices": len(devs[sw])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["hits"].(int) > out[j]["hits"].(int) })
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "software": out})
}

// w5aBlacklistScan 对指定设备重新做黑名单匹配（可随请求补录软件清单）。
func (h *Hub) w5aBlacklistScan(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/blacklist/scan/")
	dev, ok := h.store.Get(id)
	if !ok {
		writeErr5a(w, 5205, "device not found")
		return
	}
	if r.Method == http.MethodPost {
		var in struct {
			Software []proto.InstalledSoftware `json:"software"`
		}
		_ = w5aDecode(r, &in)
		if len(in.Software) > 0 {
			dev.SetSoftware(in.Software)
			dev = h.store.Upsert(dev)
		}
	}
	hits := h.w5aScanBlacklist(dev)
	h.audit(claims.Username, "blacklist_scan", id, "命中="+itoa(len(hits)), "success")
	writeJSON(w, map[string]any{"code": 0, "device_id": id, "hits": hits, "total": len(hits)})
}

// ===================== HTTP：W5-5 处理函数 =====================

func (h *Hub) w5aGuardVulnRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aVulnRuleList).ServeHTTP(w, r)
	case http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5aVulnRuleCreate).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aGuardVulnRuleItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aVulnRuleGet).ServeHTTP(w, r)
	case http.MethodPut, http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5aVulnRuleUpdate).ServeHTTP(w, r)
	case http.MethodDelete:
		h.guard(auth.PermSoftwareMgmt, h.w5aVulnRuleDelete).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aVulnRuleList(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	out := make([]*VulnRule, 0, len(s.vulnRules))
	for _, r := range s.vulnRules {
		out = append(out, r)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "rules": out})
}

func (h *Hub) w5aVulnRuleCreate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in VulnRule
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5221, "invalid body: "+err.Error())
		return
	}
	if in.Software == "" || in.CVE == "" {
		writeErr5a(w, 5222, "software and cve required")
		return
	}
	if in.Severity == "" {
		in.Severity = store.SeverityWarning
	}
	now := time.Now().UTC()
	in.ID = "vr-" + randHex(6)
	in.Enabled = true
	in.CreatedAt, in.UpdatedAt = now, now
	s := w5a(h)
	s.mu.Lock()
	s.vulnRules[in.ID] = &in
	s.mu.Unlock()
	w5aPGSave(h, "w5a_vuln_rules", in.ID, in)
	h.audit(claims.Username, "vuln_rule_create", in.ID,
		fmt.Sprintf("%s %s %s 修复=%s", in.CVE, in.Software, in.AffectedVersions, in.FixVersion), "success")
	writeJSON(w, map[string]any{"code": 0, "rule": in})
}

func (h *Hub) w5aVulnRuleGet(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/vuln/rules/")
	s := w5a(h)
	s.mu.Lock()
	rule, ok := s.vulnRules[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5223, "rule not found")
		return
	}
	writeJSON(w, map[string]any{"code": 0, "rule": rule})
}

func (h *Hub) w5aVulnRuleUpdate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/vuln/rules/")
	s := w5a(h)
	s.mu.Lock()
	rule, ok := s.vulnRules[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5223, "rule not found")
		return
	}
	var in VulnRule
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5221, "invalid body: "+err.Error())
		return
	}
	s.mu.Lock()
	if in.Software != "" {
		rule.Software = in.Software
	}
	if in.CVE != "" {
		rule.CVE = in.CVE
	}
	if in.AffectedVersions != "" {
		rule.AffectedVersions = in.AffectedVersions
	}
	if in.Severity != "" {
		rule.Severity = in.Severity
	}
	if in.FixVersion != "" {
		rule.FixVersion = in.FixVersion
	}
	if in.Advisory != "" {
		rule.Advisory = in.Advisory
	}
	rule.Enabled = in.Enabled || r.URL.Query().Get("enabled") != "false"
	rule.UpdatedAt = time.Now().UTC()
	cp := *rule
	s.mu.Unlock()
	w5aPGSave(h, "w5a_vuln_rules", cp.ID, cp)
	h.audit(claims.Username, "vuln_rule_update", cp.ID, cp.CVE, "success")
	writeJSON(w, map[string]any{"code": 0, "rule": cp})
}

func (h *Hub) w5aVulnRuleDelete(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/vuln/rules/")
	s := w5a(h)
	s.mu.Lock()
	_, ok := s.vulnRules[id]
	if ok {
		delete(s.vulnRules, id)
	}
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5223, "rule not found")
		return
	}
	w5aPGDelete(h, "w5a_vuln_rules", id)
	h.audit(claims.Username, "vuln_rule_delete", id, "", "success")
	writeJSON(w, map[string]any{"code": 0, "id": id})
}

// w5aVulnRuleImport 漏洞规则库 JSON 导入：{"rules":[{cve,software,affected_versions,...}]}。
func (h *Hub) w5aVulnRuleImport(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in struct {
		Rules []VulnRule `json:"rules"`
	}
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5221, "invalid body: "+err.Error())
		return
	}
	if len(in.Rules) == 0 {
		writeErr5a(w, 5224, "rules empty")
		return
	}
	now := time.Now().UTC()
	s := w5a(h)
	n := 0
	s.mu.Lock()
	for _, r := range in.Rules {
		if r.Software == "" || r.CVE == "" {
			continue
		}
		if r.ID == "" {
			r.ID = "vr-" + randHex(6)
		}
		if r.Severity == "" {
			r.Severity = store.SeverityWarning
		}
		r.Enabled = true
		r.CreatedAt, r.UpdatedAt = now, now
		cp := r
		s.vulnRules[cp.ID] = &cp
		w5aPGSave(h, "w5a_vuln_rules", cp.ID, cp)
		n++
	}
	s.mu.Unlock()
	h.audit(claims.Username, "vuln_rule_import", "", "导入规则="+itoa(n), "success")
	writeJSON(w, map[string]any{"code": 0, "imported": n})
}

func (h *Hub) w5aVulnItems(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	q := r.URL.Query()
	wantDev, wantCVE, wantSev, wantState := q.Get("device_id"), q.Get("cve"), q.Get("severity"), q.Get("state")
	s := w5a(h)
	s.mu.Lock()
	out := make([]*VulnItem, 0, len(s.vulnItems))
	for _, it := range s.vulnItems {
		if wantDev != "" && it.DeviceID != wantDev {
			continue
		}
		if wantCVE != "" && !strings.EqualFold(it.CVE, wantCVE) {
			continue
		}
		if wantSev != "" && it.Severity != wantSev {
			continue
		}
		if wantState != "" && it.State != wantState {
			continue
		}
		out = append(out, it)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "items": out})
}

// w5aGuardVulnItemByID 漏洞项操作：GET 详情 / POST .../accept 接受风险。
func (h *Hub) w5aGuardVulnItemByID(w http.ResponseWriter, r *http.Request) {
	rest := idAfterPrefix(r.URL.Path, "/api/v1/vuln/items/")
	if strings.HasSuffix(rest, "/accept") && r.Method == http.MethodPost {
		h.guard(auth.PermSoftwareMgmt, h.w5aVulnAccept).ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodGet {
		h.guard(auth.PermDeviceView, h.w5aVulnItemGet).ServeHTTP(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *Hub) w5aVulnItemGet(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/vuln/items/")
	s := w5a(h)
	s.mu.Lock()
	it, ok := s.vulnItems[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5225, "vuln item not found")
		return
	}
	writeJSON(w, map[string]any{"code": 0, "item": it})
}

func (h *Hub) w5aVulnAccept(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := strings.TrimSuffix(idAfterPrefix(r.URL.Path, "/api/v1/vuln/items/"), "/accept")
	s := w5a(h)
	s.mu.Lock()
	it, ok := s.vulnItems[id]
	if ok {
		it.State = VulnStateAccepted
		it.UpdatedAt = time.Now().UTC()
	}
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5225, "vuln item not found")
		return
	}
	w5aPGSave(h, "w5a_vuln_items", it.ID, it)
	h.audit(claims.Username, "vuln_accept", it.DeviceID,
		fmt.Sprintf("%s %s %s 接受风险", it.CVE, it.Software, it.Version), "success")
	writeJSON(w, map[string]any{"code": 0, "item": it})
}

// w5aVulnScan 对指定设备重新做漏洞匹配（可随请求补录软件清单）。
func (h *Hub) w5aVulnScan(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/vuln/scan/")
	dev, ok := h.store.Get(id)
	if !ok {
		writeErr5a(w, 5205, "device not found")
		return
	}
	if r.Method == http.MethodPost {
		var in struct {
			Software []proto.InstalledSoftware `json:"software"`
		}
		_ = w5aDecode(r, &in)
		if len(in.Software) > 0 {
			dev.SetSoftware(in.Software)
			dev = h.store.Upsert(dev)
		}
	}
	items := h.w5aScanVulns(dev)
	h.w5aAutoVerifyTasks(dev)
	h.audit(claims.Username, "vuln_scan", id, "漏洞项="+itoa(len(items)), "success")
	writeJSON(w, map[string]any{"code": 0, "device_id": id, "items": items, "total": len(items)})
}

// w5aVulnSeverityCounts 统计 open 状态漏洞项的严重度分布，供 stats/overview 与报表复用。
//
// v0.4.25：波次 5a 的本地漏洞规则扫描已是真实数据源，stats/overview 不再返回占位 0。
// 严重度按 VulnRule.Severity 原样分桶（info/warning/critical，见 store.Severity* 常量），
// 不做主观映射；兼容自定义取值。PG 与内存两种后端共用 w5a(h) 状态（含首次 PG 装载），
// 因此无需为持久化后端单独接线。本函数只读取状态，不触发扫描或写库。
func (h *Hub) w5aVulnSeverityCounts() (int, map[string]int) {
	s := w5a(h)
	bySev := map[string]int{}
	open := 0
	s.mu.Lock()
	for _, it := range s.vulnItems {
		if it.State == VulnStateOpen {
			open++
			bySev[it.Severity]++
		}
	}
	s.mu.Unlock()
	return open, bySev
}

// w5aVulnOverview 供 wave5.go 的 vulnOverviewProvider 消费（stats/overview 与报表）。
//
// 按波次 5a 真实严重度（info/warning/critical）原样分桶，不做主观映射：
// 项目三档是合规告警级别而非 CVSS，强行映射成 critical/high/medium/low 会制造
// 假精度，与铁律 5「诚实回告」冲突；前端 pages.tsx 用 Object.entries 动态遍历，
// 按原值分桶零契约破坏。by_severity_raw 保留同一原始分布，便于审计与后续接 CVSS。
func (h *Hub) w5aVulnOverview() map[string]any {
	open, bySev := h.w5aVulnSeverityCounts()
	return map[string]any{
		"available":       true,
		"total":           open,
		"by_severity":     bySev,
		"by_severity_raw": bySev,
		"note":            "数据源：波次 5a 本地漏洞规则扫描的 open 项（按 info/warning/critical 原样分桶）；未创建漏洞规则或设备未上报软件清单时为 0 属正常",
	}
}

// 注册依赖倒置钩子：wave5b.go 通过 vulnOverviewProvider 消费，不直接引用本文件符号。
func init() {
	vulnOverviewProvider = func(h *Hub) map[string]any { return h.w5aVulnOverview() }
}

// w5aVulnSummary 漏洞聚合视图（按严重度 / CVE / 设备 统计 open 项）。
func (h *Hub) w5aVulnSummary(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	bySev := map[string]int{}
	byCVE := map[string]int{}
	byDev := map[string]int{}
	stateCount := map[string]int{}
	open := 0
	for _, it := range s.vulnItems {
		stateCount[it.State]++
		if it.State == VulnStateOpen {
			open++
			bySev[it.Severity]++
			byCVE[it.CVE]++
			byDev[it.DeviceID]++
		}
	}
	s.mu.Unlock()
	type kv struct {
		K string `json:"key"`
		N int    `json:"count"`
	}
	toList := func(m map[string]int) []kv {
		out := make([]kv, 0, len(m))
		for k, v := range m {
			out = append(out, kv{k, v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N })
		return out
	}
	writeJSON(w, map[string]any{"code": 0, "summary": map[string]any{
		"open": open, "by_state": stateCount, "by_severity": toList(bySev),
		"by_cve": toList(byCVE), "by_device": toList(byDev),
	}})
}

func (h *Hub) w5aGuardPatchTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aTaskList).ServeHTTP(w, r)
	case http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5aTaskCreate).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aGuardPatchTaskItem(w http.ResponseWriter, r *http.Request) {
	rest := idAfterPrefix(r.URL.Path, "/api/v1/vuln/tasks/")
	switch {
	case strings.HasSuffix(rest, "/dispatch") && r.Method == http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5aTaskDispatch).ServeHTTP(w, r)
	case strings.HasSuffix(rest, "/verify") && r.Method == http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5aTaskVerify).ServeHTTP(w, r)
	case r.Method == http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aTaskGet).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aTaskList(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	wantDev, wantState := r.URL.Query().Get("device_id"), r.URL.Query().Get("state")
	s := w5a(h)
	s.mu.Lock()
	out := make([]*PatchTask, 0, len(s.tasks))
	for _, t := range s.tasks {
		if wantDev != "" && t.DeviceID != wantDev {
			continue
		}
		if wantState != "" && t.State != wantState {
			continue
		}
		out = append(out, t)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "tasks": out})
}

func (h *Hub) w5aTaskGet(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/vuln/tasks/")
	s := w5a(h)
	s.mu.Lock()
	t, ok := s.tasks[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5231, "task not found")
		return
	}
	writeJSON(w, map[string]any{"code": 0, "task": t})
}

// w5aTaskCreate 创建修复任务：{device_id, software, target_version, repo_item_id, item_ids[]}。
// item_ids 为空时自动关联该设备该软件的 open 漏洞项；target_version 为空时取漏洞项 fix_version。
func (h *Hub) w5aTaskCreate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in PatchTask
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5232, "invalid body: "+err.Error())
		return
	}
	if in.DeviceID == "" || in.Software == "" {
		writeErr5a(w, 5233, "device_id and software required")
		return
	}
	dev, ok := h.store.Get(in.DeviceID)
	if !ok {
		writeErr5a(w, 5205, "device not found")
		return
	}
	s := w5a(h)
	s.mu.Lock()
	target := in.TargetVersion
	var ids []string
	for _, it := range s.vulnItems {
		if it.DeviceID == in.DeviceID && w5aSoftwareMatch(it.Software, in.Software) && it.State == VulnStateOpen {
			ids = append(ids, it.ID)
			if target == "" {
				target = it.FixVersion
			}
		}
	}
	if len(in.ItemIDs) > 0 {
		ids = in.ItemIDs
	}
	if target == "" {
		s.mu.Unlock()
		writeErr5a(w, 5234, "target_version required (or related open vuln item with fix_version)")
		return
	}
	s.seq["task"]++
	t := &PatchTask{
		ID:       "pt-" + itoa(int(s.seq["task"])) + "-" + randHex(4),
		DeviceID: in.DeviceID, DeviceName: dev.Hostname, Software: in.Software,
		TargetVersion: target, RepoItemID: in.RepoItemID, ItemIDs: ids,
		State: PatchTaskPending, Note: in.Note,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	s.tasks[t.ID] = t
	for _, id := range ids {
		if it, ok := s.vulnItems[id]; ok {
			it.TaskID = t.ID
			w5aPGSave(h, "w5a_vuln_items", it.ID, it)
		}
	}
	s.mu.Unlock()
	w5aPGSave(h, "w5a_vuln_tasks", t.ID, t)
	h.audit(claims.Username, "patch_task_create", t.DeviceID,
		fmt.Sprintf("任务=%s 软件=%s 目标=%s 关联漏洞=%d", t.ID, t.Software, t.TargetVersion, len(ids)), "success")
	writeJSON(w, map[string]any{"code": 0, "task": t})
}

func (h *Hub) w5aTaskDispatch(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := strings.TrimSuffix(idAfterPrefix(r.URL.Path, "/api/v1/vuln/tasks/"), "/dispatch")
	s := w5a(h)
	s.mu.Lock()
	t, ok := s.tasks[id]
	s.mu.Unlock()
	if !ok {
		writeErr5a(w, 5231, "task not found")
		return
	}
	okSend := h.w5aDispatchPatch(t)
	h.audit(claims.Username, "patch_task_dispatch_api", t.DeviceID,
		fmt.Sprintf("任务=%s 状态=%s", t.ID, t.State), "success")
	writeJSON(w, map[string]any{"code": 0, "task": t, "dispatched": okSend})
}

func (h *Hub) w5aTaskVerify(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := strings.TrimSuffix(idAfterPrefix(r.URL.Path, "/api/v1/vuln/tasks/"), "/verify")
	t, met := h.w5aVerifyTask(id)
	if t == nil {
		writeErr5a(w, 5231, "task not found")
		return
	}
	h.audit(claims.Username, "patch_task_verify", t.DeviceID,
		fmt.Sprintf("任务=%s 达标=%v 状态=%s", t.ID, met, t.State), "success")
	writeJSON(w, map[string]any{"code": 0, "task": t, "patched": met})
}

// w5aGuardExceptions 例外名单：GET 列表 / POST 新增。
func (h *Hub) w5aGuardExceptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5aExceptionList).ServeHTTP(w, r)
	case http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5aExceptionCreate).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) w5aExceptionList(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := w5a(h)
	s.mu.Lock()
	out := make([]*VulnException, 0, len(s.exceptions))
	for _, e := range s.exceptions {
		out = append(out, e)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "exceptions": out})
}

func (h *Hub) w5aExceptionCreate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in VulnException
	if err := w5aDecode(r, &in); err != nil {
		writeErr5a(w, 5241, "invalid body: "+err.Error())
		return
	}
	if in.Software == "" && in.CVE == "" {
		writeErr5a(w, 5242, "software or cve required")
		return
	}
	in.ID = "ve-" + randHex(6)
	in.CreatedAt = time.Now().UTC()
	s := w5a(h)
	s.mu.Lock()
	s.exceptions[in.ID] = &in
	s.mu.Unlock()
	w5aPGSave(h, "w5a_vuln_exceptions", in.ID, in)
	h.audit(claims.Username, "vuln_exception_create", in.DeviceID,
		fmt.Sprintf("软件=%s CVE=%s 原因=%s", in.Software, in.CVE, in.Reason), "success")
	writeJSON(w, map[string]any{"code": 0, "exception": in})
}

// ===================== 集成说明 =====================
//
// W5-6 策略中心调用入口（跨单元契约）：
//   ComplianceIssues(h, deviceID) []ComplianceIssue  —— 设备当前不合规项（空切片=无问题/无数据）
//   DeviceComplianceScore(h, deviceID) int           —— 设备合规分 0-100（无数据 -1）
//
// W5-5 与波次 3「分发任务」的集成点：PatchTask.RepoItemID 预留仓库软件包 ID；
// 真实安装能力由波次 3 提供（sw_install 静默安装 + 失败重试）。本波次的 w5aDispatchPatch
// 走 patch_apply 轻量指令：波次 3 就绪后，只需把 w5aDispatchPatch 内的指令下发替换为
// 波次 3 的分发任务创建调用（任务 ID 回写 PatchTask.Note），闭环逻辑（版本比对 → patched）
// 无需改动。
