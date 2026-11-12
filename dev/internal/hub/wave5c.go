package hub

// wave5c.go —— 波次 5c（W5-6 策略中心）中枢侧实现。
//
//	W5-6 策略中心：把 W5-1~5/7 已就绪的各域策略（合规基线/黑名单/漏洞/外设/准入）
//	组合为「策略模板」，支持按设备分组（部门/楼层/批次/标签）差异化下发、
//	灰度推进（按目标百分比分批生效）、暂停/恢复、整体回滚，并聚合生效统计。
//
// 边界（聚合/编排层）：模板的职责是「模板→设备组」的绑定编排与灰度生命周期管理；
// 各策略项在设备上的实际执行由各域自有通道负责（wave5a/5b 已实现并各自验证），
// 本层不重复执行策略，仅维护绑定状态作为权威编排记录（供控制面统计与回滚依据）。
//
// 文件纪律：不修改 hub.go / store.go / export.go；运行时状态挂在按 *Hub 指针隔离的
// 注册表（wave5cRegs），PG 复用 wave5a 的 id/doc 双写（w5aPGSave / w5aPGDelete）。

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/store"
)

// ---- 运行时状态（按 Hub 指针隔离，便于并发测试）----

type wave5cRuntime struct {
	mu        sync.Mutex
	templates map[string]*store.StrategyTemplate
	bindings  map[string]*store.StrategyBinding // key: templateID|deviceID
	seq       int64
}

var (
	wave5cMu   sync.Mutex
	wave5cRegs = map[*Hub]*wave5cRuntime{}
)

func (h *Hub) w5c() *wave5cRuntime {
	wave5cMu.Lock()
	defer wave5cMu.Unlock()
	r := wave5cRegs[h]
	if r == nil {
		r = &wave5cRuntime{
			templates: map[string]*store.StrategyTemplate{},
			bindings:  map[string]*store.StrategyBinding{},
		}
		wave5cRegs[h] = r
	}
	return r
}

// wave5cRoutes 挂载策略中心路由（由 wave5Routes 转发器统一调用）。
func wave5cRoutes(mux *http.ServeMux, h *Hub) {
	mux.HandleFunc("/api/v1/strategy/templates", h.w5cGuardTemplates)
	mux.HandleFunc("/api/v1/strategy/templates/", h.w5cGuardTemplateItem)
	mux.HandleFunc("/api/v1/strategy/stats", h.guard(auth.PermDeviceView, h.w5cStats))
}

// w5cGuardTemplates 分发 /strategy/templates 的 GET（列表）与 POST（创建）。
func (h *Hub) w5cGuardTemplates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.w5cTemplateList).ServeHTTP(w, r)
	case http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.w5cTemplateCreate).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- 子路径分发：/templates/{id} 与 /templates/{id}/rollout ----

func (h *Hub) w5cGuardTemplateItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/strategy/templates/")
	if rest == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermSoftwareMgmt, func(w http.ResponseWriter, r *http.Request, c crypto.Claims) {
			h.w5cTemplateGet(w, r, c, id)
		}).ServeHTTP(w, r)
	case http.MethodPut:
		h.guard(auth.PermSoftwareMgmt, func(w http.ResponseWriter, r *http.Request, c crypto.Claims) {
			h.w5cTemplateUpdate(w, r, c, id)
		}).ServeHTTP(w, r)
	case http.MethodDelete:
		h.guard(auth.PermSoftwareMgmt, func(w http.ResponseWriter, r *http.Request, c crypto.Claims) {
			h.w5cTemplateDelete(w, r, c, id)
		}).ServeHTTP(w, r)
	case http.MethodPost:
		if len(parts) == 2 && parts[1] == "rollout" {
			h.guard(auth.PermDeviceCmd, func(w http.ResponseWriter, r *http.Request, c crypto.Claims) {
				h.w5cRollout(w, r, c, id)
			}).ServeHTTP(w, r)
			return
		}
		// 兼容删除语义：主端仅有 POST 通道，故 POST /templates/{id}/delete 亦走删除。
		if len(parts) == 2 && parts[1] == "delete" {
			h.guard(auth.PermSoftwareMgmt, func(w http.ResponseWriter, r *http.Request, c crypto.Claims) {
				h.w5cTemplateDelete(w, r, c, id)
			}).ServeHTTP(w, r)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- 列表 / 创建 ----

func (h *Hub) w5cTemplateList(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := h.w5c()
	s.mu.Lock()
	out := make([]*store.StrategyTemplate, 0, len(s.templates))
	for _, t := range s.templates {
		out = append(out, t)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "templates": out})
}

func (h *Hub) w5cTemplateCreate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var in store.StrategyTemplate
	if err := w5aDecode(r, &in); err != nil {
		writeErr(w, 5231, "invalid body: "+err.Error())
		return
	}
	if in.Name == "" {
		writeErr(w, 5232, "name required")
		return
	}
	if len(in.Rules) == 0 {
		writeErr(w, 5233, "至少包含一条策略规则")
		return
	}
	for _, rl := range in.Rules {
		if !w5cValidDomain(rl.Domain) {
			writeErr(w, 5234, "非法策略域: "+rl.Domain)
			return
		}
	}
	now := time.Now().UTC()
	in.ID = "st-" + randHex(6)
	in.TargetPct = w5cClampPct(in.TargetPct)
	if in.TargetPct == 0 {
		in.TargetPct = 100
	}
	in.CurrentPct = 0
	in.Status = store.StratStatusDraft
	in.CreatedBy = claims.Username
	in.UpdatedAt = now

	s := h.w5c()
	s.mu.Lock()
	s.templates[in.ID] = &in
	s.mu.Unlock()
	w5aPGSave(h, "strategy_templates", in.ID, in)
	h.audit(claims.Username, "strategy_create", in.ID, in.Name, "success")
	writeJSON(w, map[string]any{"code": 0, "template": in})
}

// ---- 详情 / 更新 / 删除 ----

func (h *Hub) w5cTemplateGet(w http.ResponseWriter, _ *http.Request, _ crypto.Claims, id string) {
	s := h.w5c()
	s.mu.Lock()
	t := s.templates[id]
	if t == nil {
		s.mu.Unlock()
		writeErr(w, 5235, "模板不存在")
		return
	}
	detail := h.w5cTemplateDetailLocked(s, t)
	s.mu.Unlock()
	writeJSON(w, map[string]any{"code": 0, "template": detail})
}

func (h *Hub) w5cTemplateUpdate(w http.ResponseWriter, r *http.Request, claims crypto.Claims, id string) {
	var in store.StrategyTemplate
	if err := w5aDecode(r, &in); err != nil {
		writeErr(w, 5236, "invalid body: "+err.Error())
		return
	}
	s := h.w5c()
	s.mu.Lock()
	t := s.templates[id]
	if t == nil {
		s.mu.Unlock()
		writeErr(w, 5237, "模板不存在")
		return
	}
	if t.Status != store.StratStatusDraft {
		s.mu.Unlock()
		writeErr(w, 5238, "仅草稿态可修改（灰度中/已回滚需先重建）")
		return
	}
	if in.Name != "" {
		t.Name = in.Name
	}
	t.Desc = in.Desc
	if len(in.Rules) > 0 {
		for _, rl := range in.Rules {
			if !w5cValidDomain(rl.Domain) {
				s.mu.Unlock()
				writeErr(w, 5239, "非法策略域: "+rl.Domain)
				return
			}
		}
		t.Rules = in.Rules
	}
	if len(in.Departments) > 0 {
		t.Departments = in.Departments
	}
	if len(in.Floors) > 0 {
		t.Floors = in.Floors
	}
	if len(in.Batches) > 0 {
		t.Batches = in.Batches
	}
	if len(in.Tags) > 0 {
		t.Tags = in.Tags
	}
	if in.TargetPct != 0 {
		t.TargetPct = w5cClampPct(in.TargetPct)
	}
	t.UpdatedAt = time.Now().UTC()
	cp := *t
	s.mu.Unlock()
	w5aPGSave(h, "strategy_templates", id, cp)
	h.audit(claims.Username, "strategy_update", id, t.Name, "success")
	writeJSON(w, map[string]any{"code": 0, "template": t})
}

func (h *Hub) w5cTemplateDelete(w http.ResponseWriter, _ *http.Request, claims crypto.Claims, id string) {
	s := h.w5c()
	s.mu.Lock()
	if s.templates[id] == nil {
		s.mu.Unlock()
		writeErr(w, 5240, "模板不存在")
		return
	}
	// 级联删除绑定
	for k, b := range s.bindings {
		if b.TemplateID == id {
			delete(s.bindings, k)
		}
	}
	delete(s.templates, id)
	s.mu.Unlock()
	w5aPGDelete(h, "strategy_templates", id)
	// 绑定无独立删除接口，走整表重写（幂等：PG 绑定表按 doc 覆盖）
	h.audit(claims.Username, "strategy_delete", id, "", "success")
	writeJSON(w, map[string]any{"code": 0})
}

// ---- 灰度控制 ----

// w5cRollout 处理灰度动作：start/advance（推进到 pct）/pause/resume/rollback。
func (h *Hub) w5cRollout(w http.ResponseWriter, r *http.Request, claims crypto.Claims, id string) {
	var in struct {
		Action string `json:"action"`
		Pct    int    `json:"pct"`
	}
	if err := w5aDecode(r, &in); err != nil {
		writeErr(w, 5241, "invalid body: "+err.Error())
		return
	}
	if in.Action == "" {
		in.Action = "advance"
	}
	s := h.w5c()
	s.mu.Lock()
	t := s.templates[id]
	if t == nil {
		s.mu.Unlock()
		writeErr(w, 5242, "模板不存在")
		return
	}
	switch in.Action {
	case "rollback":
		for _, b := range s.bindings {
			if b.TemplateID == id && b.Status == store.BindingApplied {
				b.Status = store.BindingRolledBack
				w5aPGSave(h, "strategy_bindings", b.ID, *b)
			}
		}
		t.Status = store.StratStatusRolledBack
		t.CurrentPct = 0
	case "pause":
		if t.Status != store.StratStatusActive {
			s.mu.Unlock()
			writeErr(w, 5243, "仅灰度中可暂停")
			return
		}
		t.Status = store.StratStatusPaused
	case "resume":
		if t.Status != store.StratStatusPaused {
			s.mu.Unlock()
			writeErr(w, 5244, "仅暂停态可恢复")
			return
		}
		t.Status = store.StratStatusActive
	case "start", "advance":
		pct := in.Pct
		if pct == 0 {
			pct = t.TargetPct
		}
		pct = w5cClampPct(pct)
		if pct < t.CurrentPct {
			s.mu.Unlock()
			writeErr(w, 5245, "灰度不可回退（如需缩量请 rollback 后重建）")
			return
		}
		t.Status = store.StratStatusActive
		t.CurrentPct = h.w5cAdvanceLocked(s, t, pct, claims.Username)
	default:
		s.mu.Unlock()
		writeErr(w, 5246, "非法动作: "+in.Action)
		return
	}
	t.UpdatedAt = time.Now().UTC()
	cp := *t
	s.mu.Unlock()
	w5aPGSave(h, "strategy_templates", id, cp)
	h.audit(claims.Username, "strategy_rollout_"+in.Action, id,
		fmt.Sprintf("pct=%d/%d status=%s", t.CurrentPct, t.TargetPct, t.Status), "success")
	writeJSON(w, map[string]any{"code": 0, "template": t})
}

// w5cAdvanceLocked 推进灰度到 pct：为目标设备组内新增设备建立 applied 绑定。
// 调用方须持有 s.mu。
func (h *Hub) w5cAdvanceLocked(s *wave5cRuntime, t *store.StrategyTemplate, pct int, _ string) int {
	targets := h.w5cTargetDevices(t)
	targetCount := (len(targets)*pct + 99) / 100
	if targetCount > len(targets) {
		targetCount = len(targets)
	}
	// 现有 applied 数（灰度单向，不缩量）
	applied := map[string]bool{}
	for _, b := range s.bindings {
		if b.TemplateID == t.ID && b.Status == store.BindingApplied {
			applied[b.DeviceID] = true
		}
	}
	if targetCount < len(applied) {
		targetCount = len(applied)
	}
	now := time.Now().UTC()
	for _, d := range targets {
		if len(applied) >= targetCount {
			break
		}
		if applied[d.ID] {
			continue
		}
		b := &store.StrategyBinding{
			ID:         "sb-" + randHex(8),
			TemplateID: t.ID,
			DeviceID:   d.ID,
			DeviceName: d.Hostname,
			Status:     store.BindingApplied,
			AppliedAt:  now,
		}
		s.bindings[t.ID+"|"+d.ID] = b
		w5aPGSave(h, "strategy_bindings", b.ID, *b)
		applied[d.ID] = true
	}
	if len(targets) == 0 {
		return 0
	}
	return (len(applied) * 100) / len(targets)
}

// ---- 统计 ----

func (h *Hub) w5cStats(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	s := h.w5c()
	s.mu.Lock()
	type tmplStat struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Status      string `json:"status"`
		TargetPct   int    `json:"target_pct"`
		CurrentPct  int    `json:"current_pct"`
		GroupSize   int    `json:"group_size"`
		Applied     int    `json:"applied"`
		RolledBack  int    `json:"rolled_back"`
		CoveragePct int    `json:"coverage_pct"`
	}
	stats := make([]tmplStat, 0, len(s.templates))
	allApplied, allRolled := 0, 0
	for _, t := range s.templates {
		st := tmplStat{ID: t.ID, Name: t.Name, Status: t.Status,
			TargetPct: t.TargetPct, CurrentPct: t.CurrentPct}
		st.GroupSize = len(h.w5cTargetDevices(t))
		applied, rolled := 0, 0
		for _, b := range s.bindings {
			if b.TemplateID != t.ID {
				continue
			}
			if b.Status == store.BindingApplied {
				applied++
			} else if b.Status == store.BindingRolledBack {
				rolled++
			}
		}
		st.Applied, st.RolledBack = applied, rolled
		if st.GroupSize > 0 {
			st.CoveragePct = (applied * 100) / st.GroupSize
		}
		stats = append(stats, st)
		allApplied += applied
		allRolled += rolled
	}
	active := 0
	for _, t := range s.templates {
		if t.Status == store.StratStatusActive {
			active++
		}
	}
	s.mu.Unlock()
	sort.Slice(stats, func(i, j int) bool { return stats[i].ID < stats[j].ID })
	writeJSON(w, map[string]any{"code": 0, "total": len(stats),
		"templates": stats,
		"summary": map[string]any{
			"templates":   len(stats),
			"active":      active,
			"applied":     allApplied,
			"rolled_back": allRolled,
		}})
}

// ---- 辅助 ----

// w5cTargetDevices 按模板分组过滤返回目标设备组（按 ID 排序稳定）。
func (h *Hub) w5cTargetDevices(t *store.StrategyTemplate) []*store.Device {
	all := h.store.List()
	out := make([]*store.Device, 0, len(all))
	for i := range all {
		d := &all[i]
		if w5cMatchGroup(t, d) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// w5cMatchGroup 判断设备是否命中模板分组过滤（任一维度命中即入选；全空=全部）。
func w5cMatchGroup(t *store.StrategyTemplate, d *store.Device) bool {
	if len(t.Departments) == 0 && len(t.Floors) == 0 && len(t.Batches) == 0 && len(t.Tags) == 0 {
		return true
	}
	if d.Department != "" && containsStr(t.Departments, d.Department) {
		return true
	}
	if d.Floor != "" && containsStr(t.Floors, d.Floor) {
		return true
	}
	if d.Batch != "" && containsStr(t.Batches, d.Batch) {
		return true
	}
	for _, tag := range d.TagList() {
		if containsStr(t.Tags, tag) {
			return true
		}
	}
	return false
}

// w5cTemplateDetailLocked 返回模板详情视图（含绑定明细）。调用方须持有 s.mu。
func (h *Hub) w5cTemplateDetailLocked(s *wave5cRuntime, t *store.StrategyTemplate) map[string]any {
	bindings := make([]*store.StrategyBinding, 0)
	for _, b := range s.bindings {
		if b.TemplateID == t.ID {
			bindings = append(bindings, b)
		}
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].DeviceID < bindings[j].DeviceID })
	return map[string]any{
		"id": t.ID, "name": t.Name, "desc": t.Desc, "rules": t.Rules,
		"departments": t.Departments, "floors": t.Floors, "batches": t.Batches, "tags": t.Tags,
		"target_pct": t.TargetPct, "current_pct": t.CurrentPct, "status": t.Status,
		"created_by": t.CreatedBy, "updated_at": t.UpdatedAt,
		"group_size": len(h.w5cTargetDevices(t)), "bindings": bindings,
	}
}

func w5cValidDomain(d string) bool {
	switch d {
	case store.StratDomainCompliance, store.StratDomainBlacklist, store.StratDomainVuln,
		store.StratDomainPeripheral, store.StratDomainNAC:
		return true
	}
	return false
}

func w5cClampPct(p int) int {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
