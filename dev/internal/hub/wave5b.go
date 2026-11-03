package hub

// wave5b.go —— 波次 5b 中枢侧实现（PRD 5.6 外设与准入 / PRD 5.9 报表与统计）：
//
//	W5-3 外设管控：按部门/楼层/批次/标签/指定设备下发 USB 存储、光驱、蓝牙策略；
//	              副端尽力执行并诚实回告（不支持项回告 unsupported + 原因）；
//	              中枢记录每台设备的策略生效状态，提供 CRUD / 状态查询 / 重新下发。
//	W5-4 网络准入：准入动作模型（allow/quarantine/block）+ 到期自动解除；
//	              触发方式二选一：① 可配置合规阈值（YUDUAN_NAC_COMPLIANCE_THRESHOLD）
//	              ② 外部显式调用 API。不依赖波次 5a 的合规实现。
//	W5-7 报表与统计：覆盖率 / 在线率 / 合规率 / 漏洞统计 / 远控统计 + CSV|XLSX 导出。
//
// 边界：中枢仍是唯一控制平面（铁律 3），指令下发前统一 HMAC 签名（铁律 4）；
// 所有管控动作落审计。文件纪律：本波次不修改 hub.go / store.go / export.go，
// 运行时状态挂在本文件内的 Hub 注册表（按 *Hub 实例隔离，便于并发测试）。

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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

// ---- 运行时状态（不侵入 Hub 结构体）----

// wave5bRuntime 保存单个 Hub 实例的波次 5b 运行时状态。
type wave5bRuntime struct {
	mu       sync.Mutex
	policies map[string]*store.PeripheralPolicy
	polSeq   int64
	applied  map[string]*store.PeripheralApplyState // key: deviceID|policyID
	nac      map[string]*store.NACAction            // key: deviceID（每设备仅一条当前准入动作）
	nacSeq   int64
}

var (
	wave5bMu   sync.Mutex
	wave5bRegs = map[*Hub]*wave5bRuntime{}
)

// w5b 返回当前 Hub 实例的波次 5b 运行时状态（懒创建）。
func (h *Hub) w5b() *wave5bRuntime {
	wave5bMu.Lock()
	defer wave5bMu.Unlock()
	r := wave5bRegs[h]
	if r == nil {
		r = &wave5bRuntime{
			policies: make(map[string]*store.PeripheralPolicy),
			applied:  make(map[string]*store.PeripheralApplyState),
			nac:      make(map[string]*store.NACAction),
		}
		wave5bRegs[h] = r
	}
	return r
}

// ---- 配置（环境变量）----

// w5bDryRun 是否为演练模式（默认 true）：下发时只评估可执行性、不执行系统变更。
// 生产部署需显式 YUDUAN_W5B_DRY_RUN=0 才会真正改动终端系统配置。
func w5bDryRun() bool { return os.Getenv("YUDUAN_W5B_DRY_RUN") != "0" }

// w5bNACThreshold 准入判定的合规分数阈值（0-100，低于阈值即判定不合规）。
func w5bNACThreshold() int { return envInt("YUDUAN_NAC_COMPLIANCE_THRESHOLD", 60) }

// w5bApplyTimeout 单台设备的指令回执等待超时。
func w5bApplyTimeout() time.Duration {
	n := envInt("YUDUAN_W5B_APPLY_TIMEOUT_SEC", 15)
	if n <= 0 {
		n = 15
	}
	return time.Duration(n) * time.Second
}

// ---- 路由挂载 ----

// wave5bRoutes 注册波次 5b 的全部 REST 路由（由 hub.go 调用；sync.Once 防重复注册 panic）。
func wave5bRoutes(mux *http.ServeMux, h *Hub) {
	{
		// W5-3 外设管控
		mux.HandleFunc("/api/v1/peripheral/policies", h.handlePeripheralPolicies)
		mux.HandleFunc("/api/v1/peripheral/policies/", h.handlePeripheralPolicyItem)
		mux.HandleFunc("/api/v1/peripheral/apply", h.guard(auth.PermDeviceCmd, h.handlePeripheralApplyDevice))
		mux.HandleFunc("/api/v1/peripheral/status", h.guard(auth.PermDeviceView, h.handlePeripheralStatus))
		// W5-4 网络准入
		mux.HandleFunc("/api/v1/nac/actions", h.guard(auth.PermDeviceView, h.handleNACList))
		mux.HandleFunc("/api/v1/nac/apply", h.guard(auth.PermDeviceCmd, h.handleNACApply))
		mux.HandleFunc("/api/v1/nac/release", h.guard(auth.PermDeviceCmd, h.handleNACRelease))
		mux.HandleFunc("/api/v1/nac/evaluate", h.guard(auth.PermDeviceCmd, h.handleNACEvaluate))
		// W5-7 报表与统计
		mux.HandleFunc("/api/v1/stats/overview", h.guard(auth.PermDeviceView, h.handleStatsOverview))
		mux.HandleFunc("/api/v1/stats/export", h.guard(auth.PermDeviceView, h.handleStatsExport))
		log.Printf("[hub] 波次 5b 路由已挂载：外设管控(dry_run=%v) / 网络准入(阈值=%d) / 统计报表",
			w5bDryRun(), w5bNACThreshold())
	}
}

// ==================== W5-3 外设管控 ====================

// handlePeripheralPolicies 分发策略集合接口：GET 列表（device:view）/ POST 创建（device:command）。
func (h *Hub) handlePeripheralPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.peripheralList).ServeHTTP(w, r)
	case http.MethodPost:
		h.guard(auth.PermDeviceCmd, h.peripheralCreate).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) peripheralList(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	rt := h.w5b()
	rt.mu.Lock()
	list := make([]*store.PeripheralPolicy, 0, len(rt.policies))
	for _, p := range rt.policies {
		list = append(list, p)
	}
	rt.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	if v := r.URL.Query().Get("scope_type"); v != "" {
		kept := list[:0]
		for _, p := range list {
			if p.ScopeType == v {
				kept = append(kept, p)
			}
		}
		list = kept
	}
	if v := r.URL.Query().Get("enabled"); v != "" {
		want := v == "1" || v == "true"
		kept := list[:0]
		for _, p := range list {
			if p.Enabled == want {
				kept = append(kept, p)
			}
		}
		list = kept
	}
	writeJSON(w, map[string]any{"code": 0, "total": len(list), "policies": list})
}

// peripheralCreate POST /api/v1/peripheral/policies
// body: {name, scope_type, scope_value, usb_storage, optical, bluetooth, enabled}
func (h *Hub) peripheralCreate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var body struct {
		Name       string `json:"name"`
		ScopeType  string `json:"scope_type"`
		ScopeValue string `json:"scope_value"`
		USBStorage string `json:"usb_storage"`
		Optical    string `json:"optical"`
		Bluetooth  string `json:"bluetooth"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 2501, "invalid body: "+err.Error())
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		writeErr(w, 2501, "name 不能为空")
		return
	}
	if !validScopeType(body.ScopeType) {
		writeErr(w, 2502, "scope_type 非法，应为 department/floor/batch/tag/device")
		return
	}
	if strings.TrimSpace(body.ScopeValue) == "" {
		writeErr(w, 2502, "scope_value 不能为空")
		return
	}
	if !validUSBStorage(body.USBStorage) || !validBlockAllow(body.Optical) || !validBlockAllow(body.Bluetooth) {
		writeErr(w, 2502, "管控项取值非法：usb_storage=block|allow|readonly；optical/bluetooth=block|allow")
		return
	}
	now := time.Now().UTC()
	rt := h.w5b()
	rt.mu.Lock()
	rt.polSeq++
	p := &store.PeripheralPolicy{
		ID:         fmt.Sprintf("pp-%d", rt.polSeq),
		Name:       body.Name,
		ScopeType:  body.ScopeType,
		ScopeValue: body.ScopeValue,
		USBStorage: body.USBStorage,
		Optical:    body.Optical,
		Bluetooth:  body.Bluetooth,
		Enabled:    true,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if body.Enabled != nil {
		p.Enabled = *body.Enabled
	}
	rt.policies[p.ID] = p
	rt.mu.Unlock()
	h.w5bSavePolicy(p)
	h.audit(claims.Username, "peripheral_policy_create", p.ID,
		fmt.Sprintf("名称=%s 范围=%s:%s usb=%s 光驱=%s 蓝牙=%s", p.Name, p.ScopeType, p.ScopeValue,
			p.USBStorage, p.Optical, p.Bluetooth), "success")
	writeJSON(w, map[string]any{"code": 0, "policy": p})
}

// handlePeripheralPolicyItem 处理 /api/v1/peripheral/policies/{id}[/status|/apply]。
func (h *Hub) handlePeripheralPolicyItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(idAfterPrefix(r.URL.Path, "/api/v1/peripheral/policies/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, 2503, "usage: /api/v1/peripheral/policies/{id}[/status|/apply]")
		return
	}
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}
	switch {
	case sub == "apply" && r.Method == http.MethodPost:
		h.guard(auth.PermDeviceCmd, h.peripheralApply).ServeHTTP(w, r)
	case sub == "status" && r.Method == http.MethodGet:
		h.guard(auth.PermDeviceView, h.peripheralPolicyStatus).ServeHTTP(w, r)
	case sub == "" && r.Method == http.MethodGet:
		h.guard(auth.PermDeviceView, h.peripheralGet).ServeHTTP(w, r)
	case sub == "" && r.Method == http.MethodPut:
		h.guard(auth.PermDeviceCmd, h.peripheralUpdate).ServeHTTP(w, r)
	case sub == "" && r.Method == http.MethodDelete:
		h.guard(auth.PermDeviceCmd, h.peripheralDelete).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Hub) peripheralGet(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	p := h.w5bGetPolicy(policyIDFromPath(r.URL.Path))
	if p == nil {
		writeErr(w, 2504, "策略不存在")
		return
	}
	writeJSON(w, map[string]any{"code": 0, "policy": p})
}

func (h *Hub) peripheralUpdate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	p := h.w5bGetPolicy(policyIDFromPath(r.URL.Path))
	if p == nil {
		writeErr(w, 2504, "策略不存在")
		return
	}
	var body struct {
		Name       string `json:"name"`
		ScopeType  string `json:"scope_type"`
		ScopeValue string `json:"scope_value"`
		USBStorage string `json:"usb_storage"`
		Optical    string `json:"optical"`
		Bluetooth  string `json:"bluetooth"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 2501, "invalid body: "+err.Error())
		return
	}
	rt := h.w5b()
	rt.mu.Lock()
	if body.Name != "" {
		p.Name = body.Name
	}
	if body.ScopeType != "" {
		if !validScopeType(body.ScopeType) {
			rt.mu.Unlock()
			writeErr(w, 2502, "scope_type 非法")
			return
		}
		p.ScopeType = body.ScopeType
	}
	if body.ScopeValue != "" {
		p.ScopeValue = body.ScopeValue
	}
	if body.USBStorage != "" {
		if !validUSBStorage(body.USBStorage) {
			rt.mu.Unlock()
			writeErr(w, 2502, "usb_storage 取值非法")
			return
		}
		p.USBStorage = body.USBStorage
	}
	if body.Optical != "" {
		if !validBlockAllow(body.Optical) {
			rt.mu.Unlock()
			writeErr(w, 2502, "optical 取值非法")
			return
		}
		p.Optical = body.Optical
	}
	if body.Bluetooth != "" {
		if !validBlockAllow(body.Bluetooth) {
			rt.mu.Unlock()
			writeErr(w, 2502, "bluetooth 取值非法")
			return
		}
		p.Bluetooth = body.Bluetooth
	}
	if body.Enabled != nil {
		p.Enabled = *body.Enabled
	}
	p.UpdatedAt = time.Now().UTC()
	rt.mu.Unlock()
	h.w5bSavePolicy(p)
	h.audit(claims.Username, "peripheral_policy_update", p.ID,
		fmt.Sprintf("名称=%s 范围=%s:%s usb=%s 光驱=%s 蓝牙=%s enabled=%v",
			p.Name, p.ScopeType, p.ScopeValue, p.USBStorage, p.Optical, p.Bluetooth, p.Enabled), "success")
	writeJSON(w, map[string]any{"code": 0, "policy": p})
}

func (h *Hub) peripheralDelete(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := policyIDFromPath(r.URL.Path)
	rt := h.w5b()
	rt.mu.Lock()
	if _, ok := rt.policies[id]; !ok {
		rt.mu.Unlock()
		writeErr(w, 2504, "策略不存在: "+id)
		return
	}
	delete(rt.policies, id)
	for k, st := range rt.applied {
		if st.PolicyID == id {
			delete(rt.applied, k)
		}
	}
	rt.mu.Unlock()
	if pg, ok := h.w5bPG(); ok {
		_ = pg.Exec(`DELETE FROM peripheral_policies WHERE id=$1`, id)
		_ = pg.Exec(`DELETE FROM peripheral_apply_state WHERE policy_id=$1`, id)
	}
	h.audit(claims.Username, "peripheral_policy_delete", id, "删除外设策略", "success")
	writeJSON(w, map[string]any{"code": 0, "deleted": id})
}

// peripheralApply POST /api/v1/peripheral/policies/{id}/apply —— 按 scope 下发到全部匹配设备。
// 可选 body: {"device_id": "..."} 限定单台设备；为空则按作用域解析。
func (h *Hub) peripheralApply(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	p := h.w5bGetPolicy(policyIDFromPath(r.URL.Path))
	if p == nil {
		writeErr(w, 2504, "策略不存在")
		return
	}
	var body struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !p.Enabled {
		writeErr(w, 2505, "策略已停用，拒绝下发（请先启用）")
		return
	}
	var targets []store.Device
	if body.DeviceID != "" {
		d, ok := h.store.Get(body.DeviceID)
		if !ok {
			writeErr(w, 2504, "设备不存在: "+body.DeviceID)
			return
		}
		targets = append(targets, d)
	} else {
		targets = h.w5bResolveTargets(p)
	}
	results := make([]store.PeripheralApplyState, 0, len(targets))
	for _, d := range targets {
		results = append(results, h.dispatchPeripheralPolicy(p, d))
	}
	sum := summarizePeripheral(results)
	h.audit(claims.Username, "peripheral_policy_apply", p.ID,
		fmt.Sprintf("范围=%s:%s 目标=%d 成功=%d 部分=%d 演练=%d 不支持=%d 失败=%d 离线=%d",
			p.ScopeType, p.ScopeValue, sum["total"], sum["applied"], sum["partial"], sum["dry_run"],
			sum["unsupported"], sum["failed"], sum["offline"]), "success")
	writeJSON(w, map[string]any{"code": 0, "policy_id": p.ID, "summary": sum, "results": results})
}

// handlePeripheralApplyDevice POST /api/v1/peripheral/apply —— 手动重新下发（补发）。
// body: {device_id}；policy_id 可选（缺省=该设备命中的全部启用策略）。
func (h *Hub) handlePeripheralApplyDevice(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var body struct {
		DeviceID string `json:"device_id"`
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 2501, "invalid body: "+err.Error())
		return
	}
	d, ok := h.store.Get(body.DeviceID)
	if !ok {
		writeErr(w, 2504, "设备不存在: "+body.DeviceID)
		return
	}
	rt := h.w5b()
	rt.mu.Lock()
	policies := make([]*store.PeripheralPolicy, 0, len(rt.policies))
	for _, p := range rt.policies {
		if !p.Enabled {
			continue
		}
		if body.PolicyID != "" {
			if p.ID == body.PolicyID {
				policies = append(policies, p)
			}
			continue
		}
		if w5bMatchDevice(p, d) {
			policies = append(policies, p)
		}
	}
	rt.mu.Unlock()
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	results := make([]store.PeripheralApplyState, 0, len(policies))
	for _, p := range policies {
		results = append(results, h.dispatchPeripheralPolicy(p, d))
	}
	h.audit(claims.Username, "peripheral_policy_reapply", body.DeviceID,
		fmt.Sprintf("重新下发策略数=%d（policy=%s）", len(policies), orDefault(body.PolicyID, "全部命中")), "success")
	writeJSON(w, map[string]any{"code": 0, "device_id": body.DeviceID, "total": len(results), "results": results})
}

// handlePeripheralStatus GET /api/v1/peripheral/status?device_id=&department=&policy_id=
func (h *Hub) handlePeripheralStatus(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	rt := h.w5b()
	q := r.URL.Query()
	deviceID := q.Get("device_id")
	department := q.Get("department")
	policyID := q.Get("policy_id")
	rt.mu.Lock()
	out := make([]store.PeripheralApplyState, 0, len(rt.applied))
	for _, st := range rt.applied {
		if deviceID != "" && st.DeviceID != deviceID {
			continue
		}
		if policyID != "" && st.PolicyID != policyID {
			continue
		}
		out = append(out, *st)
	}
	rt.mu.Unlock()
	if department != "" {
		kept := out[:0]
		for _, st := range out {
			if d, ok := h.store.Get(st.DeviceID); ok && d.Department == department {
				kept = append(kept, st)
			}
		}
		out = kept
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceID == out[j].DeviceID {
			return out[i].PolicyID < out[j].PolicyID
		}
		return out[i].DeviceID < out[j].DeviceID
	})
	// 命中但该设备尚未收到回执的策略数（主端据此展示覆盖缺口）
	pending := 0
	if deviceID != "" {
		if d, ok := h.store.Get(deviceID); ok {
			rt.mu.Lock()
			for _, p := range rt.policies {
				if p.Enabled && w5bMatchDevice(p, d) {
					if _, has := rt.applied[appliedKey(d.ID, p.ID)]; !has {
						pending++
					}
				}
			}
			rt.mu.Unlock()
		}
	}
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "pending": pending, "states": out})
}

// peripheralPolicyStatus GET /api/v1/peripheral/policies/{id}/status
func (h *Hub) peripheralPolicyStatus(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	id := policyIDFromPath(r.URL.Path)
	if h.w5bGetPolicy(id) == nil {
		writeErr(w, 2504, "策略不存在: "+id)
		return
	}
	rt := h.w5b()
	rt.mu.Lock()
	out := make([]store.PeripheralApplyState, 0, len(rt.applied))
	for _, st := range rt.applied {
		if st.PolicyID == id {
			out = append(out, *st)
		}
	}
	rt.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	writeJSON(w, map[string]any{"code": 0, "policy_id": id, "summary": summarizePeripheral(out), "states": out})
}

// ---- W5-3 下发与回执 ----

// dispatchPeripheralPolicy 向单台设备下发一条策略并记录生效状态。
func (h *Hub) dispatchPeripheralPolicy(p *store.PeripheralPolicy, d store.Device) store.PeripheralApplyState {
	st := store.PeripheralApplyState{
		DeviceID:   d.ID,
		DeviceName: d.Hostname,
		PolicyID:   p.ID,
		PolicyName: p.Name,
		USBStorage: p.USBStorage,
		Optical:    p.Optical,
		Bluetooth:  p.Bluetooth,
		Status:     store.PolicyStatusPending,
		DryRun:     w5bDryRun(),
		AppliedAt:  time.Now().UTC(),
	}
	if !h.deviceOnlineLocal(d.ID) {
		st.Status = store.PolicyStatusOffline
		st.Message = "设备离线，策略未下发（上线后需调用重新下发 API 补发）"
		h.w5bSaveApplied(&st)
		return st
	}
	payload, err := json.Marshal(proto.PeripheralApplyPayload{
		PolicyID:   p.ID,
		PolicyName: p.Name,
		USBStorage: p.USBStorage,
		Optical:    p.Optical,
		Bluetooth:  p.Bluetooth,
		DryRun:     w5bDryRun(),
	})
	if err != nil {
		st.Status = store.PolicyStatusFailed
		st.Message = "策略序列化失败: " + err.Error()
		h.w5bSaveApplied(&st)
		return st
	}
	taskID := newTaskID()
	env, _ := proto.NewEnvelope(proto.TypeCommand, 0, proto.CommandPayload{
		Action:  proto.ActionPeripheralApply,
		TaskID:  taskID,
		Command: string(payload),
	})
	h.sign(&env) // 铁律 4：关键指令签名下发
	envBytes, _ := json.Marshal(env)
	// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
	res, err := h.awaitTaskResult(taskID, w5bApplyTimeout(), func() error {
		if !h.sendToDevice(d.ID, envBytes) {
			return fmt.Errorf("指令发送失败（连接已断开）")
		}
		return nil
	})
	if err != nil {
		st.Status = store.PolicyStatusFailed
		st.Message = err.Error()
		h.w5bSaveApplied(&st)
		return st
	}
	if res.State == "failed" {
		st.Status = store.PolicyStatusFailed
		st.Message = firstLine(res.OutputLog, "副端执行失败")
		h.w5bSaveApplied(&st)
		return st
	}
	var ar proto.PeripheralApplyResult
	if jerr := json.Unmarshal([]byte(res.OutputLog), &ar); jerr != nil {
		// 旧副端/未知格式：按纯文本处理，不谎报成功
		st.Status = store.PolicyStatusFailed
		st.Message = "回执格式无法解析: " + firstLine(res.OutputLog, "")
		h.w5bSaveApplied(&st)
		return st
	}
	st.Items = make([]store.PeripheralItemResult, 0, len(ar.Items))
	for _, it := range ar.Items {
		st.Items = append(st.Items, store.PeripheralItemResult{
			Item: it.Item, Desired: it.Desired, Applied: it.Applied, State: it.State, Reason: it.Reason,
		})
	}
	st.DryRun = ar.DryRun
	st.Status = statusOfPeripheralItems(ar.Items)
	for _, it := range ar.Items {
		switch it.Item {
		case store.PeripheralUSBStorage:
			st.USBStorage = it.Applied
		case store.PeripheralOptical:
			st.Optical = it.Applied
		case store.PeripheralBluetooth:
			st.Bluetooth = it.Applied
		}
		if st.Message == "" && (it.State == store.ItemStateFailed || it.State == store.ItemStateUnsupported) {
			st.Message = fmt.Sprintf("%s: %s（%s）", it.Item, it.State, it.Reason)
		}
	}
	if st.Message == "" && ar.Message != "" {
		st.Message = ar.Message
	}
	h.w5bSaveApplied(&st)
	return st
}

// statusOfPeripheralItems 根据各管控项回执判定策略整体状态。
func statusOfPeripheralItems(items []proto.PeripheralItemResult) string {
	n := len(items)
	if n == 0 {
		return store.PolicyStatusFailed
	}
	applied, unsupported, failed, dry := 0, 0, 0, 0
	for _, it := range items {
		switch it.State {
		case store.ItemStateApplied:
			applied++
		case store.ItemStateUnsupported:
			unsupported++
		case store.ItemStateFailed:
			failed++
		case store.ItemStateDryRun:
			dry++
		}
	}
	switch {
	case applied == n:
		return store.PolicyStatusApplied
	case unsupported == n:
		return store.PolicyStatusUnsupported
	case failed == n:
		return store.PolicyStatusFailed
	case dry > 0:
		return store.PolicyStatusDryRun
	default:
		return store.PolicyStatusPartial
	}
}

func summarizePeripheral(list []store.PeripheralApplyState) map[string]int {
	sum := map[string]int{"total": len(list)}
	for _, st := range list {
		sum[st.Status]++
	}
	for _, k := range []string{store.PolicyStatusApplied, store.PolicyStatusPartial, store.PolicyStatusDryRun,
		store.PolicyStatusUnsupported, store.PolicyStatusFailed, store.PolicyStatusOffline, store.PolicyStatusPending} {
		if _, ok := sum[k]; !ok {
			sum[k] = 0
		}
	}
	return sum
}

// w5bResolveTargets 按策略作用域解析目标设备。
func (h *Hub) w5bResolveTargets(p *store.PeripheralPolicy) []store.Device {
	out := make([]store.Device, 0)
	for _, d := range h.store.List() {
		if w5bMatchDevice(p, d) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// w5bMatchDevice 判定设备是否命中策略作用域。
func w5bMatchDevice(p *store.PeripheralPolicy, d store.Device) bool {
	switch p.ScopeType {
	case store.ScopeDepartment:
		return d.Department != "" && d.Department == p.ScopeValue
	case store.ScopeFloor:
		return d.Floor != "" && d.Floor == p.ScopeValue
	case store.ScopeBatch:
		return d.Batch != "" && d.Batch == p.ScopeValue
	case store.ScopeTag:
		for _, t := range d.TagList() {
			if t == p.ScopeValue {
				return true
			}
		}
		return false
	case store.ScopeDevice:
		for _, id := range strings.Split(p.ScopeValue, ",") {
			if strings.TrimSpace(id) == d.ID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func validScopeType(s string) bool {
	switch s {
	case store.ScopeDepartment, store.ScopeFloor, store.ScopeBatch, store.ScopeTag, store.ScopeDevice:
		return true
	}
	return false
}

func validUSBStorage(s string) bool {
	switch s {
	case store.PeripheralBlock, store.PeripheralAllow, store.PeripheralReadOnly:
		return true
	}
	return false
}

func validBlockAllow(s string) bool {
	return s == store.PeripheralBlock || s == store.PeripheralAllow
}

func appliedKey(deviceID, policyID string) string { return deviceID + "|" + policyID }

// policyIDFromPath 从 /api/v1/peripheral/policies/{id}[/sub] 提取策略 ID。
func policyIDFromPath(path string) string {
	rest := strings.Trim(idAfterPrefix(path, "/api/v1/peripheral/policies/"), "/")
	return strings.Split(rest, "/")[0]
}

func (h *Hub) w5bGetPolicy(id string) *store.PeripheralPolicy {
	rt := h.w5b()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.policies[id]
}

// ==================== W5-4 网络准入 ====================

// handleNACList GET /api/v1/nac/actions?device_id=&action=&active=1
// 惰性到期解除：查询时把过期动作恢复为 allow（不依赖后台线程）。
func (h *Hub) handleNACList(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	q := r.URL.Query()
	deviceID := q.Get("device_id")
	action := q.Get("action")
	activeOnly := q.Get("active") == "1" || q.Get("active") == "true"
	rt := h.w5b()
	rt.mu.Lock()
	out := make([]store.NACAction, 0, len(rt.nac))
	for _, a := range rt.nac {
		if h.w5bExpireIfNeeded(a) {
			h.persistNACLocked(a)
		}
		if deviceID != "" && a.DeviceID != deviceID {
			continue
		}
		if action != "" && a.Action != action {
			continue
		}
		if activeOnly && a.Action == store.NACAllow {
			continue
		}
		out = append(out, *a)
	}
	rt.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	writeJSON(w, map[string]any{"code": 0, "total": len(out), "threshold": w5bNACThreshold(), "actions": out})
}

// handleNACApply POST /api/v1/nac/apply —— 显式下发准入动作。
// body: {device_id, action(allow|quarantine|block), reason, expire_in_sec?}
func (h *Hub) handleNACApply(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var body struct {
		DeviceID    string `json:"device_id"`
		Action      string `json:"action"`
		Reason      string `json:"reason"`
		ExpireInSec int    `json:"expire_in_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 2511, "invalid body: "+err.Error())
		return
	}
	switch body.Action {
	case store.NACAllow, store.NACQuarantine, store.NACBlock:
	default:
		writeErr(w, 2512, "action 非法，应为 allow/quarantine/block")
		return
	}
	d, ok := h.store.Get(body.DeviceID)
	if !ok {
		writeErr(w, 2513, "设备不存在: "+body.DeviceID)
		return
	}
	var expireAt time.Time
	if body.ExpireInSec > 0 {
		expireAt = time.Now().UTC().Add(time.Duration(body.ExpireInSec) * time.Second)
	}
	a := h.w5bDispatchNAC(d, body.Action, orDefault(body.Reason, "管理员手动下发"), expireAt, "api", -1)
	result := "success"
	if !a.Applied {
		result = "failed"
	}
	h.audit(claims.Username, "nac_apply", d.ID,
		fmt.Sprintf("动作=%s 原因=%s 到期=%s 状态=%s", a.Action, a.Reason, orDefault(w5bTimeText(a.ExpireAt), "不限时"), a.State), result)
	if a.Action != store.NACAllow {
		h.addAlert(alertOf(store.AlertCompliance, d.ID, d.Hostname, "终端网络准入已限制",
			fmt.Sprintf("动作=%s 原因=%s 操作人=%s", a.Action, a.Reason, claims.Username)))
	}
	writeJSON(w, map[string]any{"code": 0, "action": a})
}

// handleNACRelease POST /api/v1/nac/release —— 解除准入限制（恢复到 allow）。
func (h *Hub) handleNACRelease(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var body struct {
		DeviceID string `json:"device_id"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 2511, "invalid body: "+err.Error())
		return
	}
	d, ok := h.store.Get(body.DeviceID)
	if !ok {
		writeErr(w, 2513, "设备不存在: "+body.DeviceID)
		return
	}
	a := h.w5bDispatchNAC(d, store.NACAllow, orDefault(body.Reason, "管理员解除准入限制"), time.Time{}, "release", -1)
	h.audit(claims.Username, "nac_release", d.ID,
		fmt.Sprintf("解除准入限制 状态=%s %s", a.State, a.Message), "success")
	writeJSON(w, map[string]any{"code": 0, "action": a})
}

// handleNACEvaluate POST /api/v1/nac/evaluate —— 按可配置合规阈值判定并（可选）下发。
// body: {device_id?, threshold?, apply?}；apply 缺省 true。
func (h *Hub) handleNACEvaluate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var body struct {
		DeviceID  string `json:"device_id"`
		Threshold int    `json:"threshold"`
		Apply     *bool  `json:"apply"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	threshold := body.Threshold
	if threshold <= 0 {
		threshold = w5bNACThreshold()
	}
	doApply := true
	if body.Apply != nil {
		doApply = *body.Apply
	}
	var targets []store.Device
	if body.DeviceID != "" {
		d, ok := h.store.Get(body.DeviceID)
		if !ok {
			writeErr(w, 2513, "设备不存在: "+body.DeviceID)
			return
		}
		targets = append(targets, d)
	} else {
		targets = h.store.List()
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	type evalItem struct {
		DeviceID   string   `json:"device_id"`
		DeviceName string   `json:"device_name,omitempty"`
		Department string   `json:"department,omitempty"`
		Score      int      `json:"score"`
		Compliant  bool     `json:"compliant"`
		Reasons    []string `json:"reasons"`
		Action     string   `json:"action"`
		State      string   `json:"state,omitempty"`
		Message    string   `json:"message,omitempty"`
	}
	items := make([]evalItem, 0, len(targets))
	nonCompliant := 0
	for _, d := range targets {
		score, reasons := w5bComplianceScore(d)
		compliant := score >= threshold
		it := evalItem{
			DeviceID: d.ID, DeviceName: d.Hostname, Department: d.Department,
			Score: score, Compliant: compliant, Reasons: reasons, Action: store.NACAllow,
		}
		if !compliant {
			nonCompliant++
			it.Action = store.NACQuarantine
			if doApply {
				a := h.w5bDispatchNAC(d, store.NACQuarantine,
					fmt.Sprintf("合规评分 %d 低于阈值 %d（%s）", score, threshold, strings.Join(reasons, "、")),
					time.Time{}, "threshold", score)
				it.State = a.State
				it.Message = a.Message
			}
		}
		items = append(items, it)
	}
	h.audit(claims.Username, "nac_evaluate", orDefault(body.DeviceID, "*"),
		fmt.Sprintf("阈值=%d 评估=%d 不合规=%d 下发=%v", threshold, len(items), nonCompliant, doApply), "success")
	writeJSON(w, map[string]any{"code": 0, "threshold": threshold, "baseline": "wave5b_heuristic",
		"total": len(items), "non_compliant": nonCompliant, "applied": doApply, "items": items})
}

// w5bDispatchNAC 下发准入动作并记录（同一设备只保留一条当前动作）。
func (h *Hub) w5bDispatchNAC(d store.Device, action, reason string, expireAt time.Time, trigger string, score int) *store.NACAction {
	rt := h.w5b()
	rt.mu.Lock()
	rt.nacSeq++
	a := &store.NACAction{
		ID:         fmt.Sprintf("nac-%d", rt.nacSeq),
		DeviceID:   d.ID,
		DeviceName: d.Hostname,
		Action:     action,
		Reason:     reason,
		ExpireAt:   expireAt,
		State:      store.NACStatePending,
		Score:      score,
		Trigger:    trigger,
		DryRun:     w5bDryRun(),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	rt.nac[d.ID] = a
	rt.mu.Unlock()

	if !h.deviceOnlineLocal(d.ID) {
		a.State = store.NACStateOffline
		a.Message = "设备离线，准入动作未下发（上线后需重新下发）"
		h.w5bPersistNAC(a)
		return a
	}
	payload, err := json.Marshal(proto.NACApplyPayload{
		Action:   action,
		Reason:   reason,
		ExpireAt: w5bTimeText(expireAt),
		DryRun:   w5bDryRun(),
	})
	if err != nil {
		a.State = store.NACStateFailed
		a.Message = "载荷序列化失败: " + err.Error()
		h.w5bPersistNAC(a)
		return a
	}
	taskID := newTaskID()
	env, _ := proto.NewEnvelope(proto.TypeCommand, 0, proto.CommandPayload{
		Action:  proto.ActionNACApply,
		TaskID:  taskID,
		Command: string(payload),
	})
	h.sign(&env)
	envBytes, _ := json.Marshal(env)
	// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
	res, err := h.awaitTaskResult(taskID, w5bApplyTimeout(), func() error {
		if !h.sendToDevice(d.ID, envBytes) {
			return fmt.Errorf("指令发送失败（连接已断开）")
		}
		return nil
	})
	if err != nil {
		a.State = store.NACStateFailed
		a.Message = err.Error()
		h.w5bPersistNAC(a)
		return a
	}
	if res.State == "failed" {
		a.State = store.NACStateFailed
		a.Message = firstLine(res.OutputLog, "副端执行失败")
		h.w5bPersistNAC(a)
		return a
	}
	var ar proto.NACApplyResult
	if jerr := json.Unmarshal([]byte(res.OutputLog), &ar); jerr != nil {
		a.State = store.NACStateFailed
		a.Message = "回执格式无法解析: " + firstLine(res.OutputLog, "")
		h.w5bPersistNAC(a)
		return a
	}
	a.DryRun = ar.DryRun
	a.Applied = ar.Applied
	a.State = ar.State
	if a.State == "" {
		a.State = store.NACStateFailed
	}
	a.Message = ar.Reason
	a.UpdatedAt = time.Now().UTC()
	h.w5bPersistNAC(a)
	return a
}

// w5bExpireIfNeeded 惰性到期解除：过期且非 allow 的动作恢复为 allow，并异步下发解除指令。
// 返回是否发生了解除。调用方需持有 rt.mu。
func (h *Hub) w5bExpireIfNeeded(a *store.NACAction) bool {
	if a.ExpireAt.IsZero() || a.Action == store.NACAllow || a.State == store.NACStateExpired {
		return false
	}
	if !time.Now().UTC().After(a.ExpireAt) {
		return false
	}
	prev := a.Action
	a.Action = store.NACAllow
	a.State = store.NACStateExpired
	a.Applied = true
	a.Message = "准入动作已到期，自动解除为 allow"
	a.UpdatedAt = time.Now().UTC()
	if d, ok := h.store.Get(a.DeviceID); ok {
		go h.w5bExpireDispatch(d, a, prev)
	}
	return true
}

func (h *Hub) w5bExpireDispatch(d store.Device, a *store.NACAction, prev string) {
	payload, _ := json.Marshal(proto.NACApplyPayload{Action: store.NACAllow, Reason: "到期自动解除", DryRun: w5bDryRun()})
	taskID := newTaskID()
	env, _ := proto.NewEnvelope(proto.TypeCommand, 0, proto.CommandPayload{
		Action: proto.ActionNACApply, TaskID: taskID, Command: string(payload),
	})
	h.sign(&env)
	b, _ := json.Marshal(env)
	// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
	_, _ = h.awaitTaskResult(taskID, w5bApplyTimeout(), func() error {
		if !h.sendToDevice(d.ID, b) {
			return fmt.Errorf("send failed")
		}
		return nil
	})
	h.audit("system", "nac_expire_release", d.ID,
		fmt.Sprintf("准入动作 %s 到期自动解除（原动作=%s）", a.ID, prev), "success")
}

// ==================== W5-4/W5-7 合规评分（内置启发式基线）====================

// w5bComplianceScore 计算设备合规评分（0-100）与不合规原因。
// 说明：波次 5a 的合规实现并行开发中，其 DeviceComplianceScore/ComplianceIssues 未提供
// （本波次不得调用、也不得创建这两个函数），故这里用内置启发式基线：
// 在线 40 / 台账分组 20 / 软件清单 20 / 副端版本 10 / 生命周期 10。
// 评分口径通过 API 响应的 baseline=wave5b_heuristic 字段回显，便于后续替换为 5a 实现。
func w5bComplianceScore(d store.Device) (int, []string) {
	score := 0
	var reasons []string
	if d.Online {
		score += 40
	} else {
		reasons = append(reasons, "设备离线")
	}
	if d.Department != "" {
		score += 20
	} else {
		reasons = append(reasons, "未归属部门")
	}
	if len(d.SoftwareList()) > 0 {
		score += 20
	} else {
		reasons = append(reasons, "未采集软件清单")
	}
	if d.AgentVersion != "" {
		score += 10
	} else {
		reasons = append(reasons, "副端版本未知")
	}
	if d.Lifecycle != "" && d.Lifecycle != store.LifecycleInStock {
		score += 10
	} else {
		reasons = append(reasons, "未处于领用状态")
	}
	return score, reasons
}

// ==================== W5-7 报表与统计 ====================

// handleStatsOverview GET /api/v1/stats/overview —— 综合概览（主端仪表盘）。
func (h *Hub) handleStatsOverview(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	writeJSON(w, map[string]any{"code": 0, "overview": h.buildStatsOverview()})
}

func (h *Hub) buildStatsOverview() map[string]any {
	now := time.Now().UTC()
	devices := h.store.List()
	total := len(devices)
	online, managed := 0, 0
	byDept := map[string]map[string]int{} // dept -> {total, online}
	byOS := map[string]int{}
	for _, d := range devices {
		if d.Online {
			online++
		}
		if !d.LastSeen.IsZero() {
			managed++
		}
		byOS[d.OS]++
		dept := d.Department
		if dept == "" {
			dept = "(未分组)"
		}
		if byDept[dept] == nil {
			byDept[dept] = map[string]int{"total": 0, "online": 0}
		}
		byDept[dept]["total"]++
		if d.Online {
			byDept[dept]["online"]++
		}
	}
	deptList := make([]map[string]any, 0, len(byDept))
	for k, v := range byDept {
		deptList = append(deptList, map[string]any{"department": k, "total": v["total"], "online": v["online"]})
	}
	sort.Slice(deptList, func(i, j int) bool {
		return deptList[i]["department"].(string) < deptList[j]["department"].(string)
	})
	coverage := map[string]any{
		"total_devices": total,
		"managed":       managed,
		"alive":         online,
		"offline":       total - online,
		"coverage_rate": pctOf(managed, total),
		"by_department": deptList,
		"by_os":         byOS,
	}

	// 在线率与趋势分桶（近 24h / 6 桶 × 4h）
	const windowH = 24
	buckets := make([]map[string]any, 0, 6)
	for i := 0; i < 6; i++ {
		start := now.Add(-time.Duration(windowH-i*4) * time.Hour)
		end := start.Add(4 * time.Hour)
		cnt := 0
		for _, d := range devices {
			if !d.LastSeen.IsZero() && !d.LastSeen.Before(start) && d.LastSeen.Before(end) {
				cnt++
			}
		}
		buckets = append(buckets, map[string]any{
			"bucket": start.Format("01-02 15:04") + "~" + end.Format("15:04"),
			"count":  cnt,
		})
	}
	onlineStats := map[string]any{
		"window_hours": windowH,
		"online":       online,
		"total":        total,
		"online_rate":  pctOf(online, total),
		"buckets":      buckets,
		"note":         "趋势分桶按设备最后心跳（LastSeen）快照统计；中枢未持久化心跳时序，故反映「最后活跃分布」而非历史在线曲线",
	}

	// 合规率（内置启发式基线）
	threshold := w5bNACThreshold()
	compliant, scoreSum := 0, 0
	byDevice := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		score, reasons := w5bComplianceScore(d)
		scoreSum += score
		ok := score >= threshold
		if ok {
			compliant++
		}
		byDevice = append(byDevice, map[string]any{
			"device_id": d.ID, "hostname": d.Hostname, "department": d.Department,
			"score": score, "compliant": ok, "reasons": reasons,
		})
	}
	sort.Slice(byDevice, func(i, j int) bool {
		return byDevice[i]["score"].(int) < byDevice[j]["score"].(int)
	})
	avgScore := 0.0
	if total > 0 {
		avgScore = float64(scoreSum) / float64(total)
	}
	if len(byDevice) > 200 {
		byDevice = byDevice[:200]
	}
	compliance := map[string]any{
		"available":       true,
		"baseline":        "wave5b_heuristic",
		"threshold":       threshold,
		"scored_devices":  total,
		"compliant":       compliant,
		"non_compliant":   total - compliant,
		"compliance_rate": pctOf(compliant, total),
		"avg_score":       avgScore,
		"by_device":       byDevice,
		"note":            "波次 5a 的 DeviceComplianceScore 未提供，本接口使用内置启发式基线（在线 40 / 分组 20 / 软件清单 20 / 副端版本 10 / 生命周期 10）",
	}

	// 漏洞统计（波次 5a 未提供数据源 → 占位 0 并说明）
	vuln := map[string]any{
		"available": false,
		"total":     0,
		"by_severity": map[string]int{
			"critical": 0, "high": 0, "medium": 0, "low": 0,
		},
		"note": "波次 5a 未提供漏洞数据源（并行开发中），本接口返回占位 0；接入后按严重度分桶输出",
	}

	// 远控统计（基于审计事件 + 当前活动会话）
	rcStart, rcEnd, endedSec, byOperator := h.collectRCStats()
	activeSec := 0
	h.mu.Lock()
	activeSessions := len(h.sessions)
	for _, s := range h.sessions {
		activeSec += int(now.Sub(s.StartedAt).Seconds())
	}
	h.mu.Unlock()
	totalSec := endedSec + activeSec
	avg := 0
	if rcStart > 0 {
		avg = totalSec / rcStart
	}
	opList := make([]map[string]any, 0, len(byOperator))
	for k, v := range byOperator {
		opList = append(opList, map[string]any{"operator": k, "sessions": v})
	}
	sort.Slice(opList, func(i, j int) bool { return opList[i]["operator"].(string) < opList[j]["operator"].(string) })
	rc := map[string]any{
		"sessions_total":     rcStart,
		"sessions_ended":     rcEnd,
		"sessions_active":    activeSessions,
		"total_duration_sec": totalSec,
		"avg_duration_sec":   avg,
		"by_operator":        opList,
		"note":               "基于审计事件 rc_start/rc_end（时长取自 rc_end 详情）与当前活动会话统计",
	}

	return map[string]any{
		"generated_at": now.Format(time.RFC3339),
		"coverage":     coverage,
		"online":       onlineStats,
		"compliance":   compliance,
		"vuln":         vuln,
		"rc":           rc,
	}
}

// collectRCStats 从审计事件汇总远控会话次数/时长。
func (h *Hub) collectRCStats() (starts int, ends int, durationSec int, byOperator map[string]int) {
	byOperator = map[string]int{}
	if h.auditor == nil {
		return
	}
	for _, e := range h.auditor.Query(20000) {
		switch e.Action {
		case "rc_start":
			starts++
			byOperator[e.Actor]++
		case "rc_end":
			ends++
			durationSec += int(w5bParseDuration(e.Detail))
		}
	}
	return
}

// w5bParseDuration 从审计详情中解析「时长=%.0fs」。
func w5bParseDuration(detail string) float64 {
	const key = "时长="
	i := strings.Index(detail, key)
	if i < 0 {
		return 0
	}
	rest := detail[i+len(key):]
	j := 0
	for j < len(rest) && ((rest[j] >= '0' && rest[j] <= '9') || rest[j] == '.') {
		j++
	}
	if j == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(rest[:j], 64)
	if err != nil {
		return 0
	}
	return v
}

// ---- W5-7 导出（CSV / XLSX，复用 export.go 的 buildXLSX/xmlEscape）----

// handleStatsExport GET /api/v1/stats/export?format=csv|xlsx&type=coverage|online|compliance|vuln|rc
func (h *Hub) handleStatsExport(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	typ := r.URL.Query().Get("type")
	if typ == "" {
		typ = "coverage"
	}
	ov := h.buildStatsOverview()
	title, headers, rows := w5bStatsTable(typ, ov)
	if headers == nil {
		writeErr(w, 2521, "未知的导出类型: "+typ+"（应为 coverage/online/compliance/vuln/rc）")
		return
	}
	switch r.URL.Query().Get("format") {
	case "xlsx":
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="yuduan-stats-%s.xlsx"`, typ))
		_, _ = w.Write(buildXLSX(title, headers, rows))
	default:
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="yuduan-stats-%s.csv"`, typ))
		bw := &bytes.Buffer{}
		cw := csv.NewWriter(bw)
		_ = cw.Write(headers)
		for _, row := range rows {
			_ = cw.Write(row)
		}
		cw.Flush()
		_, _ = w.Write(bw.Bytes())
	}
}

// w5bStatsTable 把概览中的某个维度转成（标题、表头、行）。
func w5bStatsTable(typ string, ov map[string]any) (string, []string, [][]string) {
	switch typ {
	case "coverage":
		cov, _ := ov["coverage"].(map[string]any)
		rows := [][]string{
			{"纳管设备数", itoa(anyInt(cov["managed"]))},
			{"存活设备数", itoa(anyInt(cov["alive"]))},
			{"离线设备数", itoa(anyInt(cov["offline"]))},
			{"台账总数", itoa(anyInt(cov["total_devices"]))},
			{"纳管覆盖率(%)", fmt.Sprintf("%.1f", anyFloat(cov["coverage_rate"]))},
		}
		for _, d := range anyMapList(cov["by_department"]) {
			rows = append(rows, []string{"部门 " + anyStr(d["department"]),
				"总数 " + itoa(anyInt(d["total"])) + "；在线 " + itoa(anyInt(d["online"]))})
		}
		return "覆盖率统计", []string{"指标", "数值"}, rows
	case "online":
		on, _ := ov["online"].(map[string]any)
		rows := [][]string{
			{"在线设备数", itoa(anyInt(on["online"]))},
			{"设备总数", itoa(anyInt(on["total"]))},
			{"在线率(%)", fmt.Sprintf("%.1f", anyFloat(on["online_rate"]))},
		}
		for _, b := range anyMapList(on["buckets"]) {
			rows = append(rows, []string{"分桶 " + anyStr(b["bucket"]), "心跳落桶设备 " + itoa(anyInt(b["count"]))})
		}
		return "在线率统计", []string{"指标", "数值"}, rows
	case "compliance":
		cp, _ := ov["compliance"].(map[string]any)
		rows := [][]string{
			{"数据源", anyStr(cp["baseline"])},
			{"合规阈值", itoa(anyInt(cp["threshold"]))},
			{"参评设备数", itoa(anyInt(cp["scored_devices"]))},
			{"合规设备数", itoa(anyInt(cp["compliant"]))},
			{"不合规设备数", itoa(anyInt(cp["non_compliant"]))},
			{"合规率(%)", fmt.Sprintf("%.1f", anyFloat(cp["compliance_rate"]))},
			{"平均评分", fmt.Sprintf("%.1f", anyFloat(cp["avg_score"]))},
		}
		for _, d := range anyMapList(cp["by_device"]) {
			rows = append(rows, []string{
				anyStr(d["device_id"]), anyStr(d["hostname"]), orDefault(anyStr(d["department"]), "(未分组)"),
				itoa(anyInt(d["score"])), boolCN(anyBool(d["compliant"])),
				strings.Join(anyStrs(d["reasons"]), "、"),
			})
		}
		return "合规率统计", []string{"设备ID/指标", "主机名/说明", "部门", "评分/数值", "是否合规", "不合规原因"}, rows
	case "vuln":
		vu, _ := ov["vuln"].(map[string]any)
		sev := map[string]int{}
		if m, ok := vu["by_severity"].(map[string]int); ok {
			sev = m
		}
		rows := [][]string{
			{"严重", itoa(sev["critical"])},
			{"高危", itoa(sev["high"])},
			{"中危", itoa(sev["medium"])},
			{"低危", itoa(sev["low"])},
			{"合计", itoa(anyInt(vu["total"]))},
			{"说明", anyStr(vu["note"])},
		}
		return "漏洞统计", []string{"项目", "数值"}, rows
	case "rc":
		rc, _ := ov["rc"].(map[string]any)
		rows := [][]string{
			{"会话总次数", itoa(anyInt(rc["sessions_total"]))},
			{"已结束会话", itoa(anyInt(rc["sessions_ended"]))},
			{"进行中会话", itoa(anyInt(rc["sessions_active"]))},
			{"累计时长(秒)", itoa(anyInt(rc["total_duration_sec"]))},
			{"平均时长(秒)", itoa(anyInt(rc["avg_duration_sec"]))},
		}
		for _, o := range anyMapList(rc["by_operator"]) {
			rows = append(rows, []string{"操作员 " + anyStr(o["operator"]), "会话 " + itoa(anyInt(o["sessions"]))})
		}
		return "远控统计", []string{"指标", "数值"}, rows
	default:
		return "", nil, nil
	}
}

// ==================== 持久化双写（PostgreSQL 模式尽力而为）====================

func (h *Hub) w5bPG() (*store.PostgresStore, bool) {
	pg, ok := h.store.(*store.PostgresStore)
	return pg, ok
}

func (h *Hub) w5bSavePolicy(p *store.PeripheralPolicy) {
	pg, ok := h.w5bPG()
	if !ok {
		return
	}
	_ = pg.Exec(`INSERT INTO peripheral_policies (id,name,scope_type,scope_value,usb_storage,optical,bluetooth,enabled,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, scope_type=EXCLUDED.scope_type,
		scope_value=EXCLUDED.scope_value, usb_storage=EXCLUDED.usb_storage, optical=EXCLUDED.optical,
		bluetooth=EXCLUDED.bluetooth, enabled=EXCLUDED.enabled, updated_at=EXCLUDED.updated_at`,
		p.ID, p.Name, p.ScopeType, p.ScopeValue, p.USBStorage, p.Optical, p.Bluetooth, p.Enabled, p.CreatedAt, p.UpdatedAt)
}

func (h *Hub) w5bSaveApplied(st *store.PeripheralApplyState) {
	rt := h.w5b()
	rt.mu.Lock()
	rt.applied[appliedKey(st.DeviceID, st.PolicyID)] = st
	rt.mu.Unlock()
	pg, ok := h.w5bPG()
	if !ok {
		return
	}
	_ = pg.Exec(`INSERT INTO peripheral_apply_state (device_id,policy_id,status,usb_storage,optical,bluetooth,message,dry_run,applied_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (device_id,policy_id) DO UPDATE SET status=EXCLUDED.status, usb_storage=EXCLUDED.usb_storage,
		optical=EXCLUDED.optical, bluetooth=EXCLUDED.bluetooth, message=EXCLUDED.message,
		dry_run=EXCLUDED.dry_run, applied_at=EXCLUDED.applied_at`,
		st.DeviceID, st.PolicyID, st.Status, st.USBStorage, st.Optical, st.Bluetooth, st.Message, st.DryRun, st.AppliedAt)
}

func (h *Hub) w5bPersistNAC(a *store.NACAction) {
	rt := h.w5b()
	rt.mu.Lock()
	rt.nac[a.DeviceID] = a
	rt.mu.Unlock()
	h.persistNACPG(a)
}

// persistNACLocked 在调用方已持有 rt.mu 时落库（避免重复加锁）。
func (h *Hub) persistNACLocked(a *store.NACAction) {
	rt := h.w5b()
	rt.nac[a.DeviceID] = a
	h.persistNACPG(a)
}

func (h *Hub) persistNACPG(a *store.NACAction) {
	pg, ok := h.w5bPG()
	if !ok {
		return
	}
	_ = pg.Exec(`INSERT INTO nac_actions (id,device_id,action,reason,expire_at,state,applied,message,score,trigger_src,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (id) DO UPDATE SET action=EXCLUDED.action, reason=EXCLUDED.reason, expire_at=EXCLUDED.expire_at,
		state=EXCLUDED.state, applied=EXCLUDED.applied, message=EXCLUDED.message, score=EXCLUDED.score,
		trigger_src=EXCLUDED.trigger_src, updated_at=EXCLUDED.updated_at`,
		a.ID, a.DeviceID, a.Action, a.Reason, w5bTimeArg(a.ExpireAt), a.State, a.Applied, a.Message, a.Score, a.Trigger, a.CreatedAt, a.UpdatedAt)
}

// ==================== 小工具 ====================

func w5bTimeArg(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func w5bTimeText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func pctOf(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

func firstLine(s, def string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func anyInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

func anyFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	}
	return 0
}

func anyStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func anyBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func anyStrs(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, anyStr(e))
		}
		return out
	}
	return nil
}

func anyMapList(v any) []map[string]any {
	if m, ok := v.([]map[string]any); ok {
		return m
	}
	return nil
}

func boolCN(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

// 权限常量在 auth 包；此处做编译期引用校验，避免误删权限点。
var _ = auth.PermDeviceCmd
