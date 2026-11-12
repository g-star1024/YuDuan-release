// 波次 2：远控会话内协作的中枢侧实现（PRD 5.2 C4/C5/C7/C9/C10/C11）。
//
// 覆盖范围：
//   - W2-4 敏感设备远控二级审批（发起与审批分离，仅 admin 可放行）
//   - W2-5 会话超时断开（绝对时长上限 + 主端空闲超时）与强制结束（REST kill）
//   - 会话视图（GET /api/v1/rc/sessions）与画面状态回显（黑屏/水印，W2-3 由副端执行）
//
// 边界：中枢仍是唯一控制平面（铁律 3）。会话内聊天（W2-2）与文件传输（W2-1）
// 在本层只做「按会话归属的白名单转发」，不解析内容、不落库，避免把个人对话与
// 文件内容写进 WORM 审计链（铁律 5 最小必要）。
package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/proto"
	"yuduan/internal/store"
	"yuduan/internal/ws"
)

// RCApproval 是敏感设备远控的待审批工单（W2-4）。
// 中枢在收到 rc_request 且目标设备标记为敏感时创建工单，不立即建会话、不转发给副端；
// 由具备 rc:approve 权限（仅 admin）的账号经 REST 放行后才继续。
type RCApproval struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name,omitempty"`
	Operator   string    `json:"operator"` // 发起人（自 rc_request 载荷）
	SessionID  string    `json:"session_id"`
	Reason     string    `json:"reason"` // 触发审批的原因（敏感设备）
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"` // pending / approved / rejected / expired
	DecidedBy  string    `json:"decided_by,omitempty"`
	DecidedAt  time.Time `json:"decided_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`

	viewer *ws.Conn        // 发起方 Viewer 连接（仅用于回告结果）
	rawEnv json.RawMessage // 原始 rc_request 信封（批准后由中枢签名转发）
}

// 审批工单状态常量。
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalExpired  = "expired"
)

// 审批工单默认有效期（超时未决自动作废，避免工单悬挂导致远控长期不可用亦不可审计）。
const approvalTTL = 15 * time.Minute

// ---- W2-4 二级审批：工单创建 ----

// requestApproval 为目标敏感设备的远控请求创建待审批工单，并回告发起方。
// 返回 false 表示设备离线（与既有 rc_request 语义一致）。
func (h *Hub) requestApproval(viewer *ws.Conn, env *proto.Envelope, p proto.RCRequestPayload, devName, operator string) bool {
	h.mu.Lock()
	agentConn, ok := h.conns[p.DeviceID]
	h.mu.Unlock()
	if !ok {
		_ = viewer.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCEvent, Payload: mustRaw(proto.RCEventPayload{
			SessionID: p.SessionID, Kind: "error", Message: "设备离线，无法建立远控会话",
		})}))
		return false
	}
	_ = agentConn // 保持既有「离线判定」语义：连接存在才允许进入审批（批准后复用）

	now := time.Now().UTC()
	h.mu.Lock()
	h.approvalSeq++
	a := &RCApproval{
		ID:         fmt.Sprintf("apr-%d", h.approvalSeq),
		DeviceID:   p.DeviceID,
		DeviceName: devName,
		Operator:   operator, // 复盘 V-10：operator 取自握手鉴权 claims，不信载荷自报
		SessionID:  p.SessionID,
		Reason:     "目标设备已标记为敏感，需管理员二级审批",
		CreatedAt:  now,
		ExpiresAt:  now.Add(approvalTTL),
		Status:     ApprovalPending,
		viewer:     viewer,
		rawEnv:     env.Payload,
	}
	h.approvals[a.ID] = a
	h.mu.Unlock()

	// 回告发起方：审批中（前端据此展示「等待管理员审批」而不是黑屏等待）
	_ = viewer.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCEvent, Payload: mustRaw(proto.RCEventPayload{
		SessionID: p.SessionID, Kind: "approval_required",
		Message: fmt.Sprintf("目标设备为敏感终端，已提交二级审批（工单 %s），请等待管理员放行", a.ID),
	})}))
	h.audit(p.Operator, "rc_approval_requested", p.DeviceID,
		fmt.Sprintf("敏感设备远控待审批 工单=%s 会话=%s", a.ID, p.SessionID), "pending")
	// W1-5 告警中心同步可见（管理员在主端可看到待办）
	h.addAlert(alertOf(store.AlertRCApproval, p.DeviceID, devName, "远控待二级审批",
		fmt.Sprintf("发起人=%s 工单=%s", p.Operator, a.ID)))
	log.Printf("[hub] rc approval requested id=%s device=%s operator=%s", a.ID, p.DeviceID, p.Operator)
	return true
}

// handleRCApprovals 列出远控审批工单（W2-4）。
func (h *Hub) handleRCApprovals(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	h.mu.Lock()
	list := make([]*RCApproval, 0, len(h.approvals))
	for _, a := range h.approvals {
		// 惰性过期：查询时把超期未决工单置为 expired（不阻塞请求路径）
		if a.Status == ApprovalPending && time.Now().UTC().After(a.ExpiresAt) {
			a.Status = ApprovalExpired
		}
		list = append(list, a)
	}
	h.mu.Unlock()
	// 按创建时间倒序（最新待办在前）
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].CreatedAt.After(list[j-1].CreatedAt); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	status := r.URL.Query().Get("status")
	if status != "" {
		filtered := list[:0]
		for _, a := range list {
			if a.Status == status {
				filtered = append(filtered, a)
			}
		}
		list = filtered
	}
	writeJSON(w, map[string]any{"total": len(list), "approvals": list})
}

// handleRCApprove 审批远控工单（W2-4）：POST /api/v1/rc/approvals/{id}  {"approve":true}
// 仅 rc:approve（admin）可用——发起与审批权分离，避免单人即可触达敏感终端。
// v0.4.16（实测报告问题 4）：请求体严格校验——此前 _ = Decode 忽略错误与未知字段，
// {"decision":"approved"} / {"approved":true} 等写法落到零值 Approve=false 被**静默判拒**，
// 误读成「管理员拒绝」。现改为：解码失败 / 未知字段 / 缺 approve / 类型不符一律 400(code=2007)。
func (h *Hub) handleRCApprove(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/rc/approvals/")
	var body struct {
		Approve *bool  `json:"approve"`
		Reason  string `json:"reason,omitempty"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeErrStatus(w, http.StatusBadRequest, 2009, "请求体非法（应为 {\"approve\":bool}）: "+err.Error())
		return
	}
	if body.Approve == nil {
		writeErrStatus(w, http.StatusBadRequest, 2009, "缺少必填字段 approve（布尔）：{\"approve\":true} 或 {\"approve\":false}；字段名不是 decision/approved")
		return
	}
	approve := *body.Approve

	h.mu.Lock()
	a, ok := h.approvals[id]
	h.mu.Unlock()
	if !ok {
		writeErr(w, 2004, "审批工单不存在: "+id)
		return
	}
	if a.Status != ApprovalPending {
		writeErr(w, 2005, "审批工单已处理: "+a.Status)
		return
	}
	if time.Now().UTC().After(a.ExpiresAt) {
		h.mu.Lock()
		a.Status = ApprovalExpired
		h.mu.Unlock()
		writeErr(w, 2006, "审批工单已过期")
		return
	}

	h.mu.Lock()
	a.DecidedBy = claims.Username
	a.DecidedAt = time.Now().UTC()
	if approve {
		a.Status = ApprovalApproved
	} else {
		a.Status = ApprovalRejected
	}
	h.mu.Unlock()

	if !approve {
		h.audit(claims.Username, "rc_approval_rejected", a.DeviceID,
			fmt.Sprintf("工单=%s 发起人=%s 理由=%s", a.ID, a.Operator, orDefault(body.Reason, "未填写")), "rejected")
		if a.viewer != nil {
			_ = a.viewer.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCEvent, Payload: mustRaw(proto.RCEventPayload{
				SessionID: a.SessionID, Kind: "approval_rejected",
				Message: fmt.Sprintf("管理员 %s 拒绝了本次远控申请", claims.Username),
			})}))
		}
		writeJSON(w, map[string]any{"ok": true, "status": a.Status})
		return
	}

	// 放行：重建 rc_request 信封 → 由中枢签名后转发给副端（铁律 4）→ 建会话。
	env := &proto.Envelope{Type: proto.TypeRCRequest, Payload: a.rawEnv}
	var p proto.RCRequestPayload
	_ = env.DecodePayload(&p)
	h.mu.Lock()
	agentConn, ok := h.conns[a.DeviceID]
	if !ok {
		h.mu.Unlock()
		writeErr(w, 2007, "设备已离线，审批通过但无法建立会话")
		return
	}
	h.sessions[a.DeviceID] = &RCSession{
		SessionID: a.SessionID, DeviceID: a.DeviceID, Operator: a.Operator,
		Viewer: a.viewer, StartedAt: time.Now().UTC(), LastActive: time.Now().UTC(),
		Approved: true, ApprovedBy: claims.Username,
		MaxSec: h.rcMaxSec, IdleSec: h.rcIdleSec,
	}
	h.mu.Unlock()
	signed, _ := json.Marshal(env)
	_ = agentConn.WriteMessage(h.signForAgent(env, signed))
	h.audit(claims.Username, "rc_approval_granted", a.DeviceID,
		fmt.Sprintf("工单=%s 发起人=%s 会话=%s", a.ID, a.Operator, a.SessionID), "success")
	h.audit(a.Operator, "rc_start", a.DeviceID, "远控会话开启（二级审批放行）", "success")
	if a.viewer != nil {
		_ = a.viewer.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCEvent, Payload: mustRaw(proto.RCEventPayload{
			SessionID: a.SessionID, Kind: "approval_granted",
			Message: fmt.Sprintf("管理员 %s 已放行，远控会话建立中", claims.Username),
		})}))
	}
	writeJSON(w, map[string]any{"ok": true, "status": a.Status})
}

// ---- W2-5 会话视图 / 强制结束 / 超时扫描 ----

// handleRCSessions 列出进行中的远控会话（W2-5 管理可视性）。
func (h *Hub) handleRCSessions(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	now := time.Now().UTC()
	type item struct {
		SessionID    string `json:"session_id"`
		DeviceID     string `json:"device_id"`
		DeviceName   string `json:"device_name,omitempty"`
		Operator     string `json:"operator"`
		StartedAt    string `json:"started_at"`
		DurationSec  int64  `json:"duration_sec"`
		IdleSec      int64  `json:"idle_sec"`
		MaxSec       int    `json:"max_sec"`
		IdleLimitSec int    `json:"idle_limit_sec"`
		Blank        bool   `json:"blank"`
		Watermark    bool   `json:"watermark"`
		Approved     bool   `json:"approved"`
		ApprovedBy   string `json:"approved_by,omitempty"`
	}
	h.mu.Lock()
	out := make([]item, 0, len(h.sessions))
	for _, s := range h.sessions {
		name := ""
		if d, ok := h.store.Get(s.DeviceID); ok {
			name = d.Hostname
		}
		out = append(out, item{
			SessionID: s.SessionID, DeviceID: s.DeviceID, DeviceName: name, Operator: s.Operator,
			StartedAt:   s.StartedAt.Format(time.RFC3339),
			DurationSec: int64(now.Sub(s.StartedAt).Seconds()),
			IdleSec:     int64(now.Sub(s.LastActive).Seconds()),
			MaxSec:      s.MaxSec, IdleLimitSec: s.IdleSec,
			Blank: s.Blank, Watermark: s.Watermark, Approved: s.Approved, ApprovedBy: s.ApprovedBy,
		})
	}
	h.mu.Unlock()
	writeJSON(w, map[string]any{"total": len(out), "sessions": out})
}

// handleRCKill 强制结束指定设备的远控会话（W2-5）：POST /api/v1/rc/sessions/{device}/kill
func (h *Hub) handleRCKill(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	deviceID := idAfterPrefix(r.URL.Path, "/api/v1/rc/sessions/")
	deviceID = trimSuffix(deviceID, "/kill")
	h.mu.Lock()
	s, ok := h.sessions[deviceID]
	h.mu.Unlock()
	if !ok {
		writeErr(w, 2008, "该设备无进行中的远控会话")
		return
	}
	h.endSession(deviceID, "管理员强制结束")
	h.audit(claims.Username, "rc_kill", deviceID,
		fmt.Sprintf("强制结束远控会话 %s（原操作员 %s）", s.SessionID, s.Operator), "success")
	h.addAlert(alertOf(store.AlertRCTimeout, deviceID, "", "远控会话被强制结束",
		fmt.Sprintf("操作员 %s → 由 %s 强制结束", s.Operator, claims.Username)))
	writeJSON(w, map[string]any{"ok": true, "session_id": s.SessionID})
}

// StartRCSweeper 周期扫描远控会话超时（W2-5）：
//   - 绝对时长上限 MaxSec（默认 4h）：长时间挂机会话强制断开，避免无人值守的常开通道；
//   - 主端空闲上限 IdleSec（默认 30min）：主端长时间无任何输入指令视为遗忘挂机。
//
// 二者任一为 0 表示关闭该维度。超时同时回告主端（rc_event kind=session_timeout）
// 并向副端发 rc_stop，保证双端状态一致（不出现「主端已断、副端仍在采集」）。
func (h *Hub) StartRCSweeper() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		now := time.Now().UTC()
		h.mu.Lock()
		var expired []*RCSession
		for _, s := range h.sessions {
			if s.MaxSec > 0 && now.Sub(s.StartedAt) > time.Duration(s.MaxSec)*time.Second {
				expired = append(expired, s)
				continue
			}
			if s.IdleSec > 0 && now.Sub(s.LastActive) > time.Duration(s.IdleSec)*time.Second {
				expired = append(expired, s)
			}
		}
		h.mu.Unlock()
		for _, s := range expired {
			reason := "会话超过最大时长"
			if s.IdleSec > 0 && now.Sub(s.LastActive) > time.Duration(s.IdleSec)*time.Second {
				reason = "主端空闲超时"
			}
			log.Printf("[hub] rc session timeout device=%s session=%s reason=%s", s.DeviceID, s.SessionID, reason)
			if s.Viewer != nil {
				_ = s.Viewer.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCEvent, Payload: mustRaw(proto.RCEventPayload{
					SessionID: s.SessionID, Kind: "session_timeout", Message: "远控会话已超时结束（" + reason + "）",
				})}))
			}
			h.endSession(s.DeviceID, reason)
			h.audit(s.Operator, "rc_timeout", s.DeviceID,
				fmt.Sprintf("远控会话超时结束（%s）会话=%s", reason, s.SessionID), "timeout")
			h.addAlert(alertOf(store.AlertRCTimeout, s.DeviceID, "", "远控会话超时结束",
				fmt.Sprintf("操作员=%s 原因=%s", s.Operator, reason)))
		}
	}
}

// touchRCSession 刷新会话活跃时间（W2-5 空闲超时基准）。
func (h *Hub) touchRCSession(deviceID string) {
	h.mu.Lock()
	if s, ok := h.sessions[deviceID]; ok {
		s.LastActive = time.Now().UTC()
	}
	h.mu.Unlock()
}

// setRCDisplay 记录会话画面状态（W2-3，供会话视图回显）。
func (h *Hub) setRCDisplay(deviceID string, blank, watermark bool) {
	h.mu.Lock()
	if s, ok := h.sessions[deviceID]; ok {
		s.Blank = blank
		s.Watermark = watermark
	}
	h.mu.Unlock()
}

// ---- 内部小工具 ----

// alertOf 构造一条告警（W1-5 告警中心复用）。
func alertOf(typ, deviceID, deviceName, msg, detail string) store.Alert {
	return store.Alert{Type: typ, Severity: severityOf(typ), DeviceID: deviceID, DeviceName: deviceName, Message: msg, Detail: detail}
}

func severityOf(typ string) string {
	switch typ {
	case store.AlertAssetChange:
		return store.SeverityCritical
	case store.AlertRCApproval:
		return store.SeverityWarning
	case store.AlertRCTimeout:
		return store.SeverityInfo
	default:
		return store.SeverityWarning
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func trimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}

// 权限常量在 auth 包；此处做编译期引用校验，避免误删权限点。
var _ = auth.PermRCApprove
