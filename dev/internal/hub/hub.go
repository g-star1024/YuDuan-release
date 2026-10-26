// Package hub 实现御端服务端中枢。
// 职责：Agent 长连接纳管（注册/心跳/指令结果）、管理 REST API（RBAC 门禁 + 审计）、
// 远程控制信令与画面中继（M4）、软件仓库与分发（M5）、资产台账与报表。
// M6 新增：登录鉴权 / RBAC 接口门禁 / 审计落库 / AD-LDAP 目录同步。
// 安全基座：关键指令 HMAC 签名（副端验签）；TLS 由入口层（cmd/hub）承载。
package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/ed25519"

	"yuduan/internal/audit"
	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/directory"
	"yuduan/internal/proto"
	"yuduan/internal/record"
	"yuduan/internal/store"
	"yuduan/internal/ws"
)

// RCSession 记录一个进行中的远控会话（Hub 居中中继，局域网不出公网）。
type RCSession struct {
	SessionID string
	DeviceID  string
	Operator  string
	Viewer    *ws.Conn
	StartedAt time.Time
	Consent   bool
	rec       *record.Writer // 加密录像（启用 YUDUAN_RC_RECORD 后首帧懒开；endSession 落盘）
	recFailed bool           // 录像文件创建失败标记（本会话不再尝试）
}

// HubConfig 是中枢的可选配置；缺省项自动回退到内存实现。
type HubConfig struct {
	RepoDir     string
	Store       store.Store
	Auditor     audit.Auditor
	Users       auth.UserStore
	Auth        *auth.AuthService
	HMACSecret  string
	HMACEnforce bool
	DirSync     *directory.SyncEngine
	HubID       string // 多中枢部署时的节点标识（缺省 hub-<hostname>）
	PublicAddr  string // 节点对外地址（/api/v1/hubs 展示用）
	SignSeed    []byte // Ed25519 32 字节种子（YUDUAN_SIGN_SEED）；为空 = 软件包不签名（仅记哈希）

	// §5 加密录像留存（opt-in）：RecordEnabled 开启后，中继媒体帧逐帧 AES-GCM 落盘，
	// endSession 关闭文件；Janitor 按 RecordRetentionDays 清理过期录像。
	RecordEnabled       bool
	RecordDir           string
	RecordRetentionDays int
	RecordKey           []byte // 录像主密钥（nil = 从 HMAC 密钥派生开发态兜底）
}

// Hub 是中枢核心结构。
type Hub struct {
	store   store.Store
	auditor audit.Auditor
	users   auth.UserStore
	authSvc *auth.AuthService
	secret  string
	enforce bool
	dirSync *directory.SyncEngine

	mu       sync.Mutex
	conns    map[string]*ws.Conn // deviceID -> 控制面长连接
	pending  map[string]chan proto.ResultPayload
	sessions map[string]*RCSession // deviceID -> 远控会话
	software map[string]*proto.SoftwareItem
	repoDir  string

	hubID      string
	publicAddr string
	bus        *CommandBus // 非 nil 时指令走多中枢总线（去粘性）

	signSeed []byte // Ed25519 种子（可能为空）
	signPub  string // 由 signSeed 派生的公钥 hex（可能为空）

	recEnabled   bool
	recDir       string
	recRetention int
	recKey       []byte
	stopJanitor  func()

	// 输入观测（排查误注入）：mouse_move 聚合计数 + 上次汇总时间戳
	inMoveCount atomic.Uint64
	lastMoveLog atomic.Int64
}

// NewHub 构造中枢，缺省回退到内存实现。
func NewHub(cfg HubConfig) *Hub {
	if cfg.RepoDir == "" {
		cfg.RepoDir = "data/repo"
	}
	if cfg.Store == nil {
		cfg.Store = store.NewMemStore()
	}
	if cfg.Auditor == nil {
		cfg.Auditor = audit.NewMemAuditor()
	}
	if cfg.Users == nil {
		cfg.Users = store.NewMemUserStore()
	}
	if cfg.Auth == nil {
		cfg.Auth = auth.NewAuthService(cfg.Users, cfg.HMACSecret, "")
	}
	_ = os.MkdirAll(cfg.RepoDir, 0o755)
	hubID := cfg.HubID
	if hubID == "" {
		host, _ := os.Hostname()
		hubID = "hub-" + host
	}
	h := &Hub{
		store:        cfg.Store,
		auditor:      cfg.Auditor,
		users:        cfg.Users,
		authSvc:      cfg.Auth,
		secret:       cfg.HMACSecret,
		enforce:      cfg.HMACEnforce,
		dirSync:      cfg.DirSync,
		conns:        make(map[string]*ws.Conn),
		pending:      make(map[string]chan proto.ResultPayload),
		sessions:     make(map[string]*RCSession),
		software:     make(map[string]*proto.SoftwareItem),
		repoDir:      cfg.RepoDir,
		hubID:        hubID,
		publicAddr:   cfg.PublicAddr,
		signSeed:     cfg.SignSeed,
		recEnabled:   cfg.RecordEnabled,
		recDir:       cfg.RecordDir,
		recRetention: cfg.RecordRetentionDays,
		recKey:       cfg.RecordKey,
	}
	if h.recEnabled {
		if h.recDir == "" {
			h.recDir = "data/recordings"
		}
		if h.recRetention <= 0 {
			h.recRetention = 90
		}
		if h.recKey == nil {
			// 开发态兜底：从 HMAC 密钥派生（keystore.LoadRecordKey 未配置时）。
			h.recKey = record.DeriveMaster(cfg.HMACSecret)
		}
		_ = os.MkdirAll(h.recDir, 0o700)
		h.stopJanitor = record.StartJanitor(h.recDir, h.recRetention, time.Hour)
		log.Printf("[hub] 远控录像已启用：dir=%s 留存=%d 天", h.recDir, h.recRetention)
	}
	h.initSigning()
	return h
}

// initSigning 派生签名公钥（供软件包签名与下发校验参数使用）。
func (h *Hub) initSigning() {
	if len(h.signSeed) == ed25519.SeedSize {
		priv := ed25519.NewKeyFromSeed(h.signSeed)
		h.signPub = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	}
}

// Handler 返回 HTTP 路由（REST + WS + 控制台静态页）。
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/agent", h.handleAgentWS)
	mux.HandleFunc("/ws/viewer", h.handleViewerWS)
	// 公开
	mux.HandleFunc("/api/v1/login", h.handleLogin)
	// 受保护：自助改密（仅需登录；must_change 账户的唯一放行接口）
	mux.HandleFunc("/api/v1/password", h.guardAuthOnly(h.handleChangePassword))
	// 受保护：资产
	mux.HandleFunc("/api/v1/devices", h.guard(auth.PermDeviceView, h.handleDevices))
	mux.HandleFunc("/api/v1/report", h.guard(auth.PermDeviceView, h.handleReport))
	mux.HandleFunc("/api/v1/devices/", h.guardDeviceByID)
	// 受保护：软件仓库
	mux.HandleFunc("/api/v1/software", h.guardSoftware)
	mux.HandleFunc("/api/v1/repo/", h.handleRepo) // 副端下载（演示放开；生产应短令牌/鉴权）
	// 受保护：审计 / 目录同步
	mux.HandleFunc("/api/v1/audit", h.guard(auth.PermAuditView, h.handleAudit))
	mux.HandleFunc("/api/v1/audit/verify", h.guard(auth.PermAuditView, h.handleAuditVerify))
	mux.HandleFunc("/api/v1/dirsync", h.guard(auth.PermDirSync, h.handleDirSync))
	// 受保护：账号管理（admin）
	mux.HandleFunc("/api/v1/admin/users", h.guard(auth.PermUserManage, h.handleAdminUsers))
	mux.HandleFunc("/api/v1/admin/users/", h.guard(auth.PermUserManage, h.handleAdminUserAction))
	// 受保护：多中枢节点视图（admin）
	mux.HandleFunc("/api/v1/hubs", h.guard(auth.PermUserManage, h.handleHubs))
	// 受保护：远控录像列表（§5 加密留存；admin 查阅）
	mux.HandleFunc("/api/v1/recordings", h.guard(auth.PermAuditView, h.handleRecordings))
	mux.HandleFunc("/", h.handleConsole)
	return mux
}

// guard 包裹受保护接口：校验 Bearer 令牌并判定角色权限。
// 携带 must_change 标记的令牌除改密接口外一律 403（强制改密）。
func (h *Hub) guard(perm string, fn func(http.ResponseWriter, *http.Request, crypto.Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := h.authSvc.VerifyToken(auth.TokenFromHeader(r.Header.Get("Authorization")))
		if err != nil {
			writeErr(w, 401, "unauthorized")
			return
		}
		if claims.MustChange {
			writeErr(w, 4033, "password_change_required")
			return
		}
		if !h.authSvc.HasPerm(claims.Role, perm) {
			writeErr(w, 403, "forbidden: 需要权限 "+perm)
			return
		}
		fn(w, r, claims)
	}
}

// guardAuthOnly 仅校验令牌有效性（不做权限/改密判定），供自助改密接口使用。
func (h *Hub) guardAuthOnly(fn func(http.ResponseWriter, *http.Request, crypto.Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := h.authSvc.VerifyToken(auth.TokenFromHeader(r.Header.Get("Authorization")))
		if err != nil {
			writeErr(w, 401, "unauthorized")
			return
		}
		fn(w, r, claims)
	}
}

// guardDeviceByID 根据子路径选择所需权限（GET 查看 / POST 指令）。
func (h *Hub) guardDeviceByID(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet:
		h.guard(auth.PermDeviceView, h.handleDeviceGet).ServeHTTP(w, r)
	case r.Method == http.MethodPost:
		h.guard(auth.PermDeviceCmd, h.handleDeviceCmd).ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Hub) guardSoftware(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.guard(auth.PermDeviceView, h.handleSoftwareList).ServeHTTP(w, r)
	case http.MethodPost:
		h.guard(auth.PermSoftwareMgmt, h.handleSoftwareUpload).ServeHTTP(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// audit 写入一条审计记录。
func (h *Hub) audit(actor, action, target, detail, result string) {
	if h.auditor != nil {
		h.auditor.Record(audit.Event{Actor: actor, Action: action, Target: target, Detail: detail, Result: result})
	}
}

// StartReaper 定期检查心跳超时，将超过 90s 未心跳的设备标记为离线。
func (h *Hub) StartReaper() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		now := time.Now().UTC()
		for _, d := range h.store.List() {
			if d.Online && now.Sub(d.LastSeen) > 90*time.Second {
				h.store.MarkOffline(d.ID)
				log.Printf("[hub] reaper: %s marked offline (last seen %s)", d.Hostname, d.LastSeen.Format(time.RFC3339))
			}
		}
	}
}

// RunDirSync 执行一次目录同步并写审计。
func (h *Hub) RunDirSync(actor string) (interface{}, error) {
	if h.dirSync == nil {
		return nil, nil
	}
	res, err := h.dirSync.Sync()
	if err != nil {
		h.audit(actor, "dir_sync", "", "同步失败: "+err.Error(), "failed")
		return nil, err
	}
	h.audit(actor, "dir_sync", "", "同步用户数="+itoa(res.UsersSynced), "success")
	return res, nil
}

// ---- 登录 ----

func (h *Hub) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	res, err := h.authSvc.Login(body.Username, body.Password)
	if err != nil {
		h.audit(body.Username, "login", "", "登录失败", "failed")
		writeErr(w, 401, "invalid credentials")
		return
	}
	h.audit(body.Username, "login", "", "角色="+res.Role, "success")
	writeJSON(w, map[string]any{"code": 0, "token": res.Token, "role": res.Role, "must_change_password": res.MustChangePassword})
}

// handleChangePassword 自助改密：校验旧口令 + 强度策略；成功后清除 must_change 标记。
func (h *Hub) handleChangePassword(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := h.authSvc.ChangePassword(claims.Username, body.OldPassword, body.NewPassword); err != nil {
		h.audit(claims.Username, "password_change", claims.Username, "改密失败: "+err.Error(), "failed")
		writeErr(w, 4002, err.Error())
		return
	}
	h.audit(claims.Username, "password_change", claims.Username, "改密成功", "success")
	// 签发新令牌（must_change 已清除），前端无缝续用
	res, err := h.authSvc.Login(claims.Username, body.NewPassword)
	if err != nil {
		writeJSON(w, map[string]any{"code": 0, "message": "password changed"})
		return
	}
	writeJSON(w, map[string]any{"code": 0, "token": res.Token, "role": res.Role})
}

// handleAdminUsers 账号列表（admin）。
func (h *Hub) handleAdminUsers(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"total": h.users.Count(), "users": h.users.ListUsers()})
}

// handleAdminUserAction 账号级管理动作（admin）：
//
//	POST /api/v1/admin/users/{name}/force-password-change  强制改密
//	POST /api/v1/admin/users/{name}/disable                禁用
//	POST /api/v1/admin/users/{name}/enable                 启用
func (h *Hub) handleAdminUserAction(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/users/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" {
		writeErr(w, 4001, "usage: /api/v1/admin/users/{name}/{force-password-change|disable|enable}")
		return
	}
	name, action := parts[0], parts[1]
	u, ok := h.users.GetUserByName(name)
	if !ok {
		writeErr(w, 4004, "user not found")
		return
	}
	switch action {
	case "force-password-change":
		if err := h.authSvc.ForcePasswordChange(name); err != nil {
			writeErr(w, 4004, err.Error())
			return
		}
		h.audit(claims.Username, "force_pw_change", name, "管理员设置强制改密", "success")
		writeJSON(w, map[string]any{"code": 0, "message": "ok"})
	case "disable":
		u.Disabled = true
		h.users.UpsertUser(u)
		h.audit(claims.Username, "user_disable", name, "管理员禁用账号", "success")
		writeJSON(w, map[string]any{"code": 0, "message": "ok"})
	case "enable":
		u.Disabled = false
		h.users.UpsertUser(u)
		h.audit(claims.Username, "user_enable", name, "管理员启用账号", "success")
		writeJSON(w, map[string]any{"code": 0, "message": "ok"})
	default:
		writeErr(w, 4001, "unknown action: "+action)
	}
}

// ---- Agent 长连接 ----

func (h *Hub) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		return
	}
	defer conn.Close()

	var deviceID string
	for {
		raw, isBinary, err := conn.ReadMessageTyped()
		if err != nil {
			break
		}
		// 二进制帧：远控媒体帧透传（§8.3 P2P 兜底/中继模式），无需解析信封。
		if isBinary {
			h.relayToViewer(deviceID, raw, true)
			continue
		}
		var env proto.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		switch env.Type {
		case proto.TypeRegister:
			var p proto.RegisterPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			dev := store.Device{
				Hostname: p.Hostname, OS: p.OS, OSVersion: p.OSVersion, Arch: p.Arch,
				CPU: p.CPU, MemoryGB: p.MemoryGB, DiskGB: p.DiskGB, SerialNo: p.SerialNo,
				MAC: p.MAC, IP: p.IP, AgentVersion: p.AgentVersion, Token: p.Token,
			}
			saved := h.store.Upsert(dev)
			deviceID = saved.ID
			h.mu.Lock()
			h.conns[deviceID] = conn
			h.mu.Unlock()
			ack, _ := proto.NewEnvelope(proto.TypeRegisterAck, 0, proto.RegisterAckPayload{
				DeviceID: saved.ID, Token: saved.Token, OK: true,
			})
			ackBytes, _ := json.Marshal(ack)
			_ = conn.WriteMessage(ackBytes)
			log.Printf("[hub] agent registered: id=%s %s (%s/%s) mem=%dGB disk=%dGB", saved.ID, saved.Hostname, saved.OS, saved.Arch, saved.MemoryGB, saved.DiskGB)

		case proto.TypeHeartbeat:
			if deviceID != "" {
				h.store.Touch(deviceID)
			}

		case proto.TypeResult:
			var p proto.ResultPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			h.mu.Lock()
			ch, ok := h.pending[p.TaskID]
			if ok {
				delete(h.pending, p.TaskID)
			}
			h.mu.Unlock()
			if ok {
				ch <- p
			}
			log.Printf("[hub] result task=%s state=%s exit=%d", p.TaskID, p.State, p.ExitCode)

		case proto.TypeRCReady, proto.TypeRCFrame, proto.TypeRCEvent, proto.TypeRCCapabilities, proto.TypeRCAnswer, proto.TypeRCCandidate, proto.TypeRCPong:
			h.relayToViewer(deviceID, raw, false)
		case proto.TypeRCStop:
			h.endSession(deviceID)

		default:
		}
	}

	if deviceID != "" {
		h.store.MarkOffline(deviceID)
		h.endSession(deviceID)
		h.mu.Lock()
		delete(h.conns, deviceID)
		h.mu.Unlock()
		log.Printf("[hub] agent offline: %s", deviceID)
	}
}

// relayToViewer 将 Agent 消息透传给会话 Viewer；binary=true 时按二进制帧写（媒体帧中继）。
// 启用录像时，中继的二进制媒体帧同步加密落盘（§5；落盘失败不阻断会话，仅记日志一次）。
func (h *Hub) relayToViewer(deviceID string, raw []byte, binary bool) {
	h.mu.Lock()
	s, ok := h.sessions[deviceID]
	h.mu.Unlock()
	if !ok || s.Viewer == nil {
		return
	}
	if binary {
		if h.recEnabled {
			h.recordFrame(s, raw)
		}
		_ = s.Viewer.WriteBinary(raw)
		return
	}
	_ = s.Viewer.WriteMessage(raw)
}

// recordFrame 懒开录像文件并追加一帧；失败仅记一次日志（录像不可用不阻断远控）。
func (h *Hub) recordFrame(s *RCSession, raw []byte) {
	if s.rec == nil {
		if s.recFailed {
			return
		}
		w, err := record.Open(h.recDir, h.recKey, record.Meta{
			SessionID: s.SessionID, DeviceID: s.DeviceID, Operator: s.Operator,
			StartedAt: s.StartedAt, Consent: s.Consent,
		})
		if err != nil {
			s.recFailed = true
			log.Printf("[hub] 录像文件创建失败（本会话不再录像）: %v", err)
			return
		}
		s.rec = w
	}
	if err := s.rec.WriteFrame(raw); err != nil {
		log.Printf("[hub] 录像写入失败: %v", err)
	}
}

func (h *Hub) endSession(deviceID string) {
	h.mu.Lock()
	s, ok := h.sessions[deviceID]
	delete(h.sessions, deviceID)
	h.mu.Unlock()
	if ok && s.Viewer != nil {
		_ = s.Viewer.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCStop}))
	}
	// §5：会话结束落盘录像，写审计（帧数/字节数可追溯）。
	if ok && s.rec != nil {
		path, frames, nbytes := s.rec.Close()
		h.audit(s.Operator, "rc_record_saved", s.DeviceID,
			fmt.Sprintf("远控录像已留存 %s（%d 帧，%d 字节密文）", filepath.Base(path), frames, nbytes), "success")
		log.Printf("[hub] rc recording saved session=%s frames=%d bytes=%d", s.SessionID, frames, nbytes)
	}
}

// handleRecordings 列出加密录像文件（§5）：名称/大小/修改时间（不回传内容；回放需 master 密钥）。
func (h *Hub) handleRecordings(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	if !h.recEnabled {
		writeJSON(w, map[string]any{"enabled": false, "total": 0, "recordings": []any{}})
		return
	}
	entries, err := os.ReadDir(h.recDir)
	if err != nil && !os.IsNotExist(err) {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	type item struct {
		Name     string    `json:"name"`
		Bytes    int64     `json:"bytes"`
		Modified time.Time `json:"modified"`
	}
	var list []item
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yrec") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		list = append(list, item{Name: e.Name(), Bytes: info.Size(), Modified: info.ModTime().UTC()})
	}
	if list == nil {
		list = []item{}
	}
	writeJSON(w, map[string]any{"enabled": true, "retention_days": h.recRetention, "total": len(list), "recordings": list})
}

// ---- Viewer 长连接（M4 远控）----

func (h *Hub) handleViewerWS(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Upgrade(w, r)
	if err != nil {
		return
	}
	defer conn.Close()

	var deviceID string
	for {
		raw, isBinary, err := conn.ReadMessageTyped()
		if err != nil {
			break
		}
		// 二进制帧：Viewer→Agent 媒体方向（如输入回显/音频上行，§8.3 对称中继）。
		if isBinary {
			h.mu.Lock()
			agentConn, ok := h.conns[deviceID]
			h.mu.Unlock()
			if ok {
				_ = agentConn.WriteBinary(raw)
			}
			continue
		}
		var env proto.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		switch env.Type {
		case proto.TypeRCRequest:
			var p proto.RCRequestPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			h.mu.Lock()
			agentConn, ok := h.conns[p.DeviceID]
			h.mu.Unlock()
			if !ok {
				_ = conn.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCEvent, Payload: mustRaw(proto.RCEventPayload{
					SessionID: p.SessionID, Kind: "error", Message: "设备离线，无法建立远控会话",
				})}))
				continue
			}
			h.mu.Lock()
			h.sessions[p.DeviceID] = &RCSession{
				SessionID: p.SessionID, DeviceID: p.DeviceID, Operator: p.Operator,
				Viewer: conn, StartedAt: time.Now().UTC(),
			}
			h.mu.Unlock()
			deviceID = p.DeviceID
			// 铁律 4：远控会话发起属关键指令，转发前由中枢签名（副端验签后才执行）。
			_ = agentConn.WriteMessage(h.signForAgent(&env, raw))
			h.audit(p.Operator, "rc_start", p.DeviceID, "远控会话开启", "success")
			log.Printf("[hub] rc session start device=%s operator=%s", p.DeviceID, p.Operator)

		case proto.TypeRCInput, proto.TypeRCStop, proto.TypeRCSelect, proto.TypeRCOffer, proto.TypeRCCandidate, proto.TypeRCQos, proto.TypeRCPing:
			// 观测：mouse_move 高频聚合（5s 一条汇总），其余 rc_input 全量记录 kind/key——
			// 用于排查「主端触摸板操作 → 副端异常打字」类输入误注入问题。
			if env.Type == proto.TypeRCInput {
				var ip struct {
					Kind string `json:"kind"`
					Key  string `json:"key"`
				}
				_ = json.Unmarshal(env.Payload, &ip)
				if ip.Kind == "mouse_move" {
					h.inMoveCount.Add(1)
					now := time.Now().Unix()
					last := h.lastMoveLog.Load()
					if last == 0 || now-last >= 5 {
						if h.lastMoveLog.CompareAndSwap(last, now) {
							n := h.inMoveCount.Swap(0)
							log.Printf("[hub] rc_input mouse_move ×%d（5s 聚合）", n)
						}
					}
				} else {
					log.Printf("[hub] rc_input kind=%q key=%q", ip.Kind, ip.Key)
				}
			}
			// rc_stop 精确匹配（§8.3 会话生命周期）：仅当载荷 session_id 与当前会话一致
			// （或载荷为空的历史客户端）才转发给副端并结束会话。否则视为旧会话残留指令
			// （如前端 StrictMode 双挂载的清理），不得误杀新会话——endSession 会把
			// sessions[deviceID] 整条删掉并给 viewer 代发 rc_stop，曾导致新会话黑屏。
			if env.Type == proto.TypeRCStop {
				var sp struct {
					SessionID string `json:"session_id"`
				}
				_ = json.Unmarshal(env.Payload, &sp)
				h.mu.Lock()
				s, ok := h.sessions[deviceID]
				matched := ok && (sp.SessionID == "" || sp.SessionID == s.SessionID)
				h.mu.Unlock()
				if !matched {
					cur := ""
					if ok {
						cur = s.SessionID
					}
					log.Printf("[hub] rc_stop 忽略：session 不匹配（载荷 %q ≠ 当前 %q），疑似旧会话残留", sp.SessionID, cur)
					continue
				}
			}
			h.mu.Lock()
			agentConn, ok := h.conns[deviceID]
			h.mu.Unlock()
			if ok {
				// 铁律 4：rc_input/rc_stop/rc_select/rc_offer/rc_candidate/rc_qos/rc_ping
				// 均由中枢签发后转发，副端验签通过才执行（防伪造中枢/中间人注入输入）。
				_ = agentConn.WriteMessage(h.signForAgent(&env, raw))
			}
			if env.Type == proto.TypeRCStop {
				h.endSession(deviceID)
			}
		}
	}
}

// ---- REST 管理 API（受保护）----

func (h *Hub) handleDevices(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	list := h.store.List()
	writeJSON(w, map[string]any{"total": len(list), "devices": list})
}

func (h *Hub) handleReport(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	list := h.store.List()
	online := 0
	byOS := map[string]int{}
	for _, d := range list {
		if d.Online {
			online++
		}
		byOS[d.OS]++
	}
	writeJSON(w, map[string]any{
		"total": len(list), "online": online, "offline": len(list) - online, "by_os": byOS,
	})
}

func (h *Hub) handleDeviceGet(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	id := deviceIDFromPath(r.URL.Path)
	dev, ok := h.store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, dev)
}

func (h *Hub) handleDeviceCmd(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := deviceIDFromPath(r.URL.Path)
	var body struct {
		Action      string `json:"action"`
		Command     string `json:"command"`
		SoftwareURL string `json:"software_url"`
		Platform    string `json:"platform"`
		PkgName     string `json:"pkg_name"`
		Sha256      string `json:"sha256"`
		Signature   string `json:"signature"`
		Signer      string `json:"signer"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	timeout := 15 * time.Second
	if body.Action == "sw_install" {
		timeout = 120 * time.Second
		// 生产化：若 software_url 指向本仓库（/api/v1/repo/{id}），自动附加
		// 中枢签发的校验参数，使副端能做哈希比对 + Ed25519 验签；外部 URL 不附加。
		if repoID := repoIDFromURL(body.SoftwareURL); repoID != "" {
			h.mu.Lock()
			it, ok := h.software[repoID]
			h.mu.Unlock()
			if ok {
				body.Sha256 = it.Sha256
				body.Signature = it.Signature
				body.Signer = it.Signer
			}
		}
	}

	taskID := newTaskID()
	cmd, _ := proto.NewEnvelope(proto.TypeCommand, 0, proto.CommandPayload{
		Action: body.Action, TaskID: taskID, Command: body.Command,
		SoftwareURL: body.SoftwareURL, Platform: body.Platform, PkgName: body.PkgName,
		Sha256: body.Sha256, Signature: body.Signature, Signer: body.Signer,
	})
	h.sign(&cmd) // 安全基座：关键指令 HMAC 签名
	cmdBytes, _ := json.Marshal(cmd)

	auditDetail := "action=" + body.Action + " cmd=" + body.Command
	var res proto.ResultPayload
	var err error
	if h.bus != nil {
		// 多中枢总线：落 outbox → 本地认领或跨实例执行（去粘性）
		res, err = h.bus.Dispatch(id, taskID, cmdBytes, timeout)
	} else {
		// 单实例（内存模式）：本地直发
		h.mu.Lock()
		conn, ok := h.conns[id]
		h.mu.Unlock()
		if !ok {
			writeErr(w, 2001, "device offline")
			return
		}
		if err = conn.WriteMessage(cmdBytes); err != nil {
			writeErr(w, 2001, "send failed: "+err.Error())
			return
		}
		res, err = h.awaitTaskResult(taskID, timeout)
	}
	if err != nil {
		h.audit(claims.Username, "command", id, auditDetail, "failed")
		writeErr(w, 2001, err.Error())
		return
	}
	h.audit(claims.Username, "command", id, auditDetail, "success")
	writeJSON(w, res)
}

// awaitTaskResult 注册 taskID 等待通道并阻塞至回执或超时。
func (h *Hub) awaitTaskResult(taskID string, timeout time.Duration) (proto.ResultPayload, error) {
	ch := make(chan proto.ResultPayload, 1)
	h.mu.Lock()
	h.pending[taskID] = ch
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, taskID)
		h.mu.Unlock()
	}()
	select {
	case res := <-ch:
		return res, nil
	case <-time.After(timeout):
		return proto.ResultPayload{}, fmt.Errorf("command timeout")
	}
}

// deviceOnlineLocal 判断设备是否长连接在本实例。
func (h *Hub) deviceOnlineLocal(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.conns[id]
	return ok
}

// sendToDevice 经本实例长连接下发原始信封。
func (h *Hub) sendToDevice(id string, envBytes []byte) bool {
	h.mu.Lock()
	conn, ok := h.conns[id]
	h.mu.Unlock()
	if !ok {
		return false
	}
	return conn.WriteMessage(envBytes) == nil
}

// localDeviceIDs 返回本实例在线设备 ID 列表（总线认领用）。
func (h *Hub) localDeviceIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.conns))
	for id := range h.conns {
		ids = append(ids, id)
	}
	return ids
}

// handleHubs 多中枢节点视图（集群心跳）。
func (h *Hub) handleHubs(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	if h.bus == nil {
		writeJSON(w, map[string]any{"total": 0, "hubs": []HubNode{}, "note": "bus disabled (memory mode)"})
		return
	}
	nodes := h.bus.Nodes()
	writeJSON(w, map[string]any{"total": len(nodes), "hubs": nodes, "self": h.hubID})
}

func (h *Hub) handleSoftwareList(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	h.mu.Lock()
	items := make([]*proto.SoftwareItem, 0, len(h.software))
	for _, it := range h.software {
		items = append(items, it)
	}
	h.mu.Unlock()
	writeJSON(w, map[string]any{"total": len(items), "items": items})
}

func (h *Hub) handleSoftwareUpload(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		writeErr(w, 3002, "parse form failed: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 3003, "missing file field")
		return
	}
	defer file.Close()
	name := r.FormValue("name")
	version := r.FormValue("version")
	platform := r.FormValue("platform")
	if name == "" {
		name = strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
	}
	if version == "" {
		version = "1.0.0"
	}
	if platform == "" {
		platform = "any"
	}
	id := "sw-" + randHex(8)
	dst := filepath.Join(h.repoDir, id)
	out, err := os.Create(dst)
	if err != nil {
		writeErr(w, 3004, "save failed: "+err.Error())
		return
	}
	size, err := io.Copy(out, file)
	out.Close()
	if err != nil {
		writeErr(w, 3004, "save failed: "+err.Error())
		return
	}
	// 生产化：落盘后回读计算 SHA-256 并（若配置种子）做 Ed25519 签名，随项持久于内存目录。
	data, rerr := os.ReadFile(dst)
	if rerr != nil {
		writeErr(w, 3005, "read-back failed: "+rerr.Error())
		return
	}
	shaHex, sigHex, signer := h.signSoftware(data)
	item := &proto.SoftwareItem{
		ID: id, Name: name, Version: version, Platform: platform,
		FileName: header.Filename, Size: size, UploadedAt: time.Now().Unix(),
		Sha256: shaHex, Signature: sigHex, Signer: signer,
	}
	h.mu.Lock()
	h.software[id] = item
	h.mu.Unlock()
	if sigHex != "" {
		log.Printf("[hub] software uploaded & signed: %s v%s (%s) %d bytes sha256=%s signer=%s", name, version, platform, size, shaHex[:16], signer[:16])
	} else {
		log.Printf("[hub] software uploaded (unsigned): %s v%s (%s) %d bytes sha256=%s", name, version, platform, size, shaHex[:16])
	}
	h.audit(claims.Username, "software_upload", id, "name="+name+" v"+version+" sha256="+shaHex, "success")
	writeJSON(w, map[string]any{"code": 0, "item": item})
}

func (h *Hub) handleRepo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/repo/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	item, ok := h.software[id]
	h.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(h.repoDir, id)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+item.FileName+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

func (h *Hub) handleAudit(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, map[string]any{"total": h.auditor.AuditCount(), "events": h.auditor.Query(limit)})
}

// handleAuditVerify 重放审计哈希链，返回 WORM 完整性结论。
func (h *Hub) handleAuditVerify(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rep := h.auditor.VerifyChain()
	h.audit("system", "audit_verify", "", fmt.Sprintf("chain valid=%v checked=%d", rep.Valid, rep.Checked), "success")
	writeJSON(w, rep)
}

func (h *Hub) handleDirSync(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	res, err := h.RunDirSync(claims.Username)
	if err != nil {
		writeErr(w, 5001, err.Error())
		return
	}
	writeJSON(w, map[string]any{"code": 0, "result": res})
}

// ---- 控制台静态页 ----

func (h *Hub) handleConsole(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/index.html":
		http.ServeFile(w, r, "console/index.html")
	case "/login.html":
		http.ServeFile(w, r, "console/login.html")
	case "/change-password.html":
		http.ServeFile(w, r, "console/change-password.html")
	case "/audit.html":
		http.ServeFile(w, r, "console/audit.html")
	case "/rc.html":
		http.ServeFile(w, r, "console/rc.html")
	case "/software.html":
		http.ServeFile(w, r, "console/software.html")
	default:
		http.NotFound(w, r)
	}
}

// ---- 安全基座：指令签名 ----

func (h *Hub) sign(env *proto.Envelope) {
	if h.secret == "" {
		return
	}
	env.Sig = crypto.SignCommand(h.secret, env.MsgID, env.Ts, env.Seq, string(env.Payload), env.Nonce)
}

// signForAgent 规范化并签名一条「中枢→副端」信封，返回待发送字节。
//
// 铁律 4：remote_control 等关键指令必须 HMAC-SHA256 签名 + seq/nonce 防重放。
// 远控消息的原始信封由 Viewer（Tauri 主端 / 浏览器控制台）构造，字段完备度不一
// （主端不带 nonce），因此中枢在转发前统一补齐再签发——中枢是唯一控制平面，
// 也是唯一签发方，副端只需与中枢口径一致（YUDUAN_HMAC_SECRET 相同）。
// 未配置密钥时返回原样字节（开发态放行，行为与改造前一致）。
func (h *Hub) signForAgent(env *proto.Envelope, raw []byte) []byte {
	if h.secret == "" {
		return raw // 未启用签名：原样透传（开发态）
	}
	proto.NormalizeForSigning(env)

	// 定型：json.Marshal 会压缩空白并对 <、>、& 做 HTML 转义。签名必须覆盖「实际发送
	// 出去的 payload 字节」——副端是从收到的帧里原样提取 payload 再验签的。
	// 若按序列化前的 Payload 签名（例如主端发来带空格的 JSON），两端字节不一致，
	// 必然验签失败。故先序列化一次，按最终字节形态回填 Payload，再签名、再发送。
	// （本轮 e2e 场景 A 首跑即命中此坑：副端日志「HMAC 验签失败」）
	shaped, err := json.Marshal(env)
	if err != nil {
		return raw
	}
	var fixed proto.Envelope
	if err := json.Unmarshal(shaped, &fixed); err != nil {
		return raw
	}
	h.sign(&fixed)
	out, err := json.Marshal(&fixed)
	if err != nil {
		return raw
	}
	return out
}

// signSoftware 计算文件 SHA-256，并在配置 Ed25519 种子时对「32 字节摘要」签名，
// 返回 (sha256Hex, signatureHex, signerPubHex)。未配置种子时仅返回哈希（不签名）。
// 与副端 Rust ed25519::sign(seed, digest) 同语义：签名消息即 32 字节摘要本身。
func (h *Hub) signSoftware(data []byte) (string, string, string) {
	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])
	if len(h.signSeed) == ed25519.SeedSize {
		priv := ed25519.NewKeyFromSeed(h.signSeed)
		sig := ed25519.Sign(priv, sum[:]) // 对 32 字节摘要签名（Rust 副端同样以 digest 为消息验签）
		return shaHex, hex.EncodeToString(sig), hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	}
	return shaHex, "", ""
}

// ---- helpers ----

func deviceIDFromPath(path string) string {
	trimmed := strings.TrimPrefix(path, "/api/v1/devices/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// repoIDFromURL 从软件下载 URL 解析仓库项 ID（/api/v1/repo/{id}）。
// 仅当 URL 指向本中枢仓库时才返回 id，外部 URL 返回空（不附加校验参数）。
func repoIDFromURL(url string) string {
	const prefix = "/api/v1/repo/"
	idx := strings.Index(url, prefix)
	if idx < 0 {
		return ""
	}
	rest := url[idx+len(prefix):]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": msg})
}

func newTaskID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "t-" + hex.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func mustRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [12]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func atoi(s string) (int, error) {
	n, err := atoi64(s)
	return int(n), err
}

func atoi64(s string) (int64, error) {
	n := int64(0)
	neg := false
	i := 0
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		neg = s[i] == '-'
		i++
	}
	if i == len(s) {
		return 0, jsonError("not a number")
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, jsonError("not a number")
		}
		n = n*10 + int64(s[i]-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

func jsonError(s string) error { return &simpleErr{s} }

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }
