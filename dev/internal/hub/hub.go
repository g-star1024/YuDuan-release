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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/ed25519"

	consolefs "yuduan/console"
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
	// W2-5 会话超时：LastActive 记录主端最后一次下发指令的时间（空闲判定基准）；
	// MaxSec=绝对时长上限（0=不限），IdleSec=主端空闲上限（0=不限）。
	LastActive time.Time
	MaxSec     int
	IdleSec    int
	// W2-3 画面状态（黑屏/水印）：中枢不执行，仅记录供管理视图与会话视图回显。
	Blank     bool
	Watermark bool
	// W2-4 二级审批：经审批放行的会话记录审批人与标记。
	Approved   bool
	ApprovedBy string
	rec        *record.Writer // 加密录像（启用 YUDUAN_RC_RECORD 后首帧懒开；endSession 落盘）
	recFailed  bool           // 录像文件创建失败标记（本会话不再尝试）
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

	// 设备引导配置下发（档位 A：广播一次性注册令牌 + 副端 claim 换取）。
	// 副端经 /api/agent/claim 用有效令牌换取 HMAC 密钥与（可选）mTLS 客户端证书。
	// CACert/CAKey 同时非空 = 中枢启用 mTLS，claim 时为副端签发客户端证书；
	// TLSAddr 非空 = 返回给副端（副端以此决定走 wss://<tlsAddr> 而非明文）。
	CACert  string
	CAKey   string
	TLSAddr string

	// §5 加密录像留存（opt-in）：RecordEnabled 开启后，中继媒体帧逐帧 AES-GCM 落盘，
	// endSession 关闭文件；Janitor 按 RecordRetentionDays 清理过期录像。
	RecordEnabled       bool
	RecordDir           string
	RecordRetentionDays int
	RecordKey           []byte // 录像主密钥（nil = 从 HMAC 密钥派生开发态兜底）

	// W2-5 会话超时阈值（秒）：RCMaxSec=绝对时长上限，RCIdleSec=主端空闲上限；
	// 0 或未提供 = 取环境变量/默认值（YUDUAN_RC_MAX_SEC / YUDUAN_RC_IDLE_SEC）。
	RCMaxSec  int
	RCIdleSec int

	// MaxDevices 设备台账上限（复盘 S-3/V-03）：/ws/agent 注册不验凭据，无上限时
	// 任意内网主机可零成本刷出海量假设备（内存与台账 DoS）。0 = 取
	// YUDUAN_MAX_DEVICES（缺省 5000）。新设备注册超限即拒绝（ack OK=false）。
	MaxDevices int

	// P-1 投产阻断：PG 备份/恢复。
	// BackupDir=备份目录（默认 data/backups）；BackupKeep=保留份数（默认 7）；
	// BackupInterval=自动备份间隔（默认 24h；0=关闭自动备份，仅手动）。
	// 仅 PostgreSQL 后端支持（内存后端备份端点返回明确错误）。
	BackupDir      string
	BackupKeep     int
	BackupInterval time.Duration

	// P-2 投产阻断：告警外部通知（webhook 优先）。
	// AlertWebhookURL 为空 = 不发送外部通知（仅站内徽章）。
	AlertWebhookURL string
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

	// W2-4 二级审批工单（敏感设备远控）
	approvals   map[string]*RCApproval
	approvalSeq int64
	// W2-5 会话超时阈值（0=关闭该维度）；由 YUDUAN_RC_MAX_SEC / YUDUAN_RC_IDLE_SEC 覆盖
	rcMaxSec  int
	rcIdleSec int

	hubID      string
	publicAddr string
	bus        *CommandBus // 非 nil 时指令走多中枢总线（去粘性）

	signSeed []byte // Ed25519 种子（可能为空）
	signPub  string // 由 signSeed 派生的公钥 hex（可能为空）

	// 设备引导配置下发（档位 A）：广播响应的当前有效注册令牌 + claim 校验。
	claimMu     sync.Mutex
	claimToken  string
	claimTokenT time.Time
	caCert      string
	caKey       string
	tlsAddr     string

	recEnabled   bool
	recDir       string
	recRetention int
	recKey       []byte
	stopJanitor  func()

	// 输入观测（排查误注入）：mouse_move 聚合计数 + 上次汇总时间戳
	inMoveCount atomic.Uint64
	lastMoveLog atomic.Int64

	// 设备台账上限（复盘 S-3）：0 = 已按 YUDUAN_MAX_DEVICES 回填默认值
	maxDevices int

	// P-1 备份管理（仅 PostgreSQL 后端支持；内存后端备份端点返回明确错误）
	backupDir      string
	backupKeep     int
	backupInterval time.Duration
	backupMu       sync.Mutex
	backupLast     time.Time

	// P-2 告警 webhook（为空 = 不发送外部通知）
	alertWebhookURL string
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
		caCert:       cfg.CACert,
		caKey:        cfg.CAKey,
		tlsAddr:      cfg.TLSAddr,
		// W2-4/W2-5：审批工单表与会话超时阈值（0=关闭该维度）
		approvals:  make(map[string]*RCApproval),
		rcMaxSec:   cfg.RCMaxSec,
		rcIdleSec:  cfg.RCIdleSec,
		maxDevices: cfg.MaxDevices,
	}
	if h.rcMaxSec == 0 {
		h.rcMaxSec = envInt("YUDUAN_RC_MAX_SEC", 4*60*60) // 默认 4 小时绝对上限
	}
	if h.rcIdleSec == 0 {
		h.rcIdleSec = envInt("YUDUAN_RC_IDLE_SEC", 30*60) // 默认 30 分钟主端空闲
	}
	if h.maxDevices == 0 {
		h.maxDevices = envInt("YUDUAN_MAX_DEVICES", 5000) // 防假设备洪泛（复盘 S-3）
	}
	// P-1 备份初始化（仅 PG 后端真正生效；内存后端 runBackup 返回明确错误）
	h.backupDir = cfg.BackupDir
	if h.backupDir == "" {
		h.backupDir = "data/backups"
	}
	h.backupKeep = cfg.BackupKeep
	if h.backupKeep <= 0 {
		h.backupKeep = 7
	}
	h.backupInterval = cfg.BackupInterval
	if h.backupInterval == 0 {
		h.backupInterval = 24 * time.Hour
	}
	_ = os.MkdirAll(h.backupDir, 0o700)
	// P-2 告警 webhook（为空 = 不发送外部通知）
	h.alertWebhookURL = cfg.AlertWebhookURL
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
	// W1-2/3：台账分组元数据 + 生命周期状态流转
	mux.HandleFunc("/api/v1/devices/meta/", h.guard(auth.PermDeviceView, h.handleDeviceUpdate))
	mux.HandleFunc("/api/v1/devices/lifecycle/", h.guard(auth.PermDeviceCmd, h.handleDeviceLifecycle))
	// W1-6：资产报表导出（CSV/XLSX）
	mux.HandleFunc("/api/v1/report/export", h.guard(auth.PermDeviceView, h.handleReportExport))
	// W1-5：实时告警中心
	mux.HandleFunc("/api/v1/alerts", h.guard(auth.PermDeviceView, h.handleAlerts))
	mux.HandleFunc("/api/v1/alerts/unread", h.guard(auth.PermDeviceView, h.handleAlertUnread))
	mux.HandleFunc("/api/v1/alerts/read-all", h.guard(auth.PermDeviceView, h.handleAlertReadAll))
	mux.HandleFunc("/api/v1/alerts/", h.guard(auth.PermDeviceView, h.handleAlertRead))
	// 受保护：软件仓库
	mux.HandleFunc("/api/v1/software", h.guardSoftware)
	mux.HandleFunc("/api/v1/repo/", h.handleRepo) // 副端下载（演示放开；生产应短令牌/鉴权）
	// 受保护：审计 / 目录同步
	mux.HandleFunc("/api/v1/audit", h.guard(auth.PermAuditView, h.handleAudit))
	mux.HandleFunc("/api/v1/audit/verify", h.guard(auth.PermAuditView, h.handleAuditVerify))
	// W1-7：审计日志导出（CSV/JSON）
	mux.HandleFunc("/api/v1/audit/export", h.guard(auth.PermAuditView, h.handleAuditExport))
	// W2-5：远控会话视图 + 强制结束（会话管理）
	mux.HandleFunc("/api/v1/rc/sessions", h.guard(auth.PermRCSession, h.handleRCSessions))
	mux.HandleFunc("/api/v1/rc/sessions/", h.guard(auth.PermRCSession, h.handleRCKill))
	// W2-4：敏感设备远控二级审批（列表读=会话权限，放行/驳回=审批权限，仅 admin）
	mux.HandleFunc("/api/v1/rc/approvals", h.guard(auth.PermRCSession, h.handleRCApprovals))
	mux.HandleFunc("/api/v1/rc/approvals/", h.guard(auth.PermRCApprove, h.handleRCApprove))
	mux.HandleFunc("/api/v1/dirsync", h.guard(auth.PermDirSync, h.handleDirSync))
	// 受保护：账号管理（admin）
	mux.HandleFunc("/api/v1/admin/users", h.guard(auth.PermUserManage, h.handleAdminUsers))
	mux.HandleFunc("/api/v1/admin/users/", h.guard(auth.PermUserManage, h.handleAdminUserAction))
	// 受保护：多中枢节点视图（admin）
	mux.HandleFunc("/api/v1/hubs", h.guard(auth.PermUserManage, h.handleHubs))
	// P-1 投产阻断：PG 备份/恢复（admin；仅 PostgreSQL 后端真正生效）
	mux.HandleFunc("/api/v1/admin/backup", h.guard(auth.PermUserManage, h.handleAdminBackup))
	mux.HandleFunc("/api/v1/admin/backups", h.guard(auth.PermUserManage, h.handleAdminBackups))
	mux.HandleFunc("/api/v1/admin/backup/restore", h.guard(auth.PermUserManage, h.handleAdminBackupRestore))

	// 设备引导配置下发（档位 A）：副端用广播令牌换取 HMAC 密钥/客户端证书。
	// 无鉴权——令牌本身短时效且每次广播轮换，仅放行本端点（不暴露控制面）。
	mux.HandleFunc("/api/agent/claim", h.handleAgentClaim)

	// 波次 3/4/5 路由挂载点（各波次在 waveN.go 内实现 waveNRoutes）
	wave3Routes(mux, h)
	wave4Routes(mux, h)
	wave5Routes(mux, h)
	// 受保护：远控录像列表（§5 加密留存；admin 查阅）
	mux.HandleFunc("/api/v1/recordings", h.guard(auth.PermAuditView, h.handleRecordings))
	mux.HandleFunc("/", h.handleConsole)
	// 访问日志：包裹全部路由（明文/TLS/mTLS 共用），登录或部署失败时可从 hub.log
	// 判断请求是否到达后端（无 [http] 行 = 进程未收到；有行 = 已处理，看 status）。
	return h.withAccessLog(mux)
}

// guard 包裹受保护接口：校验 Bearer 令牌并判定角色权限。
// 携带 must_change 标记的令牌除改密接口外一律 403（强制改密）。
func (h *Hub) guard(perm string, fn func(http.ResponseWriter, *http.Request, crypto.Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := h.authSvc.VerifyToken(auth.TokenFromHeader(r.Header.Get("Authorization")))
		if err != nil {
			writeErrStatus(w, http.StatusUnauthorized, 401, "unauthorized")
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
			writeErrStatus(w, http.StatusUnauthorized, 401, "unauthorized")
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
// W1-5：标记离线时同步产生 device_offline 告警（同设备未读去重，避免重复弹）。
func (h *Hub) StartReaper() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		now := time.Now().UTC()
		for _, d := range h.store.List() {
			if d.Online && now.Sub(d.LastSeen) > 90*time.Second {
				h.store.MarkOffline(d.ID)
				log.Printf("[hub] reaper: %s marked offline (last seen %s)", d.Hostname, d.LastSeen.Format(time.RFC3339))
				h.addAlert(store.Alert{
					Type: store.AlertDeviceOffline, Severity: store.SeverityWarning,
					DeviceID: d.ID, DeviceName: d.Hostname,
					Message: "设备离线", Detail: "超过 90s 未心跳，已标记离线",
				})
			}
		}
	}
}

// ---- W1-4 资产变更检测 ----

// detectAssetChange 对比注册前后硬件指纹，硬件变动产生 asset_change 告警。
// before.ID 为空 = 首次纳管（新设备），不算变更。
func (h *Hub) detectAssetChange(before, after store.Device) {
	if before.ID == "" || before.ID != after.ID {
		return
	}
	var changes []string
	if before.CPU != after.CPU {
		changes = append(changes, "CPU")
	}
	if before.MemoryGB != after.MemoryGB {
		changes = append(changes, fmt.Sprintf("内存 %d→%dGB", before.MemoryGB, after.MemoryGB))
	}
	if before.DiskGB != after.DiskGB {
		changes = append(changes, fmt.Sprintf("磁盘 %d→%dGB", before.DiskGB, after.DiskGB))
	}
	if before.SerialNo != "" && before.SerialNo != after.SerialNo {
		changes = append(changes, "序列号")
	}
	if before.MAC != "" && before.MAC != after.MAC {
		changes = append(changes, "MAC")
	}
	if len(changes) == 0 {
		return
	}
	detail := "硬件变更: " + strings.Join(changes, "、")
	log.Printf("[hub] asset change: %s (%s): %s", after.Hostname, after.ID, detail)
	h.addAlert(store.Alert{
		Type: store.AlertAssetChange, Severity: store.SeverityCritical,
		DeviceID: after.ID, DeviceName: after.Hostname,
		Message: "资产硬件变更", Detail: detail,
	})
}

// detectIPConflict 检测同 IP 多设备在线冲突（同一 IP 由不同设备注册）。
func (h *Hub) detectIPConflict(d store.Device) {
	if d.IP == "" {
		return
	}
	for _, other := range h.store.List() {
		if other.ID != d.ID && other.Online && other.IP == d.IP {
			detail := fmt.Sprintf("IP %s 同时被 %s 与 %s 使用", d.IP, d.Hostname, other.Hostname)
			log.Printf("[hub] ip conflict: %s", detail)
			h.addAlert(store.Alert{
				Type: store.AlertIPConflict, Severity: store.SeverityWarning,
				DeviceID: d.ID, DeviceName: d.Hostname,
				Message: "IP 冲突", Detail: detail,
			})
			return
		}
	}
}

// addAlert 写入一条告警并记录审计（告警可读可标记；审计 WORM 不受影响）。
// P-2：写入后异步触发外部 webhook 通知（不阻塞；失败退避重试）。
func (h *Hub) addAlert(a store.Alert) {
	saved := h.store.AddAlert(a)
	h.audit("system", "alert", a.DeviceID, a.Message+": "+a.Detail, "success")
	h.notifyAlertWebhook(saved)
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

// handleAdminUsers 账号管理（admin）：
//
//	GET  /api/v1/admin/users           账号列表
//	POST /api/v1/admin/users           创建账号 {username,display_name,role,password}
func (h *Hub) handleAdminUsers(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"total": h.users.Count(), "users": h.users.ListUsers()})
	case http.MethodPost:
		var body struct {
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			Role        string `json:"role"`
			Password    string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if err := h.authSvc.CreateUser(body.Username, body.DisplayName, body.Role, body.Password); err != nil {
			h.audit(claims.Username, "user_create", body.Username, "创建失败: "+err.Error(), "failed")
			writeErr(w, 4002, err.Error())
			return
		}
		h.audit(claims.Username, "user_create", body.Username, "角色="+body.Role, "success")
		writeJSON(w, map[string]any{"code": 0, "message": "created"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
	case "role":
		// POST /api/v1/admin/users/{name}/role  body:{"role":"admin|operator|viewer"}
		var body struct {
			Role string `json:"role"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !auth.ValidRole(body.Role) {
			writeErr(w, 4001, "invalid role: must be admin/operator/viewer")
			return
		}
		u.Role = body.Role
		h.users.UpsertUser(u)
		h.audit(claims.Username, "user_role", name, "改角色="+body.Role, "success")
		writeJSON(w, map[string]any{"code": 0, "message": "ok"})
	case "reset-password":
		// POST /api/v1/admin/users/{name}/reset-password  body:{"password":"..."}
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if err := h.authSvc.ResetPassword(name, body.Password); err != nil {
			writeErr(w, 4002, err.Error())
			return
		}
		h.audit(claims.Username, "user_reset_pw", name, "管理员重置密码", "success")
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

	// ---- §9.1 注册凭据握手（复盘 S-3/V-03 修复）----
	//
	// 此前本机这条处理函数对任何内网来源的 register 一律照收：既不验证来者为谁，
	// 也不检查其是否持有授权凭据。后果是任意主机可以①自报一个 token 就地新建
	// 无限台假设备污染台账；②报出他人设备的 token 直接顶替上线设备，接管它的
	// 指令流并回送伪造执行结果——REST 侧的登录 / RBAC / 二级审批 / WORM 审计
	// 在这条通道上被整体旁路（与 /ws/viewer 无鉴权、claim 令牌可重放串联成完整
	// 攻击链，见 v0.2.6 复盘报告第一章）。
	//
	// 修复口径：连接建立即下发随机挑战，副端须以与中枢共享的 HMAC 密钥自证
	// （该密钥由设备引导档位 A 的 claim 流程经一次性令牌 + TLS 安全下发，是
	// 「此设备已获中枢授权」的既有凭证，不新增密钥管理面）。未完成握手的连接
	// 任何消息都不处理，register 直接 nack 并断开。
	nonce := crypto.Nonce()
	challenge, err := proto.NewEnvelope(proto.TypeAuthChallenge, 0, proto.AuthChallengePayload{
		Nonce: nonce,
		TS:    time.Now().Unix(),
	})
	if err == nil {
		if cb, mErr := json.Marshal(challenge); mErr == nil {
			if wErr := conn.WriteMessage(cb); wErr != nil {
				log.Printf("[hub] 下发注册挑战失败 from %s: %v", r.RemoteAddr, wErr)
				return
			}
		}
	}

	var (
		authed       bool   // 是否已完成凭据握手
		claimedToken string // 握手时绑定进签名的设备令牌
		violations   int    // 未握手期间的违规消息计数
	)
	// 握手限期：30s 未完成即断开，防止未认证连接长期占用句柄。
	authDone := make(chan struct{})
	var authOnce, closeOnce sync.Once
	markAuthed := func() { authOnce.Do(func() { close(authDone) }) }
	defer markAuthed()
	go func() {
		t := time.NewTimer(30 * time.Second)
		defer t.Stop()
		select {
		case <-authDone:
		case <-t.C:
			log.Printf("[hub] 注册凭据握手超时（30s），断开 %s", r.RemoteAddr)
			closeOnce.Do(func() { _ = conn.Close() })
		}
	}()

	// 保活（半开连接检测）：每 30s 服务端主动 ping，副端（Go/Rust 均已实现
	// ping→pong 自动回执）回 pong。75s 无任何 pong 判定链路已死，主动关闭——
	// 否则对端异常掉电/断网时，本端半开连接会长期占用 conns 并让台账状态失真。
	var lastPong atomic.Int64
	lastPong.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := conn.WritePing([]byte("ka")); err != nil {
					_ = conn.Close() // 写失败=链路已死，唤醒读循环
					return
				}
				if time.Since(time.Unix(0, lastPong.Load())) > 75*time.Second {
					_ = conn.Close()
					return
				}
			}
		}
	}()

	var deviceID string
	for {
		raw, isBinary, err := conn.ReadMessageTyped()
		if err != nil {
			break
		}
		lastPong.Store(time.Now().UnixNano()) // 任何入站流量都视作存活证据（含 pong）
		// 二进制帧：远控媒体帧透传（§8.3 P2P 兜底/中继模式），无需解析信封。
		// 未握手的连接不得投喂媒体帧（设备身份未知，无法判定会话归属）。
		if isBinary {
			if authed {
				h.relayToViewer(deviceID, raw, true)
			}
			continue
		}
		var env proto.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}

		// §9.1 凭据门禁：未握手的连接只允许 auth_response，其余一律不处理。
		if !authed {
			if env.Type != proto.TypeAuthResponse {
				violations++
				if env.Type == proto.TypeRegister {
					// 未自证身份即要求纳管——正是 S-3 的攻击形态，一律 nack（不创建设备、
					// 不记录台账）。此处刻意**不断连**：握手设计为顺序无关，副端可以先
					// 直发 register（老流程）再补握手，避免新旧次序互锁导致整网起不来。
					// 攻击者拿不到任何能力，且 30s 握手限期到点即断。
					nack, _ := proto.NewEnvelope(proto.TypeRegisterAck, 0, proto.RegisterAckPayload{
						OK: false, Reason: "unauthenticated: 须先完成注册凭据握手（§9.1）",
					})
					_ = conn.WriteMessage(mustJSON(nack))
					log.Printf("[hub] 拒绝未认证注册 from %s（缺少 §9.1 凭据握手）", r.RemoteAddr)
					h.audit("system", "agent_register_denied", r.RemoteAddr, "未持有有效注册凭据却请求纳管", "denied")
				}
				if violations >= 5 {
					log.Printf("[hub] 未握手连接的违规消息达 %d 条，断开 %s", violations, r.RemoteAddr)
					return
				}
				continue
			}
			var ap proto.AuthResponsePayload
			if err := env.DecodePayload(&ap); err != nil {
				log.Printf("[hub] 握手载荷解析失败 from %s: %v", r.RemoteAddr, err)
				return
			}
			// MAC 是唯一的秘密：nonce 与挑战同一连接同源，可明文比对；
			// 应答必须以共享密钥对 "yuduan-register|nonce|token" 计算，
			// 未持有密钥者无法伪造（恒定时间比较，避免逐字节试探）。
			if ap.Nonce == nonce && crypto.VerifyRegisterAuth(h.secret, nonce, ap.Token, ap.MAC) {
				authed = true
				claimedToken = ap.Token
				markAuthed()
				continue
			}
			log.Printf("[hub] 注册凭据校验失败 from %s：nonce 不匹配或 MAC 无效", r.RemoteAddr)
			h.audit("system", "agent_auth_failed", r.RemoteAddr, "注册挑战应答 MAC 校验失败", "denied")
			closeOnce.Do(func() { _ = conn.Close() })
			return
		}

		switch env.Type {
		case proto.TypeRegister:
			var p proto.RegisterPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			// §9.1：注册所用的设备令牌必须与握手时签名绑定的令牌一致，
			// 否则允许「换个 token 再注册一次」把凭据握手锁定的身份换掉。
			if p.Token != claimedToken {
				nack, _ := proto.NewEnvelope(proto.TypeRegisterAck, 0, proto.RegisterAckPayload{
					OK: false, Reason: "token_mismatch: 注册令牌与凭据握手时绑定的令牌不一致",
				})
				_ = conn.WriteMessage(mustJSON(nack))
				log.Printf("[hub] 拒绝注册：令牌与握手绑定不符 from %s", r.RemoteAddr)
				h.audit("system", "agent_register_denied", r.RemoteAddr, "注册令牌与凭据握手绑定的令牌不一致", "denied")
				return
			}
			// W1-4 变更检测：取变更前快照（按 token 复用身份，新设备为零值不告警）。
			before, _ := h.store.GetByToken(p.Token)
			// v0.4.8（实测报告问题 4）：token 轮换后（-ResetConfig / 重装副端重新 claim）
			// token 身份复用失效，同一台机器每次注册都会生成新设备 ID——内存模式无感，
			// PG 模式下台账重复建档、历史审计断链。按硬件身份（serial → hostname+mac）
			// 幂等查找既有设备并复用其 ID 与台账属性。
			identityReuse := false
			if before.ID == "" {
				if existing, ok := h.store.FindByIdentity(p.Hostname, p.MAC, p.SerialNo); ok {
					before = existing
					identityReuse = true
				}
			}
			// v0.4.10（实测报告问题 4 续）：副端自报硬件指纹稳定 ID——内存模式中枢重启/
			// 重装后台账清零，token/身份复用无从命中，设备 ID 依旧漂移（报告两轮复现）。
			// 指纹 ID 由副端本地派生（sha256("yuduan-device|serial|mac|hostname") 前 16 hex，
			// 不含任何可变量），同一台机器永远上报同一 ID。采纳规则：
			//   ① ID 未被占用 → 直接采纳（内存模式重启后即走此路，台账 ID 恒定）；
			//   ② 被占用但硬件身份一致 → 等价身份复用；
			//   ③ 被占用且身份不一致 → 拒绝采纳（防冒领他人设备 ID），回落随机 ID。
			proposedFree := false
			if !identityReuse && before.ID == "" && p.ProposedID != "" {
				if existing, ok := h.store.Get(p.ProposedID); !ok {
					proposedFree = true
				} else if p.MAC != "" && existing.MAC == p.MAC &&
					(existing.SerialNo == p.SerialNo || existing.Hostname == p.Hostname) {
					before = existing
					identityReuse = true
					log.Printf("[hub] 指纹 ID 命中既有设备：%s（host=%s mac=%s）", existing.ID, p.Hostname, p.MAC)
				} else {
					log.Printf("[hub] 拒绝采纳指纹 ID %s（已被 host=%s mac=%s 占用，身份不符，回落随机 ID）",
						p.ProposedID, existing.Hostname, existing.MAC)
				}
			}
			// 复盘 S-3/V-03：注册不验凭据时的最低防线——新设备注册超出台账上限即拒绝
			// （既有设备重连不受限），防任意内网主机零成本刷假设备打爆台账与内存。
			if before.ID == "" && h.maxDevices > 0 && len(h.store.List()) >= h.maxDevices {
				log.Printf("[hub] 拒绝新设备注册：已达台账上限 %d（host=%s from 注册连接）", h.maxDevices, p.Hostname)
				nack, _ := proto.NewEnvelope(proto.TypeRegisterAck, 0, proto.RegisterAckPayload{
					OK: false,
				})
				_ = conn.WriteMessage(mustJSON(nack))
				continue
			}
			dev := store.Device{
				Hostname: p.Hostname, OS: p.OS, OSVersion: p.OSVersion, Arch: p.Arch,
				CPU: p.CPU, MemoryGB: p.MemoryGB, DiskGB: p.DiskGB, SerialNo: p.SerialNo,
				MAC: p.MAC, IP: p.IP, AgentVersion: p.AgentVersion, Token: p.Token,
			}
			// v0.4.8 幂等注册：复用既有设备 ID 时，保留台账资产属性（分组/生命周期/
			// 指派人等），仅刷新硬件上报字段——与 token 复用路径的 Upsert 合并语义对齐。
			if identityReuse {
				dev.ID = before.ID
				dev.CreatedAt = before.CreatedAt
				dev.Department, dev.Floor, dev.Batch, dev.TagsJSON, dev.Tags =
					before.Department, before.Floor, before.Batch, before.TagsJSON, before.Tags
				dev.Lifecycle, dev.Assignee, dev.AssignedAt, dev.LifecycleNote, dev.Sensitive =
					before.Lifecycle, before.Assignee, before.AssignedAt, before.LifecycleNote, before.Sensitive
				log.Printf("[hub] 设备身份复用：新 token 注册复用既有设备 %s（host=%s mac=%s serial=%s）",
					before.ID, p.Hostname, p.MAC, p.SerialNo)
			} else if proposedFree {
				// v0.4.10：指纹 ID 未被占用，直接采纳——台账 ID 与副端硬件绑定恒定。
				dev.ID = p.ProposedID
				log.Printf("[hub] 采纳副端指纹稳定 ID：%s（host=%s mac=%s serial=%s）",
					p.ProposedID, p.Hostname, p.MAC, p.SerialNo)
			}
			// W1-1：软件清单随注册上报（JSON 落库）
			dev.SetSoftware(p.Software)
			saved := h.store.Upsert(dev)
			deviceID = saved.ID
			h.mu.Lock()
			// 同设备重复注册：确定性挤掉旧连接（旧连接读循环退出时因指针不匹配
			// 不会误标离线），避免半开旧连接长期占用 conns 或新旧互踢。
			if old, ok := h.conns[deviceID]; ok && old != conn {
				go old.Close()
			}
			h.conns[deviceID] = conn
			h.mu.Unlock()
			ack, _ := proto.NewEnvelope(proto.TypeRegisterAck, 0, proto.RegisterAckPayload{
				DeviceID: saved.ID, Token: saved.Token, OK: true,
			})
			ackBytes, _ := json.Marshal(ack)
			_ = conn.WriteMessage(ackBytes)
			log.Printf("[hub] agent registered: id=%s %s (%s/%s) mem=%dGB disk=%dGB", saved.ID, saved.Hostname, saved.OS, saved.Arch, saved.MemoryGB, saved.DiskGB)
			// W1-4 + W1-5：资产变更检测与告警
			h.detectAssetChange(before, saved)
			h.detectIPConflict(saved)

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

		case proto.TypeRCReady, proto.TypeRCFrame, proto.TypeRCEvent, proto.TypeRCCapabilities, proto.TypeRCAnswer, proto.TypeRCCandidate, proto.TypeRCPong,
			// W2-1/W2-2：会话内文件传输与聊天的「副端→主端」方向（中枢不解析内容，仅按会话归属转发）
			proto.TypeRCChat, proto.TypeRCFileOffer, proto.TypeRCFileAccept, proto.TypeRCFileChunk, proto.TypeRCFileDone:
			h.relayToViewer(deviceID, raw, false)
		case proto.TypeRCStop:
			h.endSession(deviceID, "副端连接断开")

		default:
		}
	}

	if deviceID != "" {
		// 只有当断开的仍是「当前连接」时才标离线——否则旧连接/被挤掉的连接
		// 退出会把新连接的在线状态误杀（同 StrictMode 竞态一族的教训）。
		h.mu.Lock()
		cur, ok := h.conns[deviceID]
		same := ok && cur == conn
		if same {
			delete(h.conns, deviceID)
		}
		h.mu.Unlock()
		if same {
			h.store.MarkOffline(deviceID)
			h.endSession(deviceID, "副端连接断开")
			log.Printf("[hub] agent offline: %s", deviceID)
		} else {
			log.Printf("[hub] agent connection superseded/closed: %s（设备由现行连接保持在线）", deviceID)
		}
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

// endSession 结束会话并向主端代发 rc_stop。reason 用于审计（W2-5 超时/强制结束/副端断连等）。
func (h *Hub) endSession(deviceID string, reason string) {
	h.mu.Lock()
	s, ok := h.sessions[deviceID]
	delete(h.sessions, deviceID)
	h.mu.Unlock()
	if ok && s.Viewer != nil {
		_ = s.Viewer.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCStop}))
	}
	// W2-5：会话结束统一留痕（此前 rc_stop 无审计，无法追溯谁在何时结束会话）。
	if ok {
		h.audit(s.Operator, "rc_end", deviceID,
			fmt.Sprintf("远控会话结束（%s）会话=%s 时长=%.0fs", orDefault(reason, "正常结束"),
				s.SessionID, time.Since(s.StartedAt).Seconds()), "success")
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
	// 复盘 S-1/V-01（P0）：viewer WS 握手强制鉴权。此前该路由完全无认证，
	// 任意内网主机发 rc_request 即可远控任意在线设备（中枢还会替其 HMAC 代签），
	// REST 面的登录/RBAC/二级审批全部被旁路。
	// 令牌来源：Authorization: Bearer（Tauri/工具链）或 ?token=（浏览器 WS 无法设自定义头）。
	tok := auth.TokenFromHeader(r.Header.Get("Authorization"))
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	claims, err := h.authSvc.VerifyToken(tok)
	if err != nil {
		log.Printf("[hub] viewer ws 拒绝：无效令牌 from %s", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// 与 REST guard 同口径：强制改密期不可远控；无 rc:session 权限（viewer 角色）不可远控。
	if claims.MustChange || !h.authSvc.HasPerm(claims.Role, auth.PermRCSession) {
		log.Printf("[hub] viewer ws 拒绝：角色 %s 无 rc:session 权限 from %s", claims.Role, r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
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
			_, ok := h.conns[p.DeviceID]
			h.mu.Unlock()
			if !ok {
				_ = conn.WriteMessage(mustJSON(proto.Envelope{Type: proto.TypeRCEvent, Payload: mustRaw(proto.RCEventPayload{
					SessionID: p.SessionID, Kind: "error", Message: "设备离线，无法建立远控会话",
				})}))
				continue
			}
			// 会话归属先落位（后续 rc_input/rc_chat/rc_display/rc_file_* 均按此路由）。
			// 敏感设备走审批时会话尚未建立，下方「无活动会话即拒绝转发」的门禁保证
			// 审批放行前任何控制指令都到不了被控端（不因归属落位而绕过二级审批）。
			deviceID = p.DeviceID
			// W2-4 敏感设备二级审批：标记为敏感的设备不直接建会话，先建审批工单，
			// 由具备 rc:approve（仅 admin）的账号放行后才转发 rc_request 给副端。
			// Operator 取自握手鉴权的 claims（复盘 V-10）：不信载荷自报，防伪造操作者污染审计。
			if dev, ok := h.store.Get(p.DeviceID); ok && dev.Sensitive {
				h.requestApproval(conn, &env, p, dev.Hostname, claims.Username)
				continue
			}
			var agentConn *ws.Conn
			h.mu.Lock()
			agentConn, ok = h.conns[p.DeviceID]
			h.mu.Unlock()
			if !ok {
				continue
			}
			h.mu.Lock()
			h.sessions[p.DeviceID] = &RCSession{
				SessionID: p.SessionID, DeviceID: p.DeviceID, Operator: claims.Username,
				Viewer: conn, StartedAt: time.Now().UTC(), LastActive: time.Now().UTC(),
				MaxSec: h.rcMaxSec, IdleSec: h.rcIdleSec,
			}
			h.mu.Unlock()
			deviceID = p.DeviceID
			// 铁律 4：远控会话发起属关键指令，转发前由中枢签名（副端验签后才执行）。
			_ = agentConn.WriteMessage(h.signForAgent(&env, raw))
			h.audit(claims.Username, "rc_start", p.DeviceID, "远控会话开启", "success")
			log.Printf("[hub] rc session start device=%s operator=%s", p.DeviceID, claims.Username)

		case proto.TypeRCInput, proto.TypeRCStop, proto.TypeRCSelect, proto.TypeRCOffer, proto.TypeRCCandidate, proto.TypeRCQos, proto.TypeRCPing,
			// W2-1/W2-2/W2-3：会话内文件传输、聊天、画面控制（黑屏/水印）
			proto.TypeRCChat, proto.TypeRCDisplay,
			proto.TypeRCFileOffer, proto.TypeRCFileAccept, proto.TypeRCFileChunk, proto.TypeRCFileDone:
			// 门禁（W2-4 加固）：除 rc_request（建会话本身）外，任何远控控制/协作消息
			// 都必须存在活动会话才转发。此前无此校验，未建会话（如敏感设备审批中、
			// 会话已结束）的指令仍可能被送到被控端——属可被利用的越权面。
			h.mu.Lock()
			_, hasSession := h.sessions[deviceID]
			h.mu.Unlock()
			if !hasSession {
				log.Printf("[hub] 忽略无活动会话的 %s（device=%s）", env.Type, deviceID)
				continue
			}
			// W2-5：主端任何下发指令都刷新会话活跃时间（空闲超时判定基准）。
			h.touchRCSession(deviceID)
			// W2-3：记录画面状态供管理视图回显（实际生效由副端执行并回告 rc_event）。
			if env.Type == proto.TypeRCDisplay {
				var dp proto.RCDisplayPayload
				if err := env.DecodePayload(&dp); err == nil {
					h.setRCDisplay(deviceID, dp.Blank, dp.Watermark)
					h.mu.Lock()
					s, ok := h.sessions[deviceID]
					h.mu.Unlock()
					if ok {
						h.audit(s.Operator, "rc_display", deviceID,
							fmt.Sprintf("画面控制 黑屏=%v 水印=%v", dp.Blank, dp.Watermark), "success")
					}
				}
			}
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
				h.endSession(deviceID, "主端请求结束")
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
				// P-4 投产阻断：附加短时下载令牌（TTL 10 分钟），副端凭此下载；
				// 端点已强制鉴权，无令牌的旧 URL 将被 401 拒绝。
				body.SoftwareURL = appendRepoToken(body.SoftwareURL, h.repoDownloadToken(repoID, 10*time.Minute))
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
		// V-01 修复：awaitTaskResult 先注册等待通道再发送，消除「先发送后注册」竞态
		// （回执早于注册到达被丢弃 → 超时 → 重发重复执行）。send 失败由 await 回调返回。
		res, err = h.awaitTaskResult(taskID, timeout, func() error { return conn.WriteMessage(cmdBytes) })
	}
	if err != nil {
		h.audit(claims.Username, "command", id, auditDetail, "failed")
		writeErr(w, 2001, err.Error())
		return
	}
	h.audit(claims.Username, "command", id, auditDetail, "success")
	writeJSON(w, res)
}

// ---- W1-2 台账分组元数据：POST /api/v1/devices/meta/{id} ----
//
// v0.4.14（实测报告问题 1/2 全修）：
//  1. 部分更新语义：只覆盖请求体中【出现】的字段，未提交字段保持原值。此前整体覆盖，
//     仅提交 {"sensitive":true} 会把部门/楼层/批次/标签全部清空（W2-4b 回归失败根因），
//     且编辑台账会顺手复位敏感标记。显式提交空串/空数组仍可清空对应字段。
//  2. RBAC 服务端收口：读（GET）仍需 device:view；写（POST/PUT/PATCH）强制 device:cmd
//     （viewer 仅持 device:view，无法再越权写台账——RBAC-1）。此前只靠路由 device:view
//     守卫，viewer 也能写；权限不能只靠前端守卫。
func (h *Hub) handleDeviceUpdate(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/devices/meta/")
	if r.Method == http.MethodGet {
		dev, ok := h.store.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, dev)
		return
	}
	if !h.authSvc.HasPerm(claims.Role, auth.PermDeviceCmd) {
		writeErrStatus(w, http.StatusForbidden, 4003, "修改设备台账需要 device:cmd 权限（viewer 为只读角色）")
		return
	}
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 2001, "invalid JSON body")
		return
	}
	cur, ok := h.store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	meta := store.DeviceMeta{
		Department: cur.Department,
		Floor:      cur.Floor,
		Batch:      cur.Batch,
		Tags:       cur.Tags,
		Sensitive:  &cur.Sensitive,
	}
	changed := []string{}
	if v, ok := body["department"]; ok {
		_ = json.Unmarshal(v, &meta.Department)
		changed = append(changed, "department")
	}
	if v, ok := body["floor"]; ok {
		_ = json.Unmarshal(v, &meta.Floor)
		changed = append(changed, "floor")
	}
	if v, ok := body["batch"]; ok {
		_ = json.Unmarshal(v, &meta.Batch)
		changed = append(changed, "batch")
	}
	if v, ok := body["tags"]; ok {
		_ = json.Unmarshal(v, &meta.Tags)
		changed = append(changed, "tags")
	}
	if v, ok := body["sensitive"]; ok {
		_ = json.Unmarshal(v, meta.Sensitive)
		changed = append(changed, "sensitive")
	}
	dev, ok := h.store.UpdateMeta(id, meta)
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.audit(claims.Username, "device_meta", id,
		fmt.Sprintf("变更字段=%v dept=%s floor=%s batch=%s tags=%v sensitive=%v",
			changed, meta.Department, meta.Floor, meta.Batch, meta.Tags, *meta.Sensitive), "success")
	writeJSON(w, dev)
}

// ---- W1-3 生命周期状态流转：POST /api/v1/devices/lifecycle/{id} ----

func (h *Hub) handleDeviceLifecycle(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	id := idAfterPrefix(r.URL.Path, "/api/v1/devices/lifecycle/")
	var lc store.LifecycleTransition
	_ = json.NewDecoder(r.Body).Decode(&lc)
	cur, ok := h.store.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !validTransition(cur.Lifecycle, lc.State) {
		writeErr(w, 2002, "invalid lifecycle transition: "+cur.Lifecycle+" -> "+lc.State)
		return
	}
	dev, _ := h.store.TransitionLifecycle(id, lc)
	detail := fmt.Sprintf("%s -> %s 领用人=%s 备注=%s", cur.Lifecycle, lc.State, lc.Assignee, lc.Note)
	h.audit(claims.Username, "lifecycle", id, detail, "success")
	// W1-5：生命周期变更产出告警（info 级）
	h.addAlert(store.Alert{
		Type: store.AlertLifecycle, Severity: store.SeverityInfo,
		DeviceID: id, DeviceName: dev.Hostname,
		Message: "生命周期变更", Detail: detail,
	})
	writeJSON(w, dev)
}

// validTransition 生命周期状态机：任意 → retired；in_stock→issued；issued→transferred/returned；
// transferred→returned；returned→in_stock。其余非法。
func validTransition(from, to string) bool {
	switch from {
	case store.LifecycleInStock:
		return to == store.LifecycleIssued || to == store.LifecycleRetired
	case store.LifecycleIssued:
		return to == store.LifecycleTransferred || to == store.LifecycleReturned || to == store.LifecycleRetired
	case store.LifecycleTransferred:
		return to == store.LifecycleReturned || to == store.LifecycleRetired
	case store.LifecycleReturned:
		return to == store.LifecycleInStock || to == store.LifecycleRetired
	case store.LifecycleRetired:
		return false
	default:
		return false
	}
}

// ---- W1-5 实时告警中心 ----

func (h *Hub) handleAlerts(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, map[string]any{
		"alerts": h.store.ListAlerts(limit),
		"unread": h.store.UnreadAlertCount(),
	})
}

func (h *Hub) handleAlertUnread(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	writeJSON(w, map[string]any{"unread": h.store.UnreadAlertCount()})
}

func (h *Hub) handleAlertReadAll(w http.ResponseWriter, _ *http.Request, _ crypto.Claims) {
	h.store.MarkAllAlertsRead()
	writeJSON(w, map[string]any{"ok": true})
}

func (h *Hub) handleAlertRead(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	// 路径形如 /api/v1/alerts/{id}/read → 取首段为 id
	idStr := strings.Split(idAfterPrefix(r.URL.Path, "/api/v1/alerts/"), "/")[0]
	n, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeErr(w, 2002, "invalid alert id")
		return
	}
	h.store.MarkAlertRead(n)
	writeJSON(w, map[string]any{"ok": true})
}

// ---- W1-6 资产报表导出：GET /api/v1/report/export?format=csv|xlsx ----

func (h *Hub) handleReportExport(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	list := h.store.List()
	switch r.URL.Query().Get("format") {
	case "xlsx":
		writeDevicesXLSX(w, list)
	default:
		writeDevicesCSV(w, list)
	}
}

// ---- W1-7 审计日志导出：GET /api/v1/audit/export?format=csv|json ----

func (h *Hub) handleAuditExport(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	events := h.auditor.Query(200000)
	switch r.URL.Query().Get("format") {
	case "json":
		writeAuditJSON(w, events)
	default:
		writeAuditCSV(w, events)
	}
}

// idAfterPrefix 提取路径中指定前缀之后的首段（设备 ID 等）。
// envInt 读取整型环境变量，缺失或非法时返回默认值（配置容错，不因坏值启动失败）。
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func idAfterPrefix(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	return strings.Trim(rest, "/")
}

// awaitTaskResult 注册 taskID 等待通道并阻塞至回执或超时。
//
// 复盘 V-01 修复（v0.2.7 起）：此前调用方「先发送再注册」，副端回执可能在注册前
// 到达——hub 的结果处理器（TypeResult 分支）查 pending 无果即丢弃回执，导致
// awaitTaskResult 永远超时 → HTTP 返回 timeout → 客户端/控制台重发 → 副端重复执行
// （实机「指令失败重发重复执行」根因）。现改为「先注册通道，再调用 send 回调发送」，
// 保证发送与注册之间无窗口；send 失败则注销通道并返回错误（副端未收到，无回执可丢）。
func (h *Hub) awaitTaskResult(taskID string, timeout time.Duration, send func() error) (proto.ResultPayload, error) {
	ch := make(chan proto.ResultPayload, 1)
	h.mu.Lock()
	h.pending[taskID] = ch
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, taskID)
		h.mu.Unlock()
	}()
	if err := send(); err != nil {
		return proto.ResultPayload{}, err
	}
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
	id = strings.Trim(id, "/")
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		http.NotFound(w, r)
		return
	}
	// P-4 投产阻断：下载鉴权——会话令牌（主端/控制台）或短时下载令牌（副端分发）。
	// 此前端点无鉴权（hub.go 注释自认"演示放开"），内网任意主机可拉全部安装包。
	// 注意：本端点为二进制下载，鉴权失败返回**真实 HTTP 401**（而非 writeErr 的 200+code 约定），
	// 否则副端下载器（仅判 StatusCode!=200，见 cmd/agent/swdist.go）会把错误 JSON 当安装包落盘。
	tok := r.URL.Query().Get("token")
	st := r.URL.Query().Get("st")
	switch {
	case tok != "":
		if _, err := h.authSvc.VerifyToken(tok); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	case st != "":
		if !h.verifyRepoDownloadToken(id, st) {
			http.Error(w, "invalid download token", http.StatusUnauthorized)
			return
		}
	default:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
	name, ok := consolePage(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	serveConsole(w, r, name)
}

// consolePage 把控制台 URL 路径映射到静态资源名（含 auth.js）。
func consolePage(path string) (string, bool) {
	switch path {
	case "/", "/index.html":
		return "index.html", true
	case "/login.html":
		return "login.html", true
	case "/change-password.html":
		return "change-password.html", true
	case "/audit.html":
		return "audit.html", true
	case "/rc.html":
		return "rc.html", true
	case "/software.html":
		return "software.html", true
	case "/users.html":
		return "users.html", true
	case "/auth.js":
		return "auth.js", true
	default:
		return "", false
	}
}

// serveConsole 优先读运行目录 console/<name>（开发热更），否则回退到内嵌资源
// （生产自包含）。此前发布包漏打 console/ 且中枢依赖相对路径外部文件，生产访问 / 404。
func serveConsole(w http.ResponseWriter, r *http.Request, name string) {
	if b, err := os.ReadFile(filepath.Join("console", name)); err == nil {
		w.Header().Set("Content-Type", consoleContentType(name))
		w.Write(b)
		return
	}
	if b, err := consolefs.FS.ReadFile(name); err == nil {
		w.Header().Set("Content-Type", consoleContentType(name))
		w.Write(b)
		return
	}
	http.NotFound(w, r)
}

func consoleContentType(name string) string {
	if strings.HasSuffix(name, ".js") {
		return "application/javascript; charset=utf-8"
	}
	return "text/html; charset=utf-8"
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

// appendRepoToken 给仓库下载 URL 附加 st 短时令牌（P-4）。幂等：先去掉既有 st 再追加，
// 保证延迟调度任务在**下发时**刷新令牌（TTL 10 分钟，早生成会过期）。
func appendRepoToken(rawURL, st string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		return rawURL + sep + "st=" + st
	}
	q := u.Query()
	q.Del("st")
	q.Set("st", st)
	u.RawQuery = q.Encode()
	return u.String()
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

// writeErrStatus 带真实 HTTP 状态码的错误响应：包体仍为 {code,message} 约定，
// 供网关/探活/外部脚本按 HTTP 语义判定（v0.4.5 起 guard 鉴权失败用真实 401）。
func writeErrStatus(w http.ResponseWriter, httpStatus, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpStatus)
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
