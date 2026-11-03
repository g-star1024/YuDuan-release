// 波次 3：软件分发增强 + 中枢高可用（PRD 5.3 D2/D3/D5/D6、PRD 5.10 E4）。
//
// 覆盖范围：
//   - W3-1 静默安装参数模板库（按 platform/pkg_type 索引 + custom_args 覆盖）
//   - W3-2 分发任务（目标展开、计划时间、force/optional、逐设备执行记录）
//   - W3-3 版本比对差异升级 + 旧版卸载（仅对版本落后设备下发）
//   - W3-4 失败自动重试（固定/指数退避，超限永久失败并告警）
//   - W3-5 中枢高可用（主备角色 + 租约续期 + 心跳超时自动选主）
//
// 边界（铁律）：中枢仍是唯一控制平面与唯一签发方——下发指令一律经 h.sign 签名，
// 副端只与中枢口径一致；软件分发不落任何个人信息，执行记录只留包名/版本/退出码/输出摘要。
package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/proto"
	"yuduan/internal/store"
)

// ==================== 领域模型 ====================

// W3Template 静默安装参数模板（W3-1），按 (platform, pkg_type) 唯一索引。
type W3Template struct {
	Platform  string    `json:"platform"`             // windows / macos / linux
	PkgType   string    `json:"pkg_type"`             // msi / exe / dmg / pkg / deb / rpm / zip
	Args      string    `json:"args"`                 // 默认静默参数（<pkg> 为安装包路径占位符）
	Desc      string    `json:"desc,omitempty"`       // 说明（主端展示）
	Builtin   bool      `json:"builtin"`              // 是否内置默认模板
	UpdatedAt time.Time `json:"updated_at"`           // 最近更新时间
	UpdatedBy string    `json:"updated_by,omitempty"` // 最近更新人
}

// W3TargetGroup 按台账分组维度圈选目标（复用 W1-2 的 department/floor/batch/tags）。
type W3TargetGroup struct {
	Department string `json:"department,omitempty"`
	Floor      string `json:"floor,omitempty"`
	Batch      string `json:"batch,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

// W3Targets 分发目标：设备列表 / 分组 / 全员（可组合，取并集）。
type W3Targets struct {
	DeviceIDs []string       `json:"device_ids,omitempty"`
	Group     *W3TargetGroup `json:"group,omitempty"`
	All       bool           `json:"all,omitempty"`
}

// W3Record 分发任务在单台设备上的执行记录（W3-2/W3-3/W3-4）。
type W3Record struct {
	ID             string     `json:"id"`
	TaskID         string     `json:"task_id"`
	DeviceID       string     `json:"device_id"`
	DeviceName     string     `json:"device_name,omitempty"`
	State          string     `json:"state"`
	Attempt        int        `json:"attempt"`
	ExitCode       int        `json:"exit_code"`
	Output         string     `json:"output,omitempty"`
	Reason         string     `json:"reason,omitempty"`          // skipped/失败原因
	CurrentVersion string     `json:"current_version,omitempty"` // W3-3 比对到的设备当前版本
	Uninstalled    bool       `json:"uninstalled,omitempty"`     // W3-3 是否已卸载旧版
	Confirmed      bool       `json:"confirmed,omitempty"`       // optional：终端用户已确认（重发时副端据此直装）
	NextRetryAt    *time.Time `json:"next_retry_at,omitempty"`   // W3-4 下次重试时间
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// W3DistTask 分发任务（W3-2）。Records 为逐设备执行记录（详情接口返回）。
type W3DistTask struct {
	ID          string `json:"id"`
	RepoID      string `json:"repo_id,omitempty"`
	SoftwareURL string `json:"software_url,omitempty"`
	// Sha256 外部下载地址的强制完整性摘要（复盘 S-8/V-08）。
	// 仓库包由中枢从软件清单自动填充；外部 URL 无摘要时副端自 v0.4.3 起拒绝安装，
	// 故此处需允许管理员在创建任务时显式给出摘要，否则外部 URL 分发无法合规下发。
	Sha256           string      `json:"sha256,omitempty"`
	PkgName          string      `json:"pkg_name"`
	Version          string      `json:"version,omitempty"`
	Platform         string      `json:"platform,omitempty"`
	PkgType          string      `json:"pkg_type,omitempty"`
	CustomArgs       string      `json:"custom_args,omitempty"`
	TargetVersion    string      `json:"target_version,omitempty"`
	UninstallOld     bool        `json:"uninstall_old,omitempty"`
	Targets          W3Targets   `json:"targets"`
	ScheduleAt       *time.Time  `json:"schedule_at,omitempty"`
	Mode             string      `json:"mode"`
	MaxRetry         int         `json:"max_retry"`
	RetryIntervalSec int         `json:"retry_interval_sec"`
	RetryBackoff     string      `json:"retry_backoff,omitempty"` // fixed（默认）/ exponential
	State            string      `json:"state"`
	CreatedBy        string      `json:"created_by"`
	CreatedAt        time.Time   `json:"created_at"`
	StartedAt        *time.Time  `json:"started_at,omitempty"`
	FinishedAt       *time.Time  `json:"finished_at,omitempty"`
	Total            int         `json:"total"`
	Success          int         `json:"success"`
	Failed           int         `json:"failed"`
	Skipped          int         `json:"skipped"`
	Records          []*W3Record `json:"records,omitempty"`

	running bool `json:"-"` // 是否有派发协程在运行（非持久化）
}

// W3Node 中枢高可用节点（W3-5）。
type W3Node struct {
	HubID      string    `json:"hub_id"`
	Addr       string    `json:"addr"`
	Role       string    `json:"role"` // leader / follower
	LastSeen   time.Time `json:"last_seen"`
	LeaseUntil time.Time `json:"lease_until"`
	Online     bool      `json:"online"`
}

// ---- 状态常量 ----

// 任务状态。
const (
	w3TaskPending   = "pending" // 已创建（含计划任务待到点）
	w3TaskRunning   = "running" // 派发中
	w3TaskDone      = "done"    // 全部成功/跳过
	w3TaskPartial   = "partially_done"
	w3TaskFailed    = "failed"
	w3TaskCancelled = "cancelled"
)

// 设备执行记录状态。
const (
	w3RecPending      = "pending"
	w3RecDispatching  = "dispatching"
	w3RecRetryWaiting = "retry_waiting"
	w3RecSuccess      = "success"
	w3RecFailed       = "failed"
	w3RecPermFailed   = "permanently_failed"
	w3RecSkipped      = "skipped"
	w3RecAwaitConfirm = "awaiting_confirm"
	w3RecCancelled    = "cancelled"
)

// HA 角色。
const (
	w3RoleLeader   = "leader"
	w3RoleFollower = "follower"
)

// W3-4 产生的告警类型（复用 W1-5 告警中心）。
const w3AlertDistFailed = "swdist_failed"

// ==================== 波次状态容器 ====================

type w3Store struct {
	templates map[string]*W3Template
	tasks     map[string]*W3DistTask
	nodes     map[string]*W3Node
	seq       int64
	started   bool
}

// w3States 按 *Hub 隔离波次状态（单测会构造多个 Hub，避免互相污染）。
var w3States sync.Map // *Hub -> *w3Store

func (h *Hub) w3() *w3Store {
	if v, ok := w3States.Load(h); ok {
		return v.(*w3Store)
	}
	st := &w3Store{
		templates: map[string]*W3Template{},
		tasks:     map[string]*W3DistTask{},
		nodes:     map[string]*W3Node{},
	}
	for _, t := range w3DefaultTemplates() {
		cp := *t
		st.templates[w3TplKey(cp.Platform, cp.PkgType)] = &cp
	}
	actual, _ := w3States.LoadOrStore(h, st)
	return actual.(*w3Store)
}

func w3TplKey(platform, pkgType string) string {
	return strings.ToLower(platform) + "|" + strings.ToLower(pkgType)
}

// w3DefaultTemplates 内置默认静默参数（首次启动注入，可被主端覆盖）。
func w3DefaultTemplates() []*W3Template {
	now := time.Now().UTC()
	mk := func(platform, pkgType, args, desc string) *W3Template {
		return &W3Template{Platform: platform, PkgType: pkgType, Args: args, Desc: desc, Builtin: true, UpdatedAt: now, UpdatedBy: "system"}
	}
	return []*W3Template{
		mk("windows", proto.PkgTypeMSI, "/qn /norestart", "Windows Installer 静默安装，禁止自动重启"),
		mk("windows", proto.PkgTypeEXE, "/VERYSILENT /NORESTART", "InnoSetup 静默安装；NSIS 安装包请改用 /S"),
		mk("windows", proto.PkgTypeZIP, "", "解压部署包（无安装参数）"),
		mk("macos", proto.PkgTypeDMG, "hdiutil attach <pkg> && cp -R /Volumes/*/*.app /Applications && hdiutil detach", "挂载 dmg 后拷贝 .app 到 /Applications"),
		mk("macos", proto.PkgTypePKG, "installer -pkg <pkg> -target /", "macOS 安装包静默安装到根卷"),
		mk("macos", proto.PkgTypeZIP, "", "解压部署包（无安装参数）"),
		mk("linux", proto.PkgTypeDEB, "dpkg -i <pkg>", "Debian 系静默安装"),
		mk("linux", proto.PkgTypeRPM, "rpm -i <pkg>", "RPM 系静默安装"),
		mk("linux", proto.PkgTypeZIP, "", "解压部署包（无安装参数）"),
	}
}

// ==================== 路由挂载 ====================

func wave3Routes(mux *http.ServeMux, h *Hub) {
	// W3-1 静默安装参数模板库
	mux.HandleFunc("/api/v1/swdist/templates", h.guard(auth.PermSoftwareMgmt, h.handleW3Templates))
	mux.HandleFunc("/api/v1/swdist/templates/", h.guard(auth.PermSoftwareMgmt, h.handleW3TemplateItem))
	mux.HandleFunc("/api/v1/swdist/templates/resolve", h.guard(auth.PermSoftwareMgmt, h.handleW3TemplateResolve))
	// W3-2/W3-3/W3-4 分发任务
	mux.HandleFunc("/api/v1/swdist/tasks", h.guard(auth.PermSoftwareMgmt, h.handleW3Tasks))
	mux.HandleFunc("/api/v1/swdist/tasks/", h.guard(auth.PermSoftwareMgmt, h.handleW3TaskItem))
	// W3-5 中枢高可用
	mux.HandleFunc("/api/v1/ha/nodes", h.guard(auth.PermUserManage, h.handleW3HANodes))
	mux.HandleFunc("/api/v1/ha/heartbeat", h.guard(auth.PermUserManage, h.handleW3HAHeartbeat))
	mux.HandleFunc("/api/v1/ha/claim", h.guard(auth.PermUserManage, h.handleW3HAClaim))
	h.w3Start()
}

// ==================== W3-1 模板库 ====================

func (h *Hub) handleW3Templates(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	switch r.Method {
	case http.MethodGet:
		h.mu.Lock()
		out := make([]*W3Template, 0, len(h.w3().templates))
		for _, t := range h.w3().templates {
			out = append(out, t)
		}
		h.mu.Unlock()
		sort.Slice(out, func(i, j int) bool {
			if out[i].Platform != out[j].Platform {
				return out[i].Platform < out[j].Platform
			}
			return out[i].PkgType < out[j].PkgType
		})
		writeJSON(w, map[string]any{"code": 0, "total": len(out), "templates": out})
	case http.MethodPost:
		var body struct {
			Platform string `json:"platform"`
			PkgType  string `json:"pkg_type"`
			Args     string `json:"args"`
			Desc     string `json:"desc"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 3001, "bad request: "+err.Error())
			return
		}
		tpl, err := h.w3UpsertTemplate(body.Platform, body.PkgType, body.Args, body.Desc, false, claims.Username)
		if err != nil {
			writeErr(w, 3002, err.Error())
			return
		}
		writeJSON(w, map[string]any{"code": 0, "template": tpl})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleW3TemplateItem 处理 /api/v1/swdist/templates/{platform}/{pkg_type} 与 /reset。
func (h *Hub) handleW3TemplateItem(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	rest := strings.Trim(idAfterPrefix(r.URL.Path, "/api/v1/swdist/templates/"), "/")
	if rest == "reset" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.w3ResetTemplates(claims.Username)
		h.mu.Lock()
		n := len(h.w3().templates)
		h.mu.Unlock()
		writeJSON(w, map[string]any{"code": 0, "ok": true, "total": n})
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		writeErr(w, 3003, "路径应为 /api/v1/swdist/templates/{platform}/{pkg_type}")
		return
	}
	platform, pkgType := parts[0], parts[1]
	switch r.Method {
	case http.MethodGet:
		h.mu.Lock()
		t, ok := h.w3().templates[w3TplKey(platform, pkgType)]
		h.mu.Unlock()
		if !ok {
			writeErr(w, 3004, "模板不存在: "+platform+"/"+pkgType)
			return
		}
		writeJSON(w, map[string]any{"code": 0, "template": t})
	case http.MethodPut, http.MethodPost:
		var body struct {
			Args string `json:"args"`
			Desc string `json:"desc"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		tpl, err := h.w3UpsertTemplate(platform, pkgType, body.Args, body.Desc, false, claims.Username)
		if err != nil {
			writeErr(w, 3002, err.Error())
			return
		}
		writeJSON(w, map[string]any{"code": 0, "template": tpl})
	case http.MethodDelete:
		h.mu.Lock()
		key := w3TplKey(platform, pkgType)
		_, ok := h.w3().templates[key]
		if ok {
			delete(h.w3().templates, key)
		}
		h.mu.Unlock()
		if !ok {
			writeErr(w, 3004, "模板不存在: "+platform+"/"+pkgType)
			return
		}
		if pg := h.w3PG(); pg != nil {
			_ = store.Wave3DeleteTemplate(pg, platform, pkgType)
		}
		h.audit(claims.Username, "swdist_template_delete", platform+"/"+pkgType, "删除静默安装参数模板", "success")
		writeJSON(w, map[string]any{"code": 0, "ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleW3TemplateResolve 预览「模板参数 + custom_args 覆盖」的最终命令行。
// GET /api/v1/swdist/templates/resolve?platform=&pkg_type=&custom_args=
func (h *Hub) handleW3TemplateResolve(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	q := r.URL.Query()
	platform := q.Get("platform")
	pkgType := q.Get("pkg_type")
	custom := q.Get("custom_args")
	h.mu.Lock()
	t, ok := h.w3().templates[w3TplKey(platform, pkgType)]
	h.mu.Unlock()
	tplArgs := ""
	if ok {
		tplArgs = t.Args
	}
	resolved := tplArgs
	if custom != "" {
		resolved = custom
	}
	writeJSON(w, map[string]any{
		"code": 0, "platform": platform, "pkg_type": pkgType,
		"template_args": tplArgs, "custom_args": custom, "resolved_args": resolved,
		"found": ok,
	})
}

func (h *Hub) w3UpsertTemplate(platform, pkgType, args, desc string, builtin bool, actor string) (*W3Template, error) {
	platform = strings.ToLower(strings.TrimSpace(platform))
	pkgType = strings.ToLower(strings.TrimSpace(pkgType))
	if platform == "" || pkgType == "" {
		return nil, jsonError("platform 与 pkg_type 必填")
	}
	if !w3ValidPkgType(pkgType) {
		return nil, jsonError("不支持的包类型: " + pkgType + "（应为 " + strings.Join(proto.PkgTypes(), "/") + "）")
	}
	now := time.Now().UTC()
	h.mu.Lock()
	t := &W3Template{
		Platform: platform, PkgType: pkgType, Args: args, Desc: desc,
		Builtin: builtin, UpdatedAt: now, UpdatedBy: actor,
	}
	h.w3().templates[w3TplKey(platform, pkgType)] = t
	h.mu.Unlock()
	if pg := h.w3PG(); pg != nil {
		_ = store.Wave3UpsertTemplate(pg, store.Wave3TemplateRow{
			Platform: platform, PkgType: pkgType, Args: args, Desc: desc,
			Builtin: builtin, UpdatedAt: now, UpdatedBy: actor,
		})
	}
	h.audit(actor, "swdist_template_upsert", platform+"/"+pkgType, "args="+args, "success")
	return t, nil
}

func (h *Hub) w3ResetTemplates(actor string) {
	now := time.Now().UTC()
	h.mu.Lock()
	st := h.w3()
	st.templates = map[string]*W3Template{}
	for _, t := range w3DefaultTemplates() {
		cp := *t
		cp.UpdatedAt = now
		st.templates[w3TplKey(cp.Platform, cp.PkgType)] = &cp
	}
	h.mu.Unlock()
	if pg := h.w3PG(); pg != nil {
		for _, t := range w3DefaultTemplates() {
			_ = store.Wave3UpsertTemplate(pg, store.Wave3TemplateRow{
				Platform: t.Platform, PkgType: t.PkgType, Args: t.Args, Desc: t.Desc,
				Builtin: true, UpdatedAt: now, UpdatedBy: actor,
			})
		}
	}
	h.audit(actor, "swdist_template_reset", "templates", "恢复内置默认静默安装参数模板", "success")
}

func w3ValidPkgType(t string) bool {
	for _, v := range proto.PkgTypes() {
		if v == t {
			return true
		}
	}
	return false
}

// w3ResolveArgs 解析最终静默参数：custom_args 非空时覆盖模板默认值。
func (h *Hub) w3ResolveArgs(platform, pkgType, customArgs string) string {
	h.mu.Lock()
	t, ok := h.w3().templates[w3TplKey(platform, pkgType)]
	h.mu.Unlock()
	if customArgs != "" {
		return customArgs
	}
	if ok {
		return t.Args
	}
	return ""
}

// ==================== W3-2 分发任务 API ====================

func (h *Hub) handleW3Tasks(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	switch r.Method {
	case http.MethodGet:
		h.mu.Lock()
		out := make([]*W3DistTask, 0, len(h.w3().tasks))
		for _, t := range h.w3().tasks {
			out = append(out, w3TaskView(t, false))
		}
		h.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
		writeJSON(w, map[string]any{"code": 0, "total": len(out), "tasks": out})
	case http.MethodPost:
		var body struct {
			RepoID           string    `json:"repo_id"`
			SoftwareURL      string    `json:"software_url"`
			Sha256           string    `json:"sha256"`
			PkgName          string    `json:"pkg_name"`
			Version          string    `json:"version"`
			Platform         string    `json:"platform"`
			PkgType          string    `json:"pkg_type"`
			CustomArgs       string    `json:"custom_args"`
			TargetVersion    string    `json:"target_version"`
			UninstallOld     bool      `json:"uninstall_old"`
			Targets          W3Targets `json:"targets"`
			ScheduleAt       string    `json:"schedule_at"`
			Mode             string    `json:"mode"`
			MaxRetry         int       `json:"max_retry"`
			RetryIntervalSec int       `json:"retry_interval_sec"`
			RetryBackoff     string    `json:"retry_backoff"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 3010, "bad request: "+err.Error())
			return
		}
		body.PkgName = strings.TrimSpace(body.PkgName)
		if body.PkgName == "" {
			writeErr(w, 3011, "pkg_name 必填")
			return
		}
		if !body.Targets.All && len(body.Targets.DeviceIDs) == 0 && body.Targets.Group == nil {
			writeErr(w, 3012, "targets 需指定 device_ids / group / all 之一")
			return
		}
		if body.Mode == "" {
			body.Mode = proto.DistModeForced
		}
		if body.Mode != proto.DistModeForced && body.Mode != proto.DistModeOptional {
			writeErr(w, 3013, "mode 应为 forced 或 optional")
			return
		}
		if body.MaxRetry <= 0 {
			body.MaxRetry = w3DefaultMaxRetry()
		}
		if body.RetryIntervalSec <= 0 {
			body.RetryIntervalSec = w3DefaultRetryInterval()
		}
		if body.RetryBackoff == "" {
			body.RetryBackoff = "fixed"
		}
		var sched *time.Time
		if body.ScheduleAt != "" {
			if ts, err := w3ParseTime(body.ScheduleAt); err == nil {
				sched = &ts
			} else {
				writeErr(w, 3014, "schedule_at 解析失败（需 RFC3339 或秒级时间戳）: "+body.ScheduleAt)
				return
			}
		}
		// 仓库包：补全校验参数、平台与下载地址
		if body.RepoID != "" {
			h.mu.Lock()
			it, ok := h.software[body.RepoID]
			h.mu.Unlock()
			if !ok {
				writeErr(w, 3015, "仓库中无该软件包: "+body.RepoID)
				return
			}
			if body.Version == "" {
				body.Version = it.Version
			}
			if body.Platform == "" || body.Platform == "any" {
				body.Platform = it.Platform
			}
			if body.SoftwareURL == "" {
				body.SoftwareURL = h.w3RepoURL(body.RepoID)
			}
		}
		if body.PkgType == "" {
			body.PkgType = w3ExtToPkgType(body.PkgName)
		}
		if body.Platform == "" {
			body.Platform = "any"
		}

		task := &W3DistTask{
			ID:               h.w3NewID("dt"),
			RepoID:           body.RepoID,
			SoftwareURL:      body.SoftwareURL,
			Sha256:           strings.TrimSpace(body.Sha256),
			PkgName:          body.PkgName,
			Version:          body.Version,
			Platform:         body.Platform,
			PkgType:          body.PkgType,
			CustomArgs:       body.CustomArgs,
			TargetVersion:    body.TargetVersion,
			UninstallOld:     body.UninstallOld,
			Targets:          body.Targets,
			ScheduleAt:       sched,
			Mode:             body.Mode,
			MaxRetry:         body.MaxRetry,
			RetryIntervalSec: body.RetryIntervalSec,
			RetryBackoff:     body.RetryBackoff,
			State:            w3TaskPending,
			CreatedBy:        claims.Username,
			CreatedAt:        time.Now().UTC(),
		}
		// 目标展开（复用 W1-2 台账分组字段）
		for _, d := range h.w3ExpandTargets(task.Targets) {
			task.Records = append(task.Records, &W3Record{
				ID:         h.w3NewID("dr"),
				TaskID:     task.ID,
				DeviceID:   d.ID,
				DeviceName: d.Hostname,
				State:      w3RecPending,
				CreatedAt:  task.CreatedAt,
				UpdatedAt:  task.CreatedAt,
			})
		}
		task.Total = len(task.Records)
		h.mu.Lock()
		h.w3().tasks[task.ID] = task
		h.mu.Unlock()
		h.w3PersistTask(task.ID)
		h.audit(claims.Username, "swdist_task_create", task.ID,
			fmt.Sprintf("pkg=%s v%s 目标=%d 台 mode=%s schedule=%v uninstall_old=%v target_version=%s",
				task.PkgName, orDefault(task.Version, "-"), task.Total, task.Mode,
				task.ScheduleAt != nil, task.UninstallOld, orDefault(task.TargetVersion, "-")), "success")
		log.Printf("[hub] 分发任务创建 id=%s pkg=%s 目标=%d mode=%s retry=%d/%ds",
			task.ID, task.PkgName, task.Total, task.Mode, task.MaxRetry, task.RetryIntervalSec)
		writeJSON(w, map[string]any{"code": 0, "task": w3TaskView(task, true)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleW3TaskItem 处理 /api/v1/swdist/tasks/{id}[/cancel|/records|/records/{rid}/confirm]。
func (h *Hub) handleW3TaskItem(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	rest := strings.Trim(idAfterPrefix(r.URL.Path, "/api/v1/swdist/tasks/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, 3020, "缺少任务 ID")
		return
	}
	taskID := parts[0]
	// {id}/records/{rid}/confirm —— 可选分发的终端用户确认（W3-2）
	if len(parts) == 4 && parts[1] == "records" && parts[3] == "confirm" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Confirm bool `json:"confirm"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ok, msg := h.w3ConfirmRecord(taskID, parts[2], body.Confirm)
		if !ok {
			writeErr(w, 3021, msg)
			return
		}
		h.audit(claims.Username, "swdist_record_confirm", taskID+"/"+parts[2],
			fmt.Sprintf("终端用户确认=%v", body.Confirm), "success")
		writeJSON(w, map[string]any{"code": 0, "ok": true})
		return
	}
	if len(parts) >= 2 {
		switch parts[1] {
		case "cancel":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !h.w3CancelTask(taskID) {
				writeErr(w, 3022, "任务不存在或已结束: "+taskID)
				return
			}
			h.audit(claims.Username, "swdist_task_cancel", taskID, "取消分发任务", "success")
			writeJSON(w, map[string]any{"code": 0, "ok": true})
			return
		case "records":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h.mu.Lock()
			t, ok := h.w3().tasks[taskID]
			recs := []*W3Record{}
			if ok {
				recs = append(recs, t.Records...)
			}
			h.mu.Unlock()
			if !ok {
				writeErr(w, 3023, "任务不存在: "+taskID)
				return
			}
			writeJSON(w, map[string]any{"code": 0, "total": len(recs), "records": recs})
			return
		}
	}
	if len(parts) != 1 {
		writeErr(w, 3024, "未知子路径: "+rest)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	t, ok := h.w3().tasks[taskID]
	h.mu.Unlock()
	if !ok {
		writeErr(w, 3023, "任务不存在: "+taskID)
		return
	}
	writeJSON(w, map[string]any{"code": 0, "task": w3TaskView(t, true)})
}

// ==================== W3-2 目标展开与派发 ====================

func (h *Hub) w3ExpandTargets(t W3Targets) []store.Device {
	devs := h.store.List()
	if t.All {
		return devs
	}
	seen := map[string]bool{}
	var out []store.Device
	for _, d := range devs {
		for _, id := range t.DeviceIDs {
			if id == d.ID && !seen[id] {
				seen[id] = true
				out = append(out, d)
			}
		}
	}
	if t.Group == nil {
		return out
	}
	g := t.Group
	for _, d := range devs {
		if seen[d.ID] {
			continue
		}
		if g.Department != "" && d.Department != g.Department {
			continue
		}
		if g.Floor != "" && d.Floor != g.Floor {
			continue
		}
		if g.Batch != "" && d.Batch != g.Batch {
			continue
		}
		if g.Tag != "" && !w3HasTag(d.TagList(), g.Tag) {
			continue
		}
		seen[d.ID] = true
		out = append(out, d)
	}
	return out
}

func w3HasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// w3RunTask 派发协程：循环领取 pending 记录并下发，直到无待发记录。
func (h *Hub) w3RunTask(id string) {
	defer func() {
		h.mu.Lock()
		if t, ok := h.w3().tasks[id]; ok {
			t.running = false
		}
		h.mu.Unlock()
	}()
	for {
		h.mu.Lock()
		t, ok := h.w3().tasks[id]
		if !ok || t.State == w3TaskCancelled {
			h.mu.Unlock()
			return
		}
		var batch []*W3Record
		for _, r := range t.Records {
			if r.State == w3RecPending {
				r.State = w3RecDispatching
				r.UpdatedAt = time.Now().UTC()
				batch = append(batch, r)
			}
		}
		h.mu.Unlock()
		if len(batch) == 0 {
			break
		}
		sem := make(chan struct{}, 8) // 并发上限，避免大批量任务打爆控制面
		var wg sync.WaitGroup
		for _, r := range batch {
			wg.Add(1)
			sem <- struct{}{}
			go func(rec *W3Record) {
				defer wg.Done()
				defer func() { <-sem }()
				h.w3DispatchRecord(id, rec.ID)
			}(r)
		}
		wg.Wait()
	}
	h.w3FinishTask(id)
}

// w3DispatchRecord 向单台设备下发一次安装（W3-2 主流程 + W3-3 版本比对/卸载旧版）。
func (h *Hub) w3DispatchRecord(taskID, recID string) {
	h.mu.Lock()
	t, ok := h.w3().tasks[taskID]
	if !ok {
		h.mu.Unlock()
		return
	}
	rec := w3FindRecord(t, recID)
	if rec == nil {
		h.mu.Unlock()
		return
	}
	if t.State == w3TaskCancelled || rec.State == w3RecCancelled {
		rec.State = w3RecCancelled
		rec.UpdatedAt = time.Now().UTC()
		h.mu.Unlock()
		h.w3PersistRecord(taskID, recID)
		return
	}
	rec.Attempt++
	rec.State = w3RecDispatching
	rec.UpdatedAt = time.Now().UTC()
	snapshot := *t
	snapshot.Records = nil
	dev, _ := h.store.Get(rec.DeviceID)
	h.mu.Unlock()

	// ---- W3-3 版本比对：仅对版本落后的设备下发 ----
	cur, installed := w3FindSoftware(dev, snapshot.PkgName)
	h.w3SetCurrentVersion(taskID, recID, cur)
	if snapshot.TargetVersion != "" && installed {
		cmp := proto.CompareVersion(cur, snapshot.TargetVersion)
		if cmp >= 0 {
			reason := fmt.Sprintf("已是最新版本（当前 %s ≥ 目标 %s），跳过", cur, snapshot.TargetVersion)
			if cmp > 0 {
				reason = fmt.Sprintf("当前版本高于目标（当前 %s > 目标 %s），跳过", cur, snapshot.TargetVersion)
			}
			h.w3RecordSkip(taskID, recID, reason)
			return
		}
	}

	if h.bus == nil && !h.deviceOnlineLocal(rec.DeviceID) {
		h.w3RecordFail(taskID, recID, "设备离线，无法下发安装指令", -1)
		return
	}

	// ---- W3-3 旧版卸载：先卸载再安装 ----
	if snapshot.UninstallOld && installed {
		ures, uerr := h.w3SendInstall(rec, snapshot, proto.ActionSwUninstall, proto.SwDistDetail{
			PkgType:        snapshot.PkgType,
			Package:        snapshot.PkgName,
			CurrentVersion: cur,
			TargetVersion:  snapshot.TargetVersion,
		})
		if uerr != nil || ures.State != "success" {
			out := "卸载旧版失败"
			if uerr != nil {
				out += ": " + uerr.Error()
			} else {
				out += ": " + ures.OutputLog
			}
			h.w3RecordFail(taskID, recID, out, ures.ExitCode)
			return
		}
		h.mu.Lock()
		if r := w3FindRecord(h.w3().tasks[taskID], recID); r != nil {
			r.Uninstalled = true
			r.UpdatedAt = time.Now().UTC()
		}
		h.mu.Unlock()
	}

	silent := h.w3ResolveArgs(snapshot.Platform, snapshot.PkgType, snapshot.CustomArgs)
	res, err := h.w3SendInstall(rec, snapshot, proto.ActionSwDist, proto.SwDistDetail{
		PkgType:        snapshot.PkgType,
		CustomArgs:     snapshot.CustomArgs,
		SilentArgs:     silent,
		Mode:           snapshot.Mode,
		Confirmed:      rec.Confirmed,
		TargetVersion:  snapshot.TargetVersion,
		UninstallOld:   snapshot.UninstallOld,
		CurrentVersion: cur,
	})
	if err != nil {
		h.w3RecordFail(taskID, recID, "下发失败: "+err.Error(), -1)
		return
	}
	switch res.State {
	case proto.ResultConfirmRequired:
		h.w3RecordAwaitConfirm(taskID, recID, res.OutputLog)
	case "success":
		h.w3RecordDone(taskID, recID, res.OutputLog, res.ExitCode)
	default:
		h.w3RecordFail(taskID, recID, res.OutputLog, res.ExitCode)
	}
}

// w3SendInstall 构造并下发一条分发类指令（经中枢签名；多中枢场景走总线）。
func (h *Hub) w3SendInstall(rec *W3Record, t W3DistTask, action string, d proto.SwDistDetail) (proto.ResultPayload, error) {
	c := h.w3BuildInstallCommand(rec, t, action, d)
	env, err := proto.NewEnvelope(proto.TypeCommand, 0, c)
	if err != nil {
		return proto.ResultPayload{}, err
	}
	h.sign(&env) // 铁律 4：关键指令必须经中枢签名
	raw, _ := json.Marshal(env)
	timeout := time.Duration(envInt("YUDUAN_SWDIST_TIMEOUT_SEC", 120)) * time.Second
	if h.bus != nil {
		return h.bus.Dispatch(rec.DeviceID, c.TaskID, raw, timeout)
	}
	if !h.deviceOnlineLocal(rec.DeviceID) {
		return proto.ResultPayload{}, fmt.Errorf("device offline")
	}
	// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
	return h.awaitTaskResult(c.TaskID, timeout, func() error {
		if !h.sendToDevice(rec.DeviceID, raw) {
			return fmt.Errorf("send failed")
		}
		return nil
	})
}

// ==================== W3-2/W3-4 记录状态流转 ====================

func w3FindRecord(t *W3DistTask, recID string) *W3Record {
	if t == nil {
		return nil
	}
	for _, r := range t.Records {
		if r.ID == recID {
			return r
		}
	}
	return nil
}

// w3BuildInstallCommand 构造一条分发安装指令（仓库摘要 / 外部摘要 / 下载令牌）。
//
// 单独成函数以便回归用例直接验证「摘要是否随指令下发」——这是 S-8 修复的中枢侧支点：
// 副端已强制要求摘要，中枢若漏带，表现是所有分发任务一律失败且原因难查。
func (h *Hub) w3BuildInstallCommand(rec *W3Record, t W3DistTask, action string, d proto.SwDistDetail) proto.CommandPayload {
	detail := d
	detail.DistTaskID = t.ID
	detail.DistRecordID = rec.ID
	detail.Attempt = rec.Attempt
	c := proto.CommandPayload{
		Action:      action,
		TaskID:      newTaskID(),
		Command:     proto.EncodeDistDetail(detail),
		SoftwareURL: t.SoftwareURL,
		Platform:    t.Platform,
		PkgName:     t.PkgName,
	}
	if repoID := repoIDFromURL(t.SoftwareURL); repoID != "" {
		h.mu.Lock()
		it, ok := h.software[repoID]
		h.mu.Unlock()
		if ok {
			c.Sha256 = it.Sha256
			c.Signature = it.Signature
			c.Signer = it.Signer
			// P-4：下发时附加新鲜短时下载令牌（TTL 10 分钟；任务可能延迟调度，
			// 令牌必须在真正下发时刻生成，否则早生成已过期）。端点已强制鉴权。
			c.SoftwareURL = appendRepoToken(t.SoftwareURL, h.repoDownloadToken(repoID, 10*time.Minute))
		}
	}
	// 外部 URL（非仓库）：以任务创建时管理员给出的摘要作为完整性依据。
	// 仍为空则副端会拒绝安装并回告——不得让「无摘要的包」落到 SYSTEM 权限安装环节。
	if c.Sha256 == "" {
		c.Sha256 = t.Sha256
	}
	return c
}

func (h *Hub) w3RecordSkip(taskID, recID, reason string) {
	h.mu.Lock()
	t := h.w3().tasks[taskID]
	rec := w3FindRecord(t, recID)
	if rec != nil {
		rec.State = w3RecSkipped
		rec.Reason = reason
		rec.UpdatedAt = time.Now().UTC()
	}
	h.mu.Unlock()
	h.w3PersistRecord(taskID, recID)
	h.audit("system", "swdist_record_skip", recID, reason, "skipped")
}

func (h *Hub) w3RecordDone(taskID, recID, output string, exit int) {
	h.mu.Lock()
	t := h.w3().tasks[taskID]
	rec := w3FindRecord(t, recID)
	attempt := 0
	if rec != nil {
		rec.State = w3RecSuccess
		rec.Output = output
		rec.ExitCode = exit
		rec.NextRetryAt = nil
		rec.UpdatedAt = time.Now().UTC()
		attempt = rec.Attempt
	}
	h.mu.Unlock()
	h.w3PersistRecord(taskID, recID)
	log.Printf("[hub] 分发成功 task=%s rec=%s attempt=%d", taskID, recID, attempt)
}

// w3RecordAwaitConfirm 可选分发：副端已回告「等待终端用户确认」，挂起不重试。
func (h *Hub) w3RecordAwaitConfirm(taskID, recID, output string) {
	h.mu.Lock()
	t := h.w3().tasks[taskID]
	rec := w3FindRecord(t, recID)
	if rec != nil {
		rec.State = w3RecAwaitConfirm
		rec.Output = orDefault(output, "等待终端用户确认安装（可选分发）")
		rec.NextRetryAt = nil
		rec.UpdatedAt = time.Now().UTC()
	}
	h.mu.Unlock()
	h.w3PersistRecord(taskID, recID)
	h.audit("system", "swdist_record_await_confirm", recID, "可选分发等待终端用户确认", "pending")
}

func (h *Hub) w3RecordFail(taskID, recID, output string, exit int) {
	h.mu.Lock()
	t := h.w3().tasks[taskID]
	rec := w3FindRecord(t, recID)
	if rec != nil {
		rec.Output = output
		rec.ExitCode = exit
		rec.UpdatedAt = time.Now().UTC()
	}
	h.mu.Unlock()
	h.w3ScheduleRetry(taskID, recID)
}

// w3ScheduleRetry 失败重试（W3-4）：未超上限则按固定/指数间隔重新入队，超限标记永久失败并告警。
func (h *Hub) w3ScheduleRetry(taskID, recID string) {
	now := time.Now().UTC()
	h.mu.Lock()
	t := h.w3().tasks[taskID]
	rec := w3FindRecord(t, recID)
	if t == nil || rec == nil {
		h.mu.Unlock()
		return
	}
	permanent := false
	nextAt := time.Time{}
	if rec.Attempt > t.MaxRetry {
		rec.State = w3RecPermFailed
		rec.NextRetryAt = nil
		permanent = true
	} else {
		delay := time.Duration(t.RetryIntervalSec) * time.Second
		if t.RetryBackoff == "exponential" && rec.Attempt > 1 {
			shift := rec.Attempt - 1
			if shift > 5 {
				shift = 5
			}
			delay = time.Duration(int64(t.RetryIntervalSec)<<uint(shift)) * time.Second
		}
		rec.State = w3RecRetryWaiting
		nextAt = now.Add(delay)
		rec.NextRetryAt = &nextAt
	}
	rec.UpdatedAt = now
	devName := rec.DeviceName
	devID := rec.DeviceID
	pkg := t.PkgName
	attempt := rec.Attempt
	recOutput := rec.Output
	h.mu.Unlock()

	h.w3PersistRecord(taskID, recID)
	if permanent {
		msg := fmt.Sprintf("软件分发重试 %d 次仍失败：%s", attempt-1, pkg)
		detail := fmt.Sprintf("任务=%s 设备=%s(%s) 输出=%s", taskID, devID, devName, w3Clip(recOutput, 200))
		h.addAlert(alertOf(w3AlertDistFailed, devID, devName, msg, detail))
		h.audit("system", "swdist_record_permanently_failed", devID, detail, "failed")
		log.Printf("[hub] 分发永久失败 task=%s rec=%s 设备=%s 尝试=%d", taskID, recID, devID, attempt)
		return
	}
	log.Printf("[hub] 分发失败待重试 task=%s rec=%s 尝试=%d 下次=%s", taskID, recID, attempt, nextAt.Format(time.RFC3339))
}

// w3ConfirmRecord 可选分发的确认入口：确认后重新入队派发，拒绝则标记取消。
func (h *Hub) w3ConfirmRecord(taskID, recID string, confirm bool) (bool, string) {
	h.mu.Lock()
	t := h.w3().tasks[taskID]
	rec := w3FindRecord(t, recID)
	if t == nil || rec == nil {
		h.mu.Unlock()
		return false, "执行记录不存在"
	}
	if rec.State != w3RecAwaitConfirm {
		h.mu.Unlock()
		return false, "该记录不在等待确认状态: " + rec.State
	}
	if confirm {
		rec.State = w3RecPending
		rec.Reason = ""
		rec.Confirmed = true // optional：确认后重发时副端据此直接安装，不再等待确认
	} else {
		rec.State = w3RecCancelled
		rec.Reason = "终端用户拒绝安装（可选分发）"
	}
	rec.UpdatedAt = time.Now().UTC()
	h.mu.Unlock()
	h.w3PersistRecord(taskID, recID)
	return true, ""
}

func (h *Hub) w3CancelTask(taskID string) bool {
	h.mu.Lock()
	t, ok := h.w3().tasks[taskID]
	if !ok || t.State == w3TaskDone || t.State == w3TaskCancelled {
		h.mu.Unlock()
		return false
	}
	now := time.Now().UTC()
	t.State = w3TaskCancelled
	t.FinishedAt = &now
	recIDs := make([]string, 0, len(t.Records))
	for _, r := range t.Records {
		switch r.State {
		case w3RecPending, w3RecRetryWaiting, w3RecDispatching, w3RecAwaitConfirm:
			r.State = w3RecCancelled
			r.Reason = "任务已取消"
			r.NextRetryAt = nil
			r.UpdatedAt = now
		}
		recIDs = append(recIDs, r.ID)
	}
	h.mu.Unlock()
	for _, rid := range recIDs {
		h.w3PersistRecord(taskID, rid)
	}
	h.w3PersistTask(taskID)
	log.Printf("[hub] 分发任务取消 id=%s", taskID)
	return true
}

func (h *Hub) w3FinishTask(taskID string) {
	h.mu.Lock()
	t, ok := h.w3().tasks[taskID]
	if !ok {
		h.mu.Unlock()
		return
	}
	if t.State == w3TaskCancelled {
		h.mu.Unlock()
		return
	}
	for _, r := range t.Records {
		if !w3Terminal(r.State) {
			t.State = w3TaskRunning
			h.mu.Unlock()
			return
		}
	}
	now := time.Now().UTC()
	t.FinishedAt = &now
	success, failed, skipped, cancelled := 0, 0, 0, 0
	for _, r := range t.Records {
		switch r.State {
		case w3RecSuccess:
			success++
		case w3RecPermFailed:
			failed++
		case w3RecSkipped:
			skipped++
		case w3RecCancelled:
			cancelled++
		}
	}
	t.Success, t.Failed, t.Skipped = success, failed, skipped
	switch {
	case failed == 0 && cancelled == 0:
		t.State = w3TaskDone
	case success > 0 || skipped > 0:
		t.State = w3TaskPartial
	default:
		t.State = w3TaskFailed
	}
	state := t.State
	h.mu.Unlock()
	h.w3PersistTask(taskID)
	h.audit("system", "swdist_task_finish", taskID,
		fmt.Sprintf("state=%s 成功=%d 失败=%d 跳过=%d 取消=%d", state, success, failed, skipped, cancelled), state)
	log.Printf("[hub] 分发任务结束 id=%s state=%s 成功=%d 失败=%d 跳过=%d", taskID, state, success, failed, skipped)
}

func w3Terminal(state string) bool {
	switch state {
	case w3RecSuccess, w3RecPermFailed, w3RecSkipped, w3RecCancelled:
		return true
	}
	return false
}

// ==================== 后台扫描（计划任务 / 重试 / 选主） ====================

func (h *Hub) w3Start() {
	h.mu.Lock()
	st := h.w3()
	if st.started {
		h.mu.Unlock()
		return
	}
	st.started = true
	h.mu.Unlock()
	h.w3LoadPG()
	go h.w3Sweeper()
	go h.w3HALoop()
	h.w3SelfBeat()
}

func (h *Hub) w3Sweeper() {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	for range tick.C {
		h.w3TickHA()
		h.w3TickTasks()
	}
}

func (h *Hub) w3TickTasks() {
	now := time.Now().UTC()
	h.mu.Lock()
	var kick []string
	var finish []string
	for _, t := range h.w3().tasks {
		if t.State == w3TaskPending && (t.ScheduleAt == nil || !t.ScheduleAt.After(now)) {
			t.State = w3TaskRunning
			if t.StartedAt == nil {
				ts := now
				t.StartedAt = &ts
			}
			t.running = true
			kick = append(kick, t.ID)
			continue
		}
		if t.State != w3TaskRunning {
			continue
		}
		pending, nonTerminal := 0, 0
		for _, r := range t.Records {
			if r.State == w3RecRetryWaiting && r.NextRetryAt != nil && !r.NextRetryAt.After(now) {
				r.State = w3RecPending
				r.NextRetryAt = nil
				r.UpdatedAt = now
			}
			if r.State == w3RecPending {
				pending++
			}
			if !w3Terminal(r.State) {
				nonTerminal++
			}
		}
		if nonTerminal == 0 {
			finish = append(finish, t.ID)
			continue
		}
		if pending > 0 && !t.running {
			t.running = true
			kick = append(kick, t.ID)
		}
	}
	h.mu.Unlock()
	for _, id := range kick {
		go h.w3RunTask(id)
	}
	for _, id := range finish {
		h.w3FinishTask(id)
	}
}

// ==================== W3-5 中枢高可用：主备角色与租约 ====================

func (h *Hub) w3HALease() time.Duration {
	return time.Duration(envInt("YUDUAN_HA_LEASE_SEC", 15)) * time.Second
}

func (h *Hub) w3HARenew() time.Duration {
	return time.Duration(envInt("YUDUAN_HA_RENEW_SEC", 5)) * time.Second
}

// w3TickHA 每秒校验一次 leader 租约（心跳停止也能及时发现并切换）。
func (h *Hub) w3TickHA() {
	h.mu.Lock()
	h.w3ElectLocked(time.Now().UTC())
	h.mu.Unlock()
}

// w3HALoop 本节点心跳 + leader 租约续期。
func (h *Hub) w3HALoop() {
	tick := time.NewTicker(h.w3HARenew())
	defer tick.Stop()
	for range tick.C {
		h.w3SelfBeat()
	}
}

func (h *Hub) w3SelfBeat() {
	now := time.Now().UTC()
	h.mu.Lock()
	st := h.w3()
	n, ok := st.nodes[h.hubID]
	if !ok {
		n = &W3Node{HubID: h.hubID}
		st.nodes[h.hubID] = n
	}
	n.Addr = h.publicAddr
	n.LastSeen = now
	if n.Role == w3RoleLeader {
		n.LeaseUntil = now.Add(h.w3HALease())
	}
	h.w3ElectLocked(now)
	cp := *n
	h.mu.Unlock()
	h.w3PersistNode(&cp)
}

// w3Heartbeat 记录一次节点心跳（外部节点经 REST 上报；本节点经 w3SelfBeat）。
func (h *Hub) w3Heartbeat(hubID, addr string) *W3Node {
	hubID = strings.TrimSpace(hubID)
	if hubID == "" {
		return nil
	}
	now := time.Now().UTC()
	h.mu.Lock()
	st := h.w3()
	n, ok := st.nodes[hubID]
	if !ok {
		n = &W3Node{HubID: hubID}
		st.nodes[hubID] = n
	}
	n.Addr = addr
	n.LastSeen = now
	h.w3ElectLocked(now)
	cp := *n
	h.mu.Unlock()
	h.w3PersistNode(&cp)
	return &cp
}

// w3ElectLocked 选主：存活节点中 hub_id 最小者升主；现任 leader 租约未过期不抢占。
// 调用方必须持有 h.mu（并发安全的唯一入口）。
func (h *Hub) w3ElectLocked(now time.Time) {
	st := h.w3()
	lease := h.w3HALease()
	var cand *W3Node
	var cur *W3Node
	for _, n := range st.nodes {
		n.Online = !n.LastSeen.IsZero() && now.Sub(n.LastSeen) <= lease
		if n.Role == w3RoleLeader {
			cur = n
		}
		if n.Online && (cand == nil || n.HubID < cand.HubID) {
			cand = n
		}
	}
	if cand == nil {
		for _, n := range st.nodes {
			n.Role = w3RoleFollower
			n.LeaseUntil = time.Time{}
		}
		return
	}
	if cur != nil && cur != cand && cur.LeaseUntil.After(now) {
		return // 现任 leader 租约有效，不抢占
	}
	if cur == cand && cur.LeaseUntil.After(now) {
		return // 已是该节点为主且租约有效，无需变更
	}
	for id, n := range st.nodes {
		if id == cand.HubID {
			n.Role = w3RoleLeader
			n.LeaseUntil = now.Add(lease)
		} else {
			n.Role = w3RoleFollower
			n.LeaseUntil = time.Time{}
		}
	}
	log.Printf("[hub] HA 选主：leader=%s（存活 %d/%d，租约 %v）", cand.HubID, w3OnlineCount(st), len(st.nodes), lease)
}

func w3OnlineCount(st *w3Store) int {
	n := 0
	for _, v := range st.nodes {
		if v.Online {
			n++
		}
	}
	return n
}

func (h *Hub) handleW3HANodes(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	h.mu.Lock()
	h.w3ElectLocked(now)
	nodes := make([]*W3Node, 0, len(h.w3().nodes))
	leader := ""
	for _, n := range h.w3().nodes {
		cp := *n
		nodes = append(nodes, &cp)
		if cp.Role == w3RoleLeader {
			leader = cp.HubID
		}
	}
	h.mu.Unlock()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].HubID < nodes[j].HubID })
	writeJSON(w, map[string]any{
		"code": 0, "total": len(nodes), "nodes": nodes,
		"self": h.hubID, "leader": leader,
		"lease_sec": int(h.w3HALease().Seconds()), "renew_sec": int(h.w3HARenew().Seconds()),
		"now": now.Format(time.RFC3339),
	})
}

func (h *Hub) handleW3HAHeartbeat(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		HubID string `json:"hub_id"`
		Addr  string `json:"addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 3030, "bad request: "+err.Error())
		return
	}
	n := h.w3Heartbeat(body.HubID, body.Addr)
	if n == nil {
		writeErr(w, 3031, "hub_id 必填")
		return
	}
	writeJSON(w, map[string]any{"code": 0, "node": n})
}

// handleW3HAClaim 运维介入：手动抢占主角色（需 user:manage）。
func (h *Hub) handleW3HAClaim(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		HubID string `json:"hub_id"`
		Addr  string `json:"addr"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	hubID := strings.TrimSpace(body.HubID)
	if hubID == "" {
		hubID = h.hubID
	}
	now := time.Now().UTC()
	h.mu.Lock()
	st := h.w3()
	n, ok := st.nodes[hubID]
	if !ok {
		n = &W3Node{HubID: hubID}
		st.nodes[hubID] = n
	}
	if body.Addr != "" {
		n.Addr = body.Addr
	}
	n.LastSeen = now
	n.Online = true
	n.Role = w3RoleLeader
	n.LeaseUntil = now.Add(h.w3HALease())
	for id, other := range st.nodes {
		if id == hubID {
			continue
		}
		other.Role = w3RoleFollower
		other.LeaseUntil = time.Time{}
	}
	cp := *n
	h.mu.Unlock()
	h.w3PersistNode(&cp)
	h.audit(claims.Username, "ha_claim", hubID, "手动抢占主角色（运维介入）", "success")
	log.Printf("[hub] HA 手动抢占 leader=%s by=%s", hubID, claims.Username)
	writeJSON(w, map[string]any{"code": 0, "ok": true, "node": &cp})
}

// ==================== PostgreSQL 双写 ====================

func (h *Hub) w3PG() *store.PostgresStore {
	pg, _ := h.store.(*store.PostgresStore)
	return pg
}

func (h *Hub) w3PersistNode(n *W3Node) {
	pg := h.w3PG()
	if pg == nil {
		return
	}
	_ = store.Wave3UpsertNode(pg, store.Wave3NodeRow{
		HubID: n.HubID, Addr: n.Addr, Role: n.Role, LastSeen: n.LastSeen, LeaseUntil: n.LeaseUntil,
	})
}

func (h *Hub) w3PersistTask(taskID string) {
	pg := h.w3PG()
	if pg == nil {
		return
	}
	h.mu.Lock()
	t, ok := h.w3().tasks[taskID]
	if !ok {
		h.mu.Unlock()
		return
	}
	payload := w3MustJSON(w3TaskView(t, false))
	state := t.State
	created := t.CreatedAt
	h.mu.Unlock()
	_ = store.Wave3UpsertTask(pg, store.Wave3TaskRow{ID: taskID, State: state, Payload: payload, CreatedAt: created})
}

func (h *Hub) w3PersistRecord(taskID, recID string) {
	pg := h.w3PG()
	if pg == nil {
		return
	}
	h.mu.Lock()
	t, ok := h.w3().tasks[taskID]
	rec := w3FindRecord(t, recID)
	if !ok || rec == nil {
		h.mu.Unlock()
		return
	}
	cp := *rec
	h.mu.Unlock()
	_ = store.Wave3UpsertRecord(pg, store.Wave3RecordRow{
		ID: cp.ID, TaskID: taskID, State: cp.State, Payload: w3MustJSON(&cp), UpdatedAt: cp.UpdatedAt,
	})
}

func (h *Hub) w3LoadPG() {
	pg := h.w3PG()
	if pg == nil {
		return
	}
	// 模板：库内为空视为首次启动，注入内置默认模板
	if rows, err := store.Wave3ListTemplates(pg); err == nil {
		h.mu.Lock()
		st := h.w3()
		for _, r := range rows {
			st.templates[w3TplKey(r.Platform, r.PkgType)] = &W3Template{
				Platform: r.Platform, PkgType: r.PkgType, Args: r.Args, Desc: r.Desc,
				Builtin: r.Builtin, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
			}
		}
		empty := len(st.templates) == 0
		h.mu.Unlock()
		if empty {
			for _, t := range w3DefaultTemplates() {
				_, _ = h.w3UpsertTemplate(t.Platform, t.PkgType, t.Args, t.Desc, true, "system")
			}
		}
	}
	// 任务 + 执行记录
	if rows, err := store.Wave3ListTasks(pg); err == nil {
		h.mu.Lock()
		for _, r := range rows {
			var t W3DistTask
			if json.Unmarshal([]byte(r.Payload), &t) != nil {
				continue
			}
			t.Records = nil
			t.running = false
			h.w3().tasks[r.ID] = &t
		}
		h.mu.Unlock()
	}
	if rows, err := store.Wave3ListRecords(pg); err == nil {
		h.mu.Lock()
		for _, r := range rows {
			var rec W3Record
			if json.Unmarshal([]byte(r.Payload), &rec) != nil {
				continue
			}
			if t, ok := h.w3().tasks[r.TaskID]; ok {
				t.Records = append(t.Records, &rec)
			}
		}
		for _, t := range h.w3().tasks {
			t.Total = len(t.Records)
			// 重启时中断的记录回到待发，避免永久卡在 dispatching
			for _, rec := range t.Records {
				if rec.State == w3RecDispatching {
					rec.State = w3RecPending
				}
			}
		}
		h.mu.Unlock()
	}
	// HA 节点
	if rows, err := store.Wave3ListNodes(pg); err == nil {
		h.mu.Lock()
		for _, r := range rows {
			h.w3().nodes[r.HubID] = &W3Node{
				HubID: r.HubID, Addr: r.Addr, Role: r.Role, LastSeen: r.LastSeen, LeaseUntil: r.LeaseUntil,
			}
		}
		h.mu.Unlock()
	}
}

// ==================== 小工具 ====================

func w3TaskView(t *W3DistTask, withRecords bool) *W3DistTask {
	cp := *t
	if !withRecords {
		cp.Records = nil
	}
	return &cp
}

func w3MustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (h *Hub) w3NewID(prefix string) string {
	h.mu.Lock()
	st := h.w3()
	st.seq++
	n := st.seq
	h.mu.Unlock()
	return fmt.Sprintf("%s-%d-%s", prefix, n, randHex(4))
}

func (h *Hub) w3SetCurrentVersion(taskID, recID, version string) {
	h.mu.Lock()
	t := h.w3().tasks[taskID]
	if r := w3FindRecord(t, recID); r != nil {
		r.CurrentVersion = version
	}
	h.mu.Unlock()
}

// w3FindSoftware 在设备软件清单中按名称查找（大小写不敏感，去空格后比较）。
func w3FindSoftware(d store.Device, name string) (string, bool) {
	target := strings.ToLower(strings.TrimSpace(name))
	if target == "" {
		return "", false
	}
	for _, s := range d.SoftwareList() {
		if strings.ToLower(strings.TrimSpace(s.Name)) == target {
			return s.Version, true
		}
	}
	return "", false
}

func w3ExtToPkgType(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	ext := strings.ToLower(strings.TrimPrefix(name[i:], "."))
	for _, t := range proto.PkgTypes() {
		if t == ext {
			return t
		}
	}
	return ""
}

func (h *Hub) w3RepoURL(repoID string) string {
	base := strings.TrimSpace(h.publicAddr)
	if base == "" {
		base = "127.0.0.1:8080"
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	return strings.TrimSuffix(base, "/") + "/api/v1/repo/" + repoID
}

func w3ParseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if n, err := atoi64(s); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized time: %s", s)
}

func w3Clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func w3DefaultMaxRetry() int      { return envInt("YUDUAN_SWDIST_MAX_RETRY", 2) }
func w3DefaultRetryInterval() int { return envInt("YUDUAN_SWDIST_RETRY_SEC", 60) }

// 权限常量在 auth 包；此处做编译期引用校验，避免误删权限点。
var _ = auth.PermSoftwareMgmt
