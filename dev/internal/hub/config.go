// config.go 实现中枢配置 API（v0.4.31-A）：
//   - GET  /api/v1/config  读取当前生效的非敏感配置 + 运行时信息 + 可写项清单。
//   - POST /api/v1/config  写回非敏感配置：即时热更新子集（live）落内存并持久化；
//     需重启子集（restart）仅持久化到 override 文件，重启后由 NewHub 加载生效。
//
// 铁律（用户拍板）：敏感项（HMAC_SECRET / PEPPER / SIGN_SEED / CA_KEY / TLS_KEY /
// RECORD_KEY / DB_DSN / CLIENT_* / TLS_PIN）绝不出现在 GET 响应，也绝不接受 POST 写。
// 这些密钥只能经 env / keystore 注入，变更须重启中枢。
package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/store"
)

// configOverridesFileDefault 配置覆盖文件落盘位置（HubConfig.ConfigOverridesFile 缺省）。
const configOverridesFileDefault = "data/hub-config-overrides.json"

// configKeyDef 描述一个可被配置 API 暴露 / 写回的非敏感配置项。
type configKeyDef struct {
	Key             string // API 字段名（snake_case）
	EnvVar          string // 对应环境变量（仅文档 / 回显）
	Type            string // string | int | bool
	Writable        bool   // 是否允许经 API 写回
	RequiresRestart bool   // true=仅持久化，重启后生效；false=即时热更新
	Group           string // UI 分组
	Desc            string // 中文说明
}

// configKeyDefs 是 v0.4.31 开放的全部非敏感配置项。新增可写项只需在此登记。
// 敏感项一律不在此清单——GET 不回显、POST 不接受。
var configKeyDefs = []configKeyDef{
	{Key: "alert_webhook_url", EnvVar: "YUDUAN_ALERT_WEBHOOK_URL", Type: "string", Writable: true, RequiresRestart: false, Group: "告警", Desc: "外部告警通知 webhook（为空=仅站内徽章）"},
	{Key: "rc_max_sec", EnvVar: "YUDUAN_RC_MAX_SEC", Type: "int", Writable: true, RequiresRestart: false, Group: "远控", Desc: "远控会话绝对时长上限（秒），0=系统默认"},
	{Key: "rc_idle_sec", EnvVar: "YUDUAN_RC_IDLE_SEC", Type: "int", Writable: true, RequiresRestart: false, Group: "远控", Desc: "远控主端空闲上限（秒），0=系统默认"},
	{Key: "max_devices", EnvVar: "YUDUAN_MAX_DEVICES", Type: "int", Writable: true, RequiresRestart: false, Group: "台账", Desc: "设备台账上限（防假设备洪泛），0=系统默认 5000"},
	{Key: "backup_keep", EnvVar: "YUDUAN_BACKUP_KEEP", Type: "int", Writable: true, RequiresRestart: false, Group: "备份", Desc: "PG 自动备份保留份数"},
	{Key: "backup_interval_hours", EnvVar: "YUDUAN_BACKUP_INTERVAL", Type: "int", Writable: true, RequiresRestart: true, Group: "备份", Desc: "PG 自动备份间隔（小时），0=关闭自动备份"},
	{Key: "hmac_enforce", EnvVar: "YUDUAN_HMAC_ENFORCE", Type: "bool", Writable: true, RequiresRestart: false, Group: "安全", Desc: "强制副端指令 HMAC 验签（关闭仅限排障）"},
	{Key: "record_enabled", EnvVar: "YUDUAN_RC_RECORD", Type: "bool", Writable: true, RequiresRestart: true, Group: "录像", Desc: "远控加密录像留存（opt-in）"},
	{Key: "record_retention_days", EnvVar: "YUDUAN_RECORD_RETENTION_DAYS", Type: "int", Writable: true, RequiresRestart: true, Group: "录像", Desc: "录像留存天数"},
}

var configKeyByName = func() map[string]configKeyDef {
	m := map[string]configKeyDef{}
	for _, k := range configKeyDefs {
		m[k.Key] = k
	}
	return m
}()

// sensitiveExcluded 是绝不开放的敏感配置项（仅作 GET 回显的「排除清单」告知前端）。
var sensitiveExcluded = []string{
	"YUDUAN_HMAC_SECRET", "YUDUAN_PEPPER", "YUDUAN_SIGN_SEED", "YUDUAN_CA_KEY",
	"YUDUAN_TLS_KEY", "YUDUAN_RECORD_KEY", "YUDUAN_DB_DSN",
	"YUDUAN_CLIENT_CA", "YUDUAN_CLIENT_CERT", "YUDUAN_CLIENT_KEY", "YUDUAN_TLS_CAFILE",
}

// ---- 类型安全解析（JSON 解码后为 float64 / bool / string）----

func cfgToInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n), true
		}
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n, true
		}
	}
	return 0, false
}

func cfgToBool(raw any) (bool, bool) {
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b, true
		}
	case float64:
		return v != 0, true
	}
	return false, false
}

// ---- 覆盖文件持久化 ----

// loadConfigOverrides 读取覆盖文件；文件不存在 / 非法时返回 (nil, nil)（不阻断启动）。
func loadConfigOverrides(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// saveConfigOverrides 原子写覆盖文件（临时文件 + rename）。
func saveConfigOverrides(path string, m map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// mergeConfigOverrides 把覆盖值并入 HubConfig（启动期生效）。仅认已知 key，类型不符忽略。
func mergeConfigOverrides(cfg HubConfig, ov map[string]any) HubConfig {
	for key, raw := range ov {
		def, ok := configKeyByName[key]
		if !ok {
			continue
		}
		switch key {
		case "alert_webhook_url":
			if s, ok := raw.(string); ok {
				cfg.AlertWebhookURL = s
			}
		case "rc_max_sec":
			if n, ok := cfgToInt(raw); ok {
				cfg.RCMaxSec = n
			}
		case "rc_idle_sec":
			if n, ok := cfgToInt(raw); ok {
				cfg.RCIdleSec = n
			}
		case "max_devices":
			if n, ok := cfgToInt(raw); ok {
				cfg.MaxDevices = n
			}
		case "backup_keep":
			if n, ok := cfgToInt(raw); ok {
				cfg.BackupKeep = n
			}
		case "backup_interval_hours":
			if n, ok := cfgToInt(raw); ok {
				cfg.BackupInterval = time.Duration(n) * time.Hour
			}
		case "hmac_enforce":
			if b, ok := cfgToBool(raw); ok {
				cfg.HMACEnforce = b
			}
		case "record_enabled":
			if b, ok := cfgToBool(raw); ok {
				cfg.RecordEnabled = b
			}
		case "record_retention_days":
			if n, ok := cfgToInt(raw); ok {
				cfg.RecordRetentionDays = n
			}
		}
		_ = def
	}
	return cfg
}

// ---- 运行时热更新 ----

// configGetValue 读取某 key 的当前生效值（反映运行时热更新）。
func (h *Hub) configGetValue(key string) any {
	switch key {
	case "alert_webhook_url":
		return h.alertWebhookURL
	case "rc_max_sec":
		return h.rcMaxSec
	case "rc_idle_sec":
		return h.rcIdleSec
	case "max_devices":
		return h.maxDevices
	case "backup_keep":
		return h.backupKeep
	case "backup_interval_hours":
		return int(h.backupInterval / time.Hour)
	case "hmac_enforce":
		return h.enforce
	case "record_enabled":
		return h.recEnabled
	case "record_retention_days":
		return h.recRetention
	}
	return nil
}

// configSetLive 即时热更新某 key（仅 live 项）。restart 项不在此处理。
func (h *Hub) configSetLive(key string, raw any) error {
	switch key {
	case "alert_webhook_url":
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("类型错误：%s 应为 string", key)
		}
		h.alertWebhookURL = s
	case "rc_max_sec":
		n, ok := cfgToInt(raw)
		if !ok {
			return fmt.Errorf("类型错误：%s 应为 int", key)
		}
		h.rcMaxSec = n
	case "rc_idle_sec":
		n, ok := cfgToInt(raw)
		if !ok {
			return fmt.Errorf("类型错误：%s 应为 int", key)
		}
		h.rcIdleSec = n
	case "max_devices":
		n, ok := cfgToInt(raw)
		if !ok {
			return fmt.Errorf("类型错误：%s 应为 int", key)
		}
		h.maxDevices = n
	case "backup_keep":
		n, ok := cfgToInt(raw)
		if !ok {
			return fmt.Errorf("类型错误：%s 应为 int", key)
		}
		h.backupKeep = n
	case "hmac_enforce":
		b, ok := cfgToBool(raw)
		if !ok {
			return fmt.Errorf("类型错误：%s 应为 bool", key)
		}
		h.enforce = b
	default:
		return fmt.Errorf("不可热更新的配置项：%s", key)
	}
	return nil
}

// ---- HTTP 处理 ----

// handleConfig 配置端点：GET 只读（operator+admin）/ POST 写回（仅 admin）。
func (h *Hub) handleConfig(w http.ResponseWriter, r *http.Request) {
	claims, err := h.authSvc.VerifyToken(auth.TokenFromHeader(r.Header.Get("Authorization")))
	if err != nil {
		writeErrStatus(w, http.StatusUnauthorized, 401, "unauthorized")
		return
	}
	if claims.MustChange {
		writeErr(w, 4033, "password_change_required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !h.authSvc.HasPerm(claims.Role, auth.PermConfigView) {
			writeErr(w, 403, "forbidden: 需要权限 "+auth.PermConfigView)
			return
		}
		h.handleConfigGet(w, r)
	case http.MethodPost:
		if !h.authSvc.HasPerm(claims.Role, auth.PermConfigWrite) {
			writeErr(w, 403, "forbidden: 需要权限 "+auth.PermConfigWrite)
			return
		}
		h.handleConfigPost(w, r, claims)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// effectiveNetMode 返回运行时网络形态：YUDUAN_NET_MODE（归一小写）或默认 lan。
// 配置 API 的 info 段须回显实际有效值，而非读取原始 env 落空为空串。
func effectiveNetMode() string {
	nm := strings.ToLower(strings.TrimSpace(os.Getenv("YUDUAN_NET_MODE")))
	if nm == "" {
		return "lan"
	}
	return nm
}

// AttestRequire 返回设备证明强制校验开关的运行时有效值（供启动日志 / 调试 / 配置 API 回显）。
func (h *Hub) AttestRequire() bool { return h.attestRequire }

// AttestTrustedMeasurements 返回可信度量白名单的运行时有效值（供启动日志 / 配置 API 回显）。
func (h *Hub) AttestTrustedMeasurements() map[string]bool { return h.attestTrustedMeasurements }

// handleConfigGet 返回当前生效配置 + 运行时信息 + 可写项清单。
func (h *Hub) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	h.cfgMu.RLock()
	restartPending := h.cfgRestartPending
	h.cfgMu.RUnlock()

	settings := make([]map[string]any, 0, len(configKeyDefs))
	for _, def := range configKeyDefs {
		h.cfgMu.RLock()
		val := h.configGetValue(def.Key)
		h.cfgMu.RUnlock()
		settings = append(settings, map[string]any{
			"key":              def.Key,
			"env_var":          def.EnvVar,
			"type":             def.Type,
			"writable":         def.Writable,
			"requires_restart": def.RequiresRestart,
			"group":            def.Group,
			"desc":             def.Desc,
			"value":            val,
		})
	}

	info := map[string]any{
		"net_mode":       h.netMode,
		"hub_id":         h.hubID,
		"backend":        h.backendKind(),
		"tls_enabled":    h.tlsReady.Load(),
		"mtls_enabled":   os.Getenv("YUDUAN_CLIENT_CA") != "",
		"sign_enabled":   h.signPub != "",
		"dsn_configured": os.Getenv("YUDUAN_DB_DSN") != "",
		"public_addr":    h.publicAddr,
		"discovery_port": h.discoveryPort,
		// v0.4.33 §9.2 收口：回显设备证明运行时状态，便于测试/运维确认开关已落地
		// （此前 REQUIRE=1 是否生效只能从握手拒绝日志间接推断，无法直接核验）。
		"attest_require":         h.attestRequire,
		"attest_whitelist_count": len(h.attestTrustedMeasurements),
	}

	writeJSON(w, map[string]any{
		"code":               0,
		"info":               info,
		"settings":           settings,
		"sensitive_excluded": sensitiveExcluded,
		"restart_pending":    restartPending,
	})
}

// handleConfigPost 写回配置：校验可写性 → live 即时生效 / restart 持久化待重启。
func (h *Hub) handleConfigPost(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	var body struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Settings == nil {
		writeErr(w, 2001, "invalid JSON body: 需要 {settings:{...}}")
		return
	}

	var appliedLive, pendingRestart []string
	var rejected []map[string]string

	h.cfgMu.Lock()
	if h.cfgOverrides == nil {
		h.cfgOverrides = map[string]any{}
	}
	for key, raw := range body.Settings {
		def, ok := configKeyByName[key]
		if !ok || !def.Writable {
			rejected = append(rejected, map[string]string{"key": key, "reason": "不可写或未知配置项"})
			continue
		}
		if def.RequiresRestart {
			// 仅持久化，运行时不变更（避免半生效状态）。
			h.cfgOverrides[key] = raw
			pendingRestart = append(pendingRestart, key)
			continue
		}
		if err := h.configSetLive(key, raw); err != nil {
			rejected = append(rejected, map[string]string{"key": key, "reason": err.Error()})
			continue
		}
		h.cfgOverrides[key] = raw
		appliedLive = append(appliedLive, key)
	}
	// 持久化（含 live 与 restart，保证重启后一致）。
	persistErr := saveConfigOverrides(h.cfgOverridesFile, h.cfgOverrides)
	h.cfgRestartPending = len(pendingRestart) > 0
	h.cfgMu.Unlock()

	if persistErr != nil {
		writeErr(w, 5001, "配置持久化失败: "+persistErr.Error())
		return
	}

	// 审计：谁改了什么。
	h.audit(claims.Username, "config_write", "",
		fmt.Sprintf("live=%v restart=%v rejected=%v", appliedLive, pendingRestart, rejected), "success")

	writeJSON(w, map[string]any{
		"code":            0,
		"applied_live":    appliedLive,
		"pending_restart": pendingRestart,
		"rejected":        rejected,
		"restart_pending": len(pendingRestart) > 0,
	})
}

// backendKind 返回持久化后端类型（postgres / memory）。
func (h *Hub) backendKind() string {
	if _, ok := h.store.(*store.PostgresStore); ok {
		return "postgres"
	}
	return "memory"
}
