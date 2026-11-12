package hub

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/store"
)

// newTestHub 构造一个内存态 Hub，内置 admin/operator/viewer 三账号，配置 API 覆盖文件落临时目录。
func newTestHub(t *testing.T) (*Hub, string) {
	t.Helper()
	secret := "test-secret-config"
	us := store.NewMemUserStore()
	us.UpsertUser(auth.User{Username: "admin", Role: auth.RoleAdmin, Password: "x"})
	us.UpsertUser(auth.User{Username: "operator", Role: auth.RoleOperator, Password: "x"})
	us.UpsertUser(auth.User{Username: "viewer", Role: auth.RoleViewer, Password: "x"})
	authSvc := auth.NewAuthService(us, secret, "")
	ov := filepath.Join(t.TempDir(), "hub-config-overrides.json")
	h := NewHub(HubConfig{
		HMACSecret:          secret,
		Users:               us,
		Auth:                authSvc,
		ConfigOverridesFile: ov,
	})
	return h, secret
}

func doConfig(t *testing.T, srv *httptest.Server, token, method string, body []byte) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+"/api/v1/config", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func token(secret, user, role string) string {
	return crypto.SignToken(secret, user, role, time.Now().Add(time.Hour).Unix(), false)
}

func TestConfigAPI_RBACAndLiveRestart(t *testing.T) {
	h, secret := newTestHub(t)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	adminTok := token(secret, "admin", "admin")
	opTok := token(secret, "operator", "operator")
	viewTok := token(secret, "viewer", "viewer")

	// 1) viewer 读配置应被拒绝（无 config:view）。
	// 注意：本代码库 RBAC 拒绝以 body code=403 + HTTP 200 返回（与 guard 一致），故判 body code。
	_, m := doConfig(t, srv, viewTok, http.MethodGet, nil)
	if c, _ := m["code"].(float64); c != 403 {
		t.Fatalf("viewer GET 期望 body code 403，实际 %v", m["code"])
	}

	// 2) operator 可读
	_, m = doConfig(t, srv, opTok, http.MethodGet, nil)
	if c, _ := m["code"].(float64); c != 0 {
		t.Fatalf("operator GET body code 期望 0，实际 %v", m["code"])
	}
	settings, _ := m["settings"].([]any)
	if len(settings) == 0 {
		t.Fatalf("settings 不应为空")
	}
	// 敏感项仅以「排除清单」形式告知，绝不以键值形式回显
	excl, _ := m["sensitive_excluded"].([]any)
	if len(excl) == 0 {
		t.Fatalf("sensitive_excluded 不应为空")
	}
	// 3) operator 写回应被拒绝（需 config:write=admin）
	_, m = doConfig(t, srv, opTok, http.MethodPost, mustJSONBytes(map[string]any{
		"settings": map[string]any{"rc_max_sec": 7200},
	}))
	if c, _ := m["code"].(float64); c != 403 {
		t.Fatalf("operator POST 期望 body code 403，实际 %v", m["code"])
	}

	// 4) admin 写回：live 即时生效 + restart 持久化
	code, m := doConfig(t, srv, adminTok, http.MethodPost, mustJSONBytes(map[string]any{
		"settings": map[string]any{
			"rc_max_sec":            7200,
			"backup_interval_hours": 12,
		},
	}))
	if code != http.StatusOK {
		t.Fatalf("admin POST 期望 200，实际 %d body=%v", code, m)
	}
	applied, _ := m["applied_live"].([]any)
	pending, _ := m["pending_restart"].([]any)
	if !containsKey(applied, "rc_max_sec") {
		t.Fatalf("rc_max_sec 应即时生效，applied_live=%v", applied)
	}
	if !containsKey(pending, "backup_interval_hours") {
		t.Fatalf("backup_interval_hours 应待重启，pending_restart=%v", pending)
	}

	// 5) 覆盖文件已落地（restart 持久化）
	if _, err := os.Stat(h.cfgOverridesFile); err != nil {
		t.Fatalf("覆盖文件未持久化: %v", err)
	}

	// 6) 再读：live 值已生效，restart_pending=true
	_, m2 := doConfig(t, srv, adminTok, http.MethodGet, nil)
	if rp, _ := m2["restart_pending"].(bool); !rp {
		t.Fatalf("restart_pending 应为 true")
	}
	got := settingValue(m2, "rc_max_sec")
	if got != float64(7200) {
		t.Fatalf("rc_max_sec 期望 7200，实际 %v", got)
	}

	// 7) 敏感项写回必须被拒绝
	code, m = doConfig(t, srv, adminTok, http.MethodPost, mustJSONBytes(map[string]any{
		"settings": map[string]any{"hmac_secret": "evil"},
	}))
	if code != http.StatusOK {
		t.Fatalf("敏感项写回应返回 200 但带 rejected，实际 %d", code)
	}
	rej, _ := m["rejected"].([]any)
	if len(rej) == 0 {
		t.Fatalf("敏感项 hmac_secret 写回应被 rejected")
	}
}

// ---- 测试辅助 ----

func mustJSONBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func containsKey(list []any, key string) bool {
	for _, it := range list {
		if s, ok := it.(string); ok && s == key {
			return true
		}
	}
	return false
}

// settingValue 从 GET 响应的 settings 数组中取出某 key 的 value。
func settingValue(m map[string]any, key string) any {
	settings, _ := m["settings"].([]any)
	for _, it := range settings {
		row, _ := it.(map[string]any)
		if row["key"] == key {
			return row["value"]
		}
	}
	return nil
}
