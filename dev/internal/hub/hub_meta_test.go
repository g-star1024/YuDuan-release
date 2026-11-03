// v0.4.14 回归测试（实测报告问题 1/2）：
//   - W2-4b：POST /api/v1/devices/meta/{id} 改为部分更新语义——仅提交 {"sensitive":true}
//     不得清空部门/楼层/批次/标签（此前整体覆盖，报告实测全部置 null）。
//   - RBAC-1：viewer（仅 device:view）写台账必须被拒（真实 403）；operator 可写。
package hub

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/store"
)

func metaTestHub(t *testing.T) (*Hub, *httptest.Server) {
	t.Helper()
	h := NewHub(HubConfig{HMACSecret: "sec-test-secret"})
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)
	dev := h.store.Upsert(store.Device{ID: "dev-meta-1", Hostname: "PC-META", OS: "windows", Token: "tok-meta-1"})
	_ = dev
	return h, srv
}

func metaLoginToken(t *testing.T, h *Hub, role string) string {
	t.Helper()
	const pw = "Str0ng-Passw0rd!"
	h.users.UpsertUser(auth.User{
		Username: "meta-" + role, Role: role,
		Password: crypto.HashPassword(pw, "yuduan-dev-pepper"),
	})
	res, err := h.authSvc.Login("meta-"+role, pw)
	if err != nil {
		t.Fatalf("login %s: %v", role, err)
	}
	return res.Token
}

func metaPost(t *testing.T, srv *httptest.Server, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/devices/meta/dev-meta-1", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST meta: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func metaDeviceOf(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	raw, ok := out["device"].(map[string]any)
	if !ok {
		// writeJSON 直接回 Device；错误响应才是 {code,message}
		if _, isErr := out["code"]; isErr {
			return nil
		}
		return out
	}
	return raw
}

// TestMetaPartialUpdateKeepsFields：仅提交 sensitive 不得清空其他台账字段（W2-4b 回归）。
func TestMetaPartialUpdateKeepsFields(t *testing.T) {
	h, srv := metaTestHub(t)
	tok := metaLoginToken(t, h, "admin")

	// 第一步：写全台账。
	code, out := metaPost(t, srv, tok, map[string]any{
		"department": "财务部", "floor": "3F", "batch": "2024Q1", "tags": []string{"重要", "外网禁用"},
	})
	if code != 200 {
		t.Fatalf("写台账 HTTP=%d out=%v", code, out)
	}
	dev := metaDeviceOf(t, out)
	if dev == nil || dev["department"] != "财务部" {
		t.Fatalf("台账写入未生效: %v", out)
	}

	// 第二步：仅提交 {"sensitive":true} —— 此前会把其他字段全部清空。
	code, out = metaPost(t, srv, tok, map[string]any{"sensitive": true})
	if code != 200 {
		t.Fatalf("仅提交 sensitive HTTP=%d out=%v", code, out)
	}
	dev = metaDeviceOf(t, out)
	if dev == nil {
		t.Fatalf("仅提交 sensitive 响应异常: %v", out)
	}
	if dev["department"] != "财务部" || dev["floor"] != "3F" || dev["batch"] != "2024Q1" {
		t.Fatalf("W2-4b 回归失败：仅提交 sensitive 清空了台账字段 dept=%v floor=%v batch=%v", dev["department"], dev["floor"], dev["batch"])
	}
	tags, _ := dev["tags"].([]any)
	if len(tags) != 2 {
		t.Fatalf("W2-4b 回归失败：tags 被清空/改变: %v", dev["tags"])
	}
	if dev["sensitive"] != true {
		t.Fatalf("sensitive 未生效: %v", dev["sensitive"])
	}

	// 第三步：显式空串仍可清空对应字段，且不影响其他字段。
	code, out = metaPost(t, srv, tok, map[string]any{"floor": ""})
	if code != 200 {
		t.Fatalf("显式清空 floor HTTP=%d", code)
	}
	dev = metaDeviceOf(t, out)
	// floor 带 omitempty，显式空串在 JSON 里被省略（缺失 = 已清空）。
	if f, present := dev["floor"]; present && f != "" {
		t.Fatalf("显式清空 floor 未生效: %v", f)
	}
	if dev["department"] != "财务部" || dev["batch"] != "2024Q1" {
		t.Fatalf("清空 floor 影响了其他字段: %v", dev)
	}

	// 第四步：再次写台账不得复位 sensitive（此前整体覆盖的隐性 bug）。
	code, out = metaPost(t, srv, tok, map[string]any{"department": "审计部"})
	dev = metaDeviceOf(t, out)
	if dev["department"] != "审计部" || dev["sensitive"] != true {
		t.Fatalf("编辑台账复位了 sensitive 或丢失修改: dept=%v sensitive=%v", dev["department"], dev["sensitive"])
	}
}

// TestMetaViewerForbidden：viewer 写台账必须 403（RBAC-1 回归，服务端强制，不靠前端）。
func TestMetaViewerForbidden(t *testing.T) {
	h, srv := metaTestHub(t)
	vtok := metaLoginToken(t, h, "viewer")
	code, out := metaPost(t, srv, vtok, map[string]any{"department": "越权"})
	if code != http.StatusForbidden {
		t.Fatalf("viewer 写台账应 403，实得 HTTP=%d out=%v", code, out)
	}
	if dev, _ := h.store.Get("dev-meta-1"); dev.Department == "越权" {
		t.Fatal("viewer 越权写台账实际生效——RBAC-1 未修复")
	}

	// operator 持 device:cmd，可写（报告 RBAC-2 预期范围）。
	otok := metaLoginToken(t, h, "operator")
	code, out = metaPost(t, srv, otok, map[string]any{"department": "运维部"})
	if code != 200 {
		t.Fatalf("operator 写台账应 200，实得 HTTP=%d out=%v", code, out)
	}
	if dev, _ := h.store.Get("dev-meta-1"); dev.Department != "运维部" {
		t.Fatalf("operator 写台账未生效: %+v", dev)
	}

	// viewer 的 GET 仍应放行（只读语义保留）。
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/devices/meta/dev-meta-1", nil)
	req.Header.Set("Authorization", "Bearer "+vtok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET meta: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("viewer GET meta 应 200，实得 %d", resp.StatusCode)
	}
}
