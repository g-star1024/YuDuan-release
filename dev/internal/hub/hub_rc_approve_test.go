// v0.4.16 回归测试（实测报告问题 4）：
// POST /api/v1/rc/approvals/{id} 请求体严格校验——
//   - {"decision":"approved"} / {"approved":true} 等错误写法此前被零值 Approve=false
//     **静默判拒**（返回 ok+status=rejected），运维易误读成「管理员拒绝」；
//   - 现改为：解码失败 / 未知字段 / 缺 approve / 类型不符一律 HTTP 400 + code=2009；
//   - 合法 body 但工单不存在仍走业务码 2004（HTTP 200），证明入口校验未误伤正常流程。
package hub

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func approvePostRaw(t *testing.T, srv *httptest.Server, token, rawBody string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/rc/approvals/apr-x", bytes.NewReader([]byte(rawBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST approvals: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestRCApproveInvalidBodyReturns400(t *testing.T) {
	h, srv := metaTestHub(t)
	token := metaLoginToken(t, h, "admin")

	cases := []struct{ name, body string }{
		{"decision 写法", `{"decision":"approved"}`},
		{"approved 字段写法", `{"approved":true}`},
		{"缺少 approve 字段", `{"reason":"测试"}`},
		{"approve 类型错误", `{"approve":"true"}`},
		{"非法 JSON", `{bad`},
		{"空 body", ``},
	}
	for _, c := range cases {
		st, out := approvePostRaw(t, srv, token, c.body)
		if st != http.StatusBadRequest {
			t.Fatalf("%s: HTTP = %d, want 400（不得静默判拒）body=%s", c.name, st, c.body)
		}
		if code, _ := out["code"].(float64); int(code) != 2009 {
			t.Fatalf("%s: code = %v, want 2009", c.name, out["code"])
		}
	}
}

func TestRCApproveValidBodyPassesValidation(t *testing.T) {
	h, srv := metaTestHub(t)
	token := metaLoginToken(t, h, "admin")

	// 合法 body：入口校验通过，因工单不存在落到业务码 2004（HTTP 200）。
	for _, c := range []struct{ name, body string }{
		{"approve=true", `{"approve":true}`},
		{"approve=false 带 reason", `{"approve":false,"reason":"ok"}`},
	} {
		st, out := approvePostRaw(t, srv, token, c.body)
		if st != http.StatusOK {
			t.Fatalf("%s: HTTP = %d, want 200（合法 body 不应被 400 拦截）", c.name, st)
		}
		if code, _ := out["code"].(float64); int(code) != 2004 {
			t.Fatalf("%s: code = %v, want 2004（工单不存在）", c.name, out["code"])
		}
	}
}
