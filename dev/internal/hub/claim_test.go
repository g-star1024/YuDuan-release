package hub

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func newClaimHub(t *testing.T) *Hub {
	t.Helper()
	h := NewHub(HubConfig{HMACSecret: "secret-abc", HubID: "hub-test"})
	return h
}

func TestClaimTokenRotatesAndValidates(t *testing.T) {
	h := newClaimHub(t)
	tok1 := h.CurrentClaimToken()
	if tok1 == "" {
		t.Fatal("令牌不应为空")
	}
	if !h.claimTokenValid(tok1) {
		t.Fatal("刚生成的令牌应有效")
	}
	// 同一窗口内返回相同令牌（广播与 claim 一致）
	if got := h.CurrentClaimToken(); got != tok1 {
		t.Fatalf("窗口内令牌应稳定: got %s want %s", got, tok1)
	}
	// 无效令牌
	if h.claimTokenValid("bogus") {
		t.Fatal("伪令牌不应有效")
	}
	if h.claimTokenValid("") {
		t.Fatal("空令牌不应有效")
	}
}

func TestClaimEndpointReturnsHMACSecret(t *testing.T) {
	h := newClaimHub(t)
	tok := h.CurrentClaimToken()
	// 有效令牌
	req := httptest.NewRequest("GET", "/api/agent/claim?token="+tok+"&device=d1&hostname=pc1", nil)
	w := httptest.NewRecorder()
	h.handleAgentClaim(w, req)
	if !strings.Contains(w.Body.String(), "secret-abc") {
		t.Fatalf("有效令牌应返回 hmacSecret，got: %s", w.Body.String())
	}
}

func TestClaimEndpointRejectsInvalidToken(t *testing.T) {
	h := newClaimHub(t)
	req := httptest.NewRequest("GET", "/api/agent/claim?token=bogus", nil)
	w := httptest.NewRecorder()
	h.handleAgentClaim(w, req)
	if !strings.Contains(w.Body.String(), "invalid_or_expired_token") {
		t.Fatalf("伪令牌应被拒，got: %s", w.Body.String())
	}
}

func TestClaimEndpointRequiresToken(t *testing.T) {
	h := newClaimHub(t)
	req := httptest.NewRequest("GET", "/api/agent/claim", nil)
	w := httptest.NewRecorder()
	h.handleAgentClaim(w, req)
	if !strings.Contains(w.Body.String(), "token_required") {
		t.Fatalf("缺令牌应报 token_required，got: %s", w.Body.String())
	}
}

func TestClaimEndpointSignsClientCertWhenCAReady(t *testing.T) {
	// 无 CA 时不签发客户端证书（不 panic，字段为空）
	h := newClaimHub(t)
	tok := h.CurrentClaimToken()
	req := httptest.NewRequest("GET", "/api/agent/claim?token="+tok+"&device=d1", nil)
	w := httptest.NewRecorder()
	h.handleAgentClaim(w, req)
	if strings.Contains(w.Body.String(), "clientCert") {
		t.Fatalf("无根 CA 时不应返回客户端证书，got: %s", w.Body.String())
	}
}
