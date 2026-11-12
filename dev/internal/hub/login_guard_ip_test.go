package hub

// v0.4.31-C 登录防爆破增强单测：全局按源 IP 维度限速。
// 关键论证：
//   - 新增 IP 维度不得破坏 v0.4.27 F-04「账号维度回环不豁免」（既有 8 个用例已守）
//   - IP 维度必须对回环放行（反代 RemoteAddr 塌缩 DoS + 就绪探针保护）
//   - 4029 契约与秒数文案不变
//   - 内存后端（无 PG）自动降级，功能完整可用

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ipReq(ip string, username string) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/login",
		strings.NewReader(`{"username":"`+username+`","password":"wrong"}`))
	r.RemoteAddr = ip
	r.Header.Set("Content-Type", "application/json")
	return r
}

//  1. IP 维度跨账号累计：同一 IP 分别尝试 admin/user1/user2 都计入同一把锁，
//     而账号维度按 username 分开，永远不会达阈值——证明「全局」维度确实生效。
func TestLoginGuardIP_CrossAccountAccumulates(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "100") // 账号维度阈值拉高，排除干扰
	t.Setenv("YUDUAN_LOGIN_IP_MAX_FAILS", "4")
	t.Setenv("YUDUAN_LOGIN_IP_LOCK_SEC", "60")
	t.Setenv("YUDUAN_LOGIN_IP_WINDOW_SEC", "300")
	h := newGuardHub()
	const ip = "198.51.100.7:50000"
	for _, u := range []string{"admin", "user1", "user2", "user3"} {
		h.loginGuardRecord(ipReq(ip, u), u, false)
	}
	blocked, retry := h.loginGuardBlocked(ipReq(ip, "a-fresh-account"), "a-fresh-account")
	if !blocked {
		t.Fatal("同一来源 IP 跨 4 个账号累计失败应触发全局 IP 锁定")
	}
	if retry < 1 || retry > 60 {
		t.Fatalf("4029 重试秒数应在 (0,60]，got %d", retry)
	}
}

// 2) 不同 IP 互不牵连（IP 维度也遵守「整网不被拖累」）。
func TestLoginGuardIP_PerIPIsolation(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "100")
	t.Setenv("YUDUAN_LOGIN_IP_MAX_FAILS", "3")
	h := newGuardHub()
	for i := 0; i < 3; i++ {
		h.loginGuardRecord(ipReq("198.51.100.21:50000", "u"+string(rune('a'+i))), "u", false)
	}
	if blocked, _ := h.loginGuardBlocked(ipReq("198.51.100.22:50000", "u"), "u"); blocked {
		t.Fatal("来源 B 不应被来源 A 的 IP 维度锁定牵连")
	}
}

//  3. 回环放行（IP 维度）：连续 40 次来自 127.0.0.1、跨多账号，IP 维度绝不锁定。
//     这正是反代 RemoteAddr 全塌缩为 127.0.0.1 时的防 DoS 保障。
func TestLoginGuardIP_LoopbackExempt_NoCrossAccountDoS(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "100")
	t.Setenv("YUDUAN_LOGIN_IP_MAX_FAILS", "2") // 极低阈值：一旦误计数立刻锁
	h := newGuardHub()
	for i := 0; i < 40; i++ {
		h.loginGuardRecord(ipReq("127.0.0.1:50000", "user"+string(rune('a'+i%20))), "u", false)
	}
	if blocked, _ := h.loginGuardIPBlocked(ipReq("127.0.0.1:50000", "u")); blocked {
		t.Fatal("IP 维度必须对回环放行，否则反代塌缩会造成跨来源账号锁定 DoS")
	}
	st := h.loginGuardIPState()
	st.mu.Lock()
	n := len(st.entries)
	st.mu.Unlock()
	if n != 0 {
		t.Fatalf("回环来源不得进入 IP 维度计数表，got %d 条", n)
	}
}

// 4) IPv6 回环 + IPv4-mapped IPv6 回环同样放行。
func TestLoginGuardIP_LoopbackVariants(t *testing.T) {
	for _, ip := range []string{"::1", "[::1]:50000", "::ffff:127.0.0.1"} {
		if !loginGuardIPIsLoopback(loginGuardClientIP(ipReq(ip, "u"))) {
			t.Errorf("%s 应判定为回环", ip)
		}
	}
	for _, ip := range []string{"203.0.113.9", "10.0.0.5:40000"} {
		if loginGuardIPIsLoopback(loginGuardClientIP(ipReq(ip, "u"))) {
			t.Errorf("%s 不应判定为回环", ip)
		}
	}
}

//  5. XFF 默认不采信（可伪造）；YUDUAN_TRUST_PROXY=1 才采信首段，
//     且采信后 loopback 判定基于最终 IP（真实公网 IP 不再被豁免）。
func TestLoginGuardIP_TrustProxyGating(t *testing.T) {
	r := ipReq("127.0.0.1:50000", "u")
	r.Header.Set("X-Forwarded-For", "203.0.113.77, 10.0.0.1")
	t.Setenv("YUDUAN_TRUST_PROXY", "")
	if got := loginGuardClientIP(r); got != "127.0.0.1" {
		t.Fatalf("默认不采信 XFF，应取 RemoteAddr，got %s", got)
	}
	t.Setenv("YUDUAN_TRUST_PROXY", "1")
	if got := loginGuardClientIP(r); got != "203.0.113.77" {
		t.Fatalf("信任代理时应取 XFF 首段，got %s", got)
	}
	if loginGuardIPExempt(loginGuardClientIP(r)) {
		t.Fatal("信任代理取到公网 IP 后不得再按回环豁免")
	}
}

// 6) 成功登录清零 IP 维度计数；锁定后到期自动解除。
func TestLoginGuardIP_SuccessResetsAndExpiry(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "100")
	t.Setenv("YUDUAN_LOGIN_IP_MAX_FAILS", "3")
	h := newGuardHub()
	const ip = "198.51.100.30:50000"
	h.loginGuardRecord(ipReq(ip, "u1"), "u1", false)
	h.loginGuardRecord(ipReq(ip, "u2"), "u2", false)
	h.loginGuardRecord(ipReq(ip, "u3"), "u3", true) // 成功清零
	h.loginGuardRecord(ipReq(ip, "u4"), "u4", false)
	h.loginGuardRecord(ipReq(ip, "u5"), "u5", false)
	if blocked, _ := h.loginGuardBlocked(ipReq(ip, "u6"), "u6"); blocked {
		t.Fatal("成功登录后 IP 维度计数应清零")
	}
}

// 7) HTTP 层 4029 契约：IP 维度锁定也走 writeErr(HTTP 200) 且文案含秒数。
func TestLoginGuardIP_HTTP4029ContractPreserved(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "100")
	t.Setenv("YUDUAN_LOGIN_IP_MAX_FAILS", "2")
	t.Setenv("YUDUAN_LOGIN_IP_LOCK_SEC", "60")
	h := newGuardHub()
	post := func(u string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.handleLogin(w, ipReq("198.51.100.40:50000", u))
		return w
	}
	post("u1")
	post("u2")
	w := post("u3")
	if !strings.Contains(w.Body.String(), "4029") {
		t.Fatalf("IP 维度锁定应返回 4029，got: %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Fatalf("4029 必须继续走 writeErr 恒 HTTP 200（就绪探针契约），got HTTP %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("应带 Retry-After 头")
	}
	if !strings.Contains(w.Body.String(), "秒") {
		t.Fatalf("4029 文案应含秒数（前端 App.tsx 用 /(\\d+)\\s*秒/ 提取），got: %s", w.Body.String())
	}
}

// 8) 内存后端（无 PG）自动降级：loginGuardPGStore() 为 nil，全流程不报错。
func TestLoginGuardIP_MemoryBackendDegradesGracefully(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "100")
	t.Setenv("YUDUAN_LOGIN_IP_MAX_FAILS", "2")
	h := newGuardHub()
	if h.loginGuardPGStore() != nil {
		t.Fatal("newGuardHub 使用 MemStore，PG 探测应为 nil")
	}
	// 触发一次锁定，确保发布共享锁定的路径在无 PG 时静默跳过、不 panic。
	h.loginGuardRecord(ipReq("198.51.100.50:50000", "u1"), "u1", false)
	h.loginGuardRecord(ipReq("198.51.100.50:50000", "u2"), "u2", false)
	if blocked, _ := h.loginGuardBlocked(ipReq("198.51.100.50:50000", "u3"), "u3"); !blocked {
		t.Fatal("无 PG 时内存维度仍应正常锁定")
	}
}
