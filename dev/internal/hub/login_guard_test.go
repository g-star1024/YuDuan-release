package hub

// v0.4.25 登录防爆破回归：核心是证明「默认关闭 = 局域网行为一字未改」，
// 以及显式开启后的锁定 / 成功清零 / 按来源 IP 隔离 / HTTP 层 4029 拦截。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newGuardHub() *Hub {
	return NewHub(HubConfig{HMACSecret: "secret-guard", HubID: "hub-guard-test"})
}

func guardReq(ip string) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
	r.RemoteAddr = ip
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestLoginGuard_DefaultOff_LANUnchanged(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "")
	h := newGuardHub()
	r := guardReq("10.0.0.5:50000")
	for i := 0; i < 40; i++ {
		h.loginGuardRecord(r, "admin", false)
	}
	if blocked, _ := h.loginGuardBlocked(r, "admin"); blocked {
		t.Fatal("默认未开启时，局域网连续失败不应触发任何锁定（零影响铁律）")
	}
}

func TestLoginGuard_LockAfterThreshold(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "3")
	t.Setenv("YUDUAN_LOGIN_LOCK_SEC", "60")
	h := newGuardHub()
	r := guardReq("203.0.113.9:40000")
	for i := 0; i < 2; i++ {
		h.loginGuardRecord(r, "admin", false)
	}
	if blocked, _ := h.loginGuardBlocked(r, "admin"); blocked {
		t.Fatal("未达阈值不应锁定")
	}
	h.loginGuardRecord(r, "admin", false)
	blocked, retry := h.loginGuardBlocked(r, "admin")
	if !blocked {
		t.Fatal("达到阈值后应锁定")
	}
	if retry < 1 || retry > 60 {
		t.Fatalf("重试秒数应在 (0,60]，got %d", retry)
	}
}

func TestLoginGuard_SuccessResetsCounter(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "3")
	h := newGuardHub()
	r := guardReq("203.0.113.10:40000")
	h.loginGuardRecord(r, "admin", false)
	h.loginGuardRecord(r, "admin", false)
	h.loginGuardRecord(r, "admin", true) // 成功登录清零
	h.loginGuardRecord(r, "admin", false)
	h.loginGuardRecord(r, "admin", false)
	if blocked, _ := h.loginGuardBlocked(r, "admin"); blocked {
		t.Fatal("成功后计数应清零，不应累积到锁定")
	}
}

func TestLoginGuard_PerSourceIPIsolation(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "2")
	h := newGuardHub()
	a := guardReq("203.0.113.11:40000")
	b := guardReq("203.0.113.12:40000")
	h.loginGuardRecord(a, "admin", false)
	h.loginGuardRecord(a, "admin", false)
	if blocked, _ := h.loginGuardBlocked(a, "admin"); !blocked {
		t.Fatal("来源 A 应被锁定")
	}
	if blocked, _ := h.loginGuardBlocked(b, "admin"); blocked {
		t.Fatal("来源 B 不应被 A 的失败牵连（避免整网登不上）")
	}
}

func TestLoginGuard_HTTPReturns4029AndNoToken(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "2")
	h := newGuardHub()
	post := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.handleLogin(w, guardReq("203.0.113.13:40000"))
		return w
	}
	post()
	post() // 第 2 次失败触发锁定，但本次仍返回 401
	w := post()
	if !strings.Contains(w.Body.String(), "4029") {
		t.Fatalf("锁定后应返回 4029，got: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"token"`) {
		t.Fatal("锁定时不得签发 token")
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("应带 Retry-After 头")
	}
}

// ---- v0.4.27 F-04：回环豁免取消后的三条回归守卫 ----
// 说明：以下用例不使用 t.Parallel（t.Setenv 与全局 log 状态不兼容并行）。
// 关键契约：4029 仍走 writeErr（HTTP 200），不是真实 429；就绪探针只认 200/401。

// TestLoginGuard_LoopbackLocksAtThreshold 证明回环来源不再被无条件放行：
// 连续失败达默认阈值 5 后必须锁定，并经 HTTP 层返回业务码 4029。
func TestLoginGuard_LoopbackLocksAtThreshold(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "5")
	t.Setenv("YUDUAN_LOGIN_LOCK_SEC", "60")
	h := newGuardHub()
	const loopback = "127.0.0.1:50000"
	post := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.handleLogin(w, guardReq(loopback))
		return w
	}
	for i := 0; i < 5; i++ { // 5 次失败触发锁定；每次仍返回 401
		w := post()
		if !strings.Contains(w.Body.String(), "401") {
			t.Fatalf("第 %d 次失败应返回业务码 401，got: %s", i+1, w.Body.String())
		}
	}
	if blocked, _ := h.loginGuardBlocked(guardReq(loopback), "admin"); !blocked {
		t.Fatal("回环来源达阈值后应被锁定（F-04：回环不再豁免）")
	}
	w := post()
	if !strings.Contains(w.Body.String(), "4029") {
		t.Fatalf("锁定后应返回 4029，got: %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Fatalf("4029 必须继续走 writeErr 恒 HTTP 200，严禁改成真实 429，got HTTP %d", w.Code)
	}
	if strings.Contains(w.Body.String(), `"token"`) {
		t.Fatal("锁定时不得签发 token")
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("应带 Retry-After 头")
	}
}

// TestLoginGuard_ReadyProbeSingleFailureNotLocked 模拟 cmd/hub/main.go 的就绪探针：
// 回环 POST /api/v1/login 单次失败（admin 已改密的最坏情况）。writeErr 恒 HTTP 200
// → 探针第 1 次即 break，最多只记 1 次失败，远不达阈值 5；且探针可继续服务。
func TestLoginGuard_ReadyProbeSingleFailureNotLocked(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "1")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "5")
	t.Setenv("YUDUAN_LOGIN_LOCK_SEC", "60")
	h := newGuardHub()
	const loopback = "127.0.0.1:50001"

	probe := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.handleLogin(w, guardReq(loopback))
		return w
	}
	w := probe() // 探针第 1 次（真实实现拿到 200 后立即 break）
	if w.Code != http.StatusOK {
		t.Fatalf("探针响应必须是 HTTP 200（writeErr），否则探针会走满 120×500ms，got HTTP %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "4029") {
		t.Fatalf("单次失败绝不应返回 4029，got: %s", w.Body.String())
	}
	if blocked, _ := h.loginGuardBlocked(guardReq(loopback), "admin"); blocked {
		t.Fatal("探针单次失败不应触发锁定")
	}
	// 白盒核对：恰好 1 次失败计数（证明「最多记 1 次」而非 0 次误放行）。
	st := h.loginGuardState()
	st.mu.Lock()
	e := st.entries[loginGuardKey(guardReq(loopback), "admin")]
	fails := 0
	if e != nil {
		fails = e.fails
	}
	st.mu.Unlock()
	if fails != 1 {
		t.Fatalf("探针单次失败应恰好记 1 次，got %d", fails)
	}
	// 探针可继续：即便因故重复几次，也远不达阈值、不会被锁、也不会返回 4029。
	for i := 0; i < 3; i++ {
		w2 := probe()
		if w2.Code != http.StatusOK || strings.Contains(w2.Body.String(), "4029") {
			t.Fatalf("探针第 %d 次重复不应被锁，got HTTP %d body %s", i+2, w2.Code, w2.Body.String())
		}
	}
	if blocked, _ := h.loginGuardBlocked(guardReq(loopback), "admin"); blocked {
		t.Fatal("探针重复 4 次（< 阈值 5）仍不应被锁定")
	}
}

// TestLoginGuard_LANDefaultOff_LoopbackUnchanged 是铁律「LAN 零回归」硬断言：
// guard 默认关闭时，回环来源既不计数也不锁定，HTTP 层永不出现 4029。
func TestLoginGuard_LANDefaultOff_LoopbackUnchanged(t *testing.T) {
	t.Setenv("YUDUAN_LOGIN_GUARD", "")
	t.Setenv("YUDUAN_LOGIN_MAX_FAILS", "2") // 故意设极低阈值：一旦误计数就会立刻锁定
	h := newGuardHub()
	const loopback = "127.0.0.1:50002"
	for i := 0; i < 40; i++ {
		w := httptest.NewRecorder()
		h.handleLogin(w, guardReq(loopback))
		if strings.Contains(w.Body.String(), "4029") {
			t.Fatalf("LAN 默认关闭时第 %d 次请求不应出现 4029", i+1)
		}
	}
	if blocked, _ := h.loginGuardBlocked(guardReq(loopback), "admin"); blocked {
		t.Fatal("LAN 默认 guard 关闭时不应锁定回环来源")
	}
	st := h.loginGuardState()
	st.mu.Lock()
	n := len(st.entries)
	st.mu.Unlock()
	if n != 0 {
		t.Fatalf("LAN 默认 guard 关闭时不得计数，got %d 条记录", n)
	}
}
