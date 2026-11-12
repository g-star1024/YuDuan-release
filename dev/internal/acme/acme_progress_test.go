package acme

// v0.4.27 F-06 回归：证明「进度日志真的会输出」，
// 尤其是 429/503 的 retryAfter 等待点（真机 20s 黑洞时屏幕全空的直接成因）。
// 不修改 acme.go 的任何流程，仅观察 log 输出。

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureACMELogs 临时把标准 logger 指到 buffer，测试结束自动还原。
// 本包所有测试均不使用 t.Parallel，故全局 logger 交换是安全的。
func captureACMELogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
}

// TestACMEProgress_StageLogsOnEarlyFailure 证明 Issue 在「拉取 Directory 立刻失败」
// 的最坏场景也已经打印开始 + 1/8 阶段日志，不再是全程零输出。
func TestACMEProgress_StageLogsOnEarlyFailure(t *testing.T) {
	buf := captureACMELogs(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Issue(Options{
		Domain:       "example.com",
		Email:        "admin@example.com",
		DirectoryURL: srv.URL,
		CertsDir:     t.TempDir(),
		HTTPListen:   "127.0.0.1:0",
	})
	if err == nil {
		t.Fatal("Directory 返回 500 时 Issue 应失败")
	}
	out := buf.String()
	for _, want := range []string{
		"[acme] 开始签发",
		"HTTP-01 监听",
		"输出目录",
		"[acme] 1/8 拉取 ACME Directory",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("进度日志缺少 %q；实际输出:\n%s", want, out)
		}
	}
	// v0.4.28 O-01：库内起始行必须恰好一条（信息已合并，不再依赖 CLI 补打）。
	if n := strings.Count(out, "[acme] 开始签发"); n != 1 {
		t.Errorf("起始日志应恰好 1 条，实得 %d；实际输出:\n%s", n, out)
	}
}

// TestACMEProgress_RetryAfterWaitIsLogged 证明 GET 遇到 429 时，
// 会打印「等待 N 秒，第 k 次重试」——这是 team-lead 明确要求的等待点覆盖。
func TestACMEProgress_RetryAfterWaitIsLogged(t *testing.T) {
	buf := captureACMELogs(t)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	c := &client{http: &http.Client{Timeout: 5 * time.Second}, userAgent: userAgent}
	st, _, _, err := c.get(srv.URL, "")
	if err != nil {
		t.Fatalf("get 出错: %v", err)
	}
	if st != http.StatusOK {
		t.Fatalf("重试后应拿到 200，实得 %d", st)
	}
	if calls != 2 {
		t.Fatalf("应恰好 2 次请求（首次 429 + 1 次重试），实得 %d", calls)
	}
	if !strings.Contains(buf.String(), "等待 1 秒，第 1 次重试") {
		t.Errorf("429 等待点必须输出进度日志；实际输出:\n%s", buf.String())
	}
}

// TestACMEProgress_PostRetryAfterWaitIsLogged 同上，覆盖 POST 路径的 503 等待点。
func TestACMEProgress_PostRetryAfterWaitIsLogged(t *testing.T) {
	buf := captureACMELogs(t)
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// 第 2 次是 refreshNonce（GET newNonce），第 3 次是重试的 POST。
		if r.Method == http.MethodGet {
			w.Header().Set("Replay-Nonce", "test-nonce")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Replay-Nonce", "test-nonce-2")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	c := &client{
		http:       &http.Client{Timeout: 5 * time.Second},
		userAgent:  userAgent,
		nonce:      "initial-nonce",
		accountKey: mustTestECDSAKey(t),
		dir:        directory{NewNonce: srv.URL + "/nonce"},
	}
	_, _, _, err := c.post(srv.URL+"/acct", false, []byte("{}"))
	if err != nil {
		t.Fatalf("post 出错: %v", err)
	}
	if !strings.Contains(buf.String(), "等待 1 秒，第 1 次重试") {
		t.Errorf("503 等待点必须输出进度日志；实际输出:\n%s", buf.String())
	}
}

// mustTestECDSAKey 复用 acme_test.go 同一套 P-256 生成逻辑的最小替身。
func mustTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	return k
}
