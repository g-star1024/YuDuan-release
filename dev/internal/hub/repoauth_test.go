package hub

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/proto"
)

// TestRepoDownloadAuth：P-4 投产阻断——仓库下载端点此前无鉴权（hub.go 自认"演示放开"），
// 内网任意主机可拉全部安装包。修复后：
//   - 无令牌 → 真实 HTTP 401
//   - 无效 st（短时下载令牌）→ 401
//   - 过期 st → 401
//   - 有效 st（副端分发路径）→ 200 且正文一致
//   - 有效会话 token（主端/控制台）→ 200
//   - 路径遍历 id（`..`）→ 404（不被 filepath.Join 逃逸）
//
// 注意：本端点为二进制下载，鉴权失败返回真实 HTTP 状态码（非 writeErr 的 200+code 约定），
// 否则副端下载器（cmd/agent/swdist.go 仅判 StatusCode!=200）会把错误 JSON 当安装包落盘。
func TestRepoDownloadAuth(t *testing.T) {
	const secret = "repoauth-test-secret"
	const pw = "Str0ng-Passw0rd!"
	repoDir := t.TempDir()
	payload := []byte("yuduan-repo-payload-v1")
	id := "sw-p4-01"
	if err := os.WriteFile(filepath.Join(repoDir, id), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	h := NewHub(HubConfig{HMACSecret: secret, RepoDir: repoDir})
	h.mu.Lock()
	h.software[id] = &proto.SoftwareItem{
		ID: id, Name: "demo", Version: "1.0.0", Platform: "any",
		FileName: "demo.zip", Size: int64(len(payload)), UploadedAt: 1,
	}
	h.mu.Unlock()

	h.users.UpsertUser(auth.User{
		Username: "admin", Role: auth.RoleAdmin,
		Password: crypto.HashPassword(pw, "yuduan-dev-pepper"),
	})
	login, err := h.authSvc.Login("admin", pw)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	get := func(path string) int {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	getBody := func(path string) string {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf := make([]byte, len(payload)*2)
		n, _ := resp.Body.Read(buf)
		return string(buf[:n])
	}

	cases := []struct {
		name string
		path string
		want int
	}{
		{"无令牌", "/api/v1/repo/" + id, 401},
		{"无效st", "/api/v1/repo/" + id + "?st=bad_token", 401},
		{"过期st", "/api/v1/repo/" + id + "?st=" + h.repoDownloadToken(id, -time.Minute), 401},
		{"有效st", "/api/v1/repo/" + id + "?st=" + h.repoDownloadToken(id, time.Minute), 200},
		{"会话token", "/api/v1/repo/" + id + "?token=" + login.Token, 200},
		{"路径遍历", "/api/v1/repo/..%2fsecret", 404},
		{"空id", "/api/v1/repo/", 404},
	}
	for _, c := range cases {
		if got := get(c.path); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}

	// 有效 st 正文必须与仓库文件一致（鉴权不破坏下载正确性）
	if body := getBody("/api/v1/repo/" + id + "?st=" + h.repoDownloadToken(id, time.Minute)); body != string(payload) {
		t.Fatalf("有效 st 下载正文不一致: got %q want %q", body, string(payload))
	}
}

// TestRepoDownloadToken_Roundtrip：令牌生成/校验往返 + 跨 id 隔离（令牌只对该 repoID 有效）。
func TestRepoDownloadToken_Roundtrip(t *testing.T) {
	h := NewHub(HubConfig{HMACSecret: "rt-secret"})
	tok := h.repoDownloadToken("sw-a", 5*time.Minute)
	if !h.verifyRepoDownloadToken("sw-a", tok) {
		t.Fatal("同 id 令牌应校验通过")
	}
	if h.verifyRepoDownloadToken("sw-b", tok) {
		t.Fatal("令牌不得跨 id 复用（HMAC 绑定 repoID）")
	}
	// 格式不合法
	if h.verifyRepoDownloadToken("sw-a", "no_underscore") {
		t.Fatal("非法格式应拒绝")
	}
	if h.verifyRepoDownloadToken("sw-a", "abc_def") {
		t.Fatal("非数字 exp 应拒绝")
	}
}

// TestAppendRepoToken：st 令牌附加——无查询串用 ?；已有查询串合并（net/url 排序）；幂等去旧 st。
func TestAppendRepoToken(t *testing.T) {
	if got := appendRepoToken("http://hub:8080/api/v1/repo/sw-x", "123_abc"); got != "http://hub:8080/api/v1/repo/sw-x?st=123_abc" {
		t.Fatalf("无查询串: got %q", got)
	}
	if got := appendRepoToken("http://hub:8080/api/v1/repo/sw-x?token=t", "123_abc"); got != "http://hub:8080/api/v1/repo/sw-x?st=123_abc&token=t" {
		t.Fatalf("已有查询串: got %q", got)
	}
	// 幂等：已带旧 st 时替换而非叠加
	if got := appendRepoToken("http://hub:8080/api/v1/repo/sw-x?st=old&token=t", "new"); got != "http://hub:8080/api/v1/repo/sw-x?st=new&token=t" {
		t.Fatalf("去旧st: got %q", got)
	}
}
