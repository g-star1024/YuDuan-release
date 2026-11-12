// session_test.go —— v0.4.31-E 会话安全离线单测。
//
// 全部在 auth 包内，复用 auth_test.go 的 memStore / testSecret / strongPW；
// 用 t.Setenv 动态切换开关（sessionEnforceEnabled 每次读 env，故可切换），
// 不依赖任何外部服务 / PostgreSQL / 真实 HTTP，可离线证明。
package auth

import (
	"strings"
	"testing"
	"time"

	"yuduan/internal/crypto"
)

// newSessionSvc 构造：带 memStore + MemSessionStore 的 AuthService（已挂载），
// 并预置一个 admin 账号 alice。开关由各测试自行 t.Setenv 决定。
func newSessionSvc(t *testing.T) (*AuthService, *memStore, *MemSessionStore) {
	t.Helper()
	st := newMemStore()
	sess := NewMemSessionStore()
	svc := NewAuthService(st, testSecret, "test-pepper").WithSessionStore(sess)
	if err := svc.CreateUser("alice", "Alice", RoleAdmin, strongPW); err != nil {
		t.Fatalf("准备 admin 账号失败: %v", err)
	}
	return svc, st, sess
}

// ① 令牌格式一字不改：仍是 body.hexMAC 两段、body 仍 4 段（未塞 session id/jti），
// crypto.VerifyToken 仍能解析；auth_test.go / crypto_test.go 全部保持通过。
func TestSession_TokenFormatUnchanged(t *testing.T) {
	t.Setenv("YUDUAN_SESSION_ENFORCE", "1")
	svc, _, _ := newSessionSvc(t)
	res, err := svc.Login("alice", strongPW)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	parts := strings.Split(res.Token, ".")
	if len(parts) != 2 {
		t.Fatalf("令牌应仅 body.MAC 两段，实际 %d 段（不得新增 jti 段）", len(parts))
	}
	fields := strings.Split(parts[0], "|")
	if len(fields) != 4 {
		t.Fatalf("body 应仍为 username|role|exp|must 四段，实际 %d 段", len(fields))
	}
	c, err := crypto.VerifyToken(testSecret, res.Token)
	if err != nil {
		t.Fatalf("crypto.VerifyToken 解析失败（令牌格式被破坏）: %v", err)
	}
	if c.Username != "alice" || c.Role != RoleAdmin {
		t.Errorf("声明不符: %+v", c)
	}
}

// ② 权限（角色）变更后旧令牌即时失效：guard 用 claims.Role 判权，改角色后旧令牌
// 不再带旧角色继续用满 24h（P2-E 核心缺口）。
func TestSession_RoleChangeRevokesOldToken(t *testing.T) {
	t.Setenv("YUDUAN_SESSION_ENFORCE", "1")
	t.Setenv("YUDUAN_SESSION_LEGACY_ALLOW", "0")
	svc, st, _ := newSessionSvc(t)
	res, err := svc.Login("alice", strongPW)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if _, err := svc.VerifyToken(res.Token); err != nil {
		t.Fatalf("改角色前令牌应有效: %v", err)
	}
	u, _ := st.GetUserByName("alice")
	u.Role = RoleViewer // admin 把 alice 降权
	st.UpsertUser(u)
	if _, err := svc.VerifyToken(res.Token); err == nil {
		t.Fatal("角色变更后旧令牌应被拒（权限变更使旧令牌失效）")
	} else if !strings.Contains(err.Error(), "role changed") {
		t.Errorf("错误信息应指明角色变更，实际: %v", err)
	}
}

// ③ MustChangePW 即时生效：admin 设置强制改密后，旧令牌声明被账号当前状态覆盖，
// guard 随即判为 4033（不再等 24h 或下次登录）。
func TestSession_MustChangePWImmediate(t *testing.T) {
	t.Setenv("YUDUAN_SESSION_ENFORCE", "1")
	t.Setenv("YUDUAN_SESSION_LEGACY_ALLOW", "0")
	svc, _, _ := newSessionSvc(t)
	res, err := svc.Login("alice", strongPW)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if res.MustChangePassword {
		t.Fatal("前提：新建账号不应带强制改密")
	}
	if err := svc.ForcePasswordChange("alice"); err != nil {
		t.Fatalf("设置强制改密失败: %v", err)
	}
	claims, err := svc.VerifyToken(res.Token)
	if err != nil {
		t.Fatalf("强制改密不应使令牌完全失效（应由 guard 判 4033）: %v", err)
	}
	if !claims.MustChange {
		t.Fatal("MustChangePW 应即时覆盖令牌声明（guard 将返回 4033）")
	}
}

// ④ 登出 / 主动吊销后令牌失效：handleLogout → RevokeSession → Revoke(sid)。
func TestSession_LogoutRevokesToken(t *testing.T) {
	t.Setenv("YUDUAN_SESSION_ENFORCE", "1")
	t.Setenv("YUDUAN_SESSION_LEGACY_ALLOW", "0")
	svc, _, _ := newSessionSvc(t)
	res, err := svc.Login("alice", strongPW)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if _, err := svc.VerifyToken(res.Token); err != nil {
		t.Fatalf("登出前令牌应有效: %v", err)
	}
	if !svc.RevokeSession(res.Token) {
		t.Fatal("RevokeSession 应返回 true（sessions 已挂载）")
	}
	if _, err := svc.VerifyToken(res.Token); err == nil {
		t.Fatal("登出吊销后令牌应失效")
	} else if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("错误信息应指明吊销，实际: %v", err)
	}
}

// ⑤ 空闲超时：last_active 距今超过 YUDUAN_SESSION_IDLE_SEC 即拒绝；
// 未超时则放行并刷新 last_active（不挂 WS 心跳，铁律 10）。
func TestSession_IdleTimeout(t *testing.T) {
	t.Setenv("YUDUAN_SESSION_ENFORCE", "1")
	t.Setenv("YUDUAN_SESSION_LEGACY_ALLOW", "0")
	t.Setenv("YUDUAN_SESSION_IDLE_SEC", "60")
	svc, _, sess := newSessionSvc(t)
	res, err := svc.Login("alice", strongPW)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	sid := SessionID(res.Token)

	// 未超时：last_active = now-30（< 60s）
	sess.mu.Lock()
	s0 := sess.m[sid]
	s0.LastActive = time.Now().Unix() - 30
	sess.m[sid] = s0
	sess.mu.Unlock()
	if _, err := svc.VerifyToken(res.Token); err != nil {
		t.Fatalf("空闲 30s（< 60s）应有效: %v", err)
	}

	// 超时：手动把 last_active 拨到 now-61（> 60s）
	sess.mu.Lock()
	s1 := sess.m[sid]
	s1.LastActive = time.Now().Unix() - 61
	sess.m[sid] = s1
	sess.mu.Unlock()
	if _, err := svc.VerifyToken(res.Token); err == nil {
		t.Fatal("空闲超过阈值应失效")
	} else if !strings.Contains(err.Error(), "idle") {
		t.Errorf("错误信息应指明空闲超时，实际: %v", err)
	}
}

// ⑥ legacy_passthrough 宽限：平滑迁移，避免一开启就把所有已登录客户端踢下线。
func TestSession_LegacyPassthrough(t *testing.T) {
	t.Run("legacy_allow_on", func(t *testing.T) {
		t.Setenv("YUDUAN_SESSION_ENFORCE", "1")
		t.Setenv("YUDUAN_SESSION_LEGACY_ALLOW", "1")
		svc, _, sess := newSessionSvc(t)
		// 绕过 Login 直接签一个「开关启用前已存在、无会话记录」的旧令牌
		old := crypto.SignToken(testSecret, "alice", RoleAdmin, time.Now().Add(time.Hour).Unix(), false)
		if _, ok := sess.Get(SessionID(old)); ok {
			t.Fatal("前提：旧令牌不应有会话记录")
		}
		if _, err := svc.VerifyToken(old); err != nil {
			t.Fatalf("legacy 宽限下旧令牌应放行（签名有效+未过期+无记录）: %v", err)
		}
		if _, ok := sess.Get(SessionID(old)); !ok {
			t.Error("legacy 宽限应自动补建会话，平滑纳入管理")
		}
	})
	t.Run("legacy_allow_off_strict", func(t *testing.T) {
		t.Setenv("YUDUAN_SESSION_ENFORCE", "1")
		t.Setenv("YUDUAN_SESSION_LEGACY_ALLOW", "0")
		svc, _, _ := newSessionSvc(t)
		old := crypto.SignToken(testSecret, "alice", RoleAdmin, time.Now().Add(time.Hour).Unix(), false)
		if _, err := svc.VerifyToken(old); err == nil {
			t.Fatal("legacy 关闭（严格模式）下无会话记录的旧令牌应被拒")
		}
	})
}

// ⑦ 开关关闭时行为与现状逐字一致（即便已挂载 SessionStore 也零回归）：
// Login 不建会话；改角色 / 强制改密 / 登出都不改变既有令牌行为。
func TestSession_EnforceOffMatchesLegacy(t *testing.T) {
	t.Setenv("YUDUAN_SESSION_ENFORCE", "0")
	t.Setenv("YUDUAN_SESSION_LEGACY_ALLOW", "0")
	svc, st, sess := newSessionSvc(t)
	res, err := svc.Login("alice", strongPW)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	// (a) 开关关闭：Login 不建会话
	if _, ok := sess.Get(SessionID(res.Token)); ok {
		t.Fatal("开关关闭时 Login 不应创建会话（行为与现状一致）")
	}
	// (b) VerifyToken 通过（会话校验整段跳过）
	if _, err := svc.VerifyToken(res.Token); err != nil {
		t.Fatalf("开关关闭时应走原路径通过: %v", err)
	}
	// (c) 改角色后旧令牌仍有效（① 不生效 = 逐字保持既有行为）
	u, _ := st.GetUserByName("alice")
	u.Role = RoleViewer
	st.UpsertUser(u)
	if _, err := svc.VerifyToken(res.Token); err != nil {
		t.Fatalf("开关关闭时角色变更不应使旧令牌失效（零回归）: %v", err)
	}
	// (d) 强制改密不覆盖 claims.MustChange（② 不生效 = 逐字保持既有行为）
	if err := svc.ForcePasswordChange("alice"); err != nil {
		t.Fatalf("设置强制改密失败: %v", err)
	}
	claims, err := svc.VerifyToken(res.Token)
	if err != nil {
		t.Fatalf("开关关闭时令牌应仍有效: %v", err)
	}
	if claims.MustChange {
		t.Fatal("开关关闭时 MustChangePW 不应覆盖令牌声明（零回归）")
	}
	// (e) 登出不影响令牌有效性（前端「无论成败」清本地态，后端行为不变）
	_ = svc.RevokeSession(res.Token)
	if _, err := svc.VerifyToken(res.Token); err != nil {
		t.Fatalf("开关关闭时登出不应影响令牌有效性（零回归）: %v", err)
	}
}

// ⑧ 探针路径零回归：就绪探针（main.go 回环 POST /api/v1/login，认 200/401）只打
// login；handleLogin 成功 writeJSON(code:0) / 失败 writeErr(401) 均恒 HTTP 200。
// 会话校验只在 VerifyToken（受保护接口），Login 路径零介入、不新增任何拒绝码，
// 且不触碰 loginGuard（不会被锁）。本测试证明 enforce 开/关 Login 返回逐字一致。
func TestSession_ProbePathUnaffected(t *testing.T) {
	for _, enforce := range []string{"0", "1"} {
		t.Setenv("YUDUAN_SESSION_ENFORCE", enforce)
		svc, _, _ := newSessionSvc(t)
		// 成功登录：token 结构完整、可被 crypto 解析（handleLogin → writeJSON code:0 → HTTP 200）
		res, err := svc.Login("alice", strongPW)
		if err != nil {
			t.Fatalf("enforce=%s 登录失败: %v", enforce, err)
		}
		if _, err := crypto.VerifyToken(testSecret, res.Token); err != nil {
			t.Fatalf("enforce=%s 令牌格式异常: %v", enforce, err)
		}
		// 失败登录：err 语义为 invalid credentials（handleLogin → writeErr 401 → HTTP 200）
		if _, err := svc.Login("alice", "Wr0ngPassword!"); err == nil || !strings.Contains(err.Error(), "invalid credentials") {
			t.Fatalf("enforce=%s 失败登录错误语义异常: %v", enforce, err)
		}
	}
}

// ⑨ RevokeUser 能力：改密 / 重置密码后吊销该账号全部会话（其它标签页 / 已泄露旧令牌
// 即时失效），且不影响其它账号。对应 auth.ChangePassword / ResetPassword 的接入。
func TestSession_RevokeUserDropsAllSessions(t *testing.T) {
	t.Setenv("YUDUAN_SESSION_ENFORCE", "1")
	t.Setenv("YUDUAN_SESSION_LEGACY_ALLOW", "0")
	svc, _, sess := newSessionSvc(t)
	if err := svc.CreateUser("bob", "Bob", RoleViewer, strongPW); err != nil {
		t.Fatalf("准备 bob 账号失败: %v", err)
	}
	// 手动构造同一账号两条不同 sid 的会话（不同 exp）+ 另一账号一条，模拟多标签页
	mk := func(user, role string, d time.Duration) string {
		exp := time.Now().Add(d).Unix()
		tok := crypto.SignToken(testSecret, user, role, exp, false)
		now := time.Now().Unix()
		_ = sess.Create(Session{SID: SessionID(tok), Username: user, Role: role,
			IssuedAt: now, LastActive: now, ExpiresAt: exp, Revoked: false})
		return tok
	}
	a1 := mk("alice", RoleAdmin, time.Hour)
	a2 := mk("alice", RoleAdmin, 2*time.Hour)
	b1 := mk("bob", RoleViewer, time.Hour)
	for _, tk := range []string{a1, a2, b1} {
		if _, err := svc.VerifyToken(tk); err != nil {
			t.Fatalf("初始会话应有效: %v", err)
		}
	}
	if err := svc.sessions.RevokeUser("alice"); err != nil {
		t.Fatalf("RevokeUser 失败: %v", err)
	}
	for _, tk := range []string{a1, a2} {
		if _, err := svc.VerifyToken(tk); err == nil {
			t.Error("alice 的全部会话应被吊销")
		}
	}
	if _, err := svc.VerifyToken(b1); err != nil {
		t.Errorf("bob 的会话不应受 alice 的 RevokeUser 影响: %v", err)
	}
}
