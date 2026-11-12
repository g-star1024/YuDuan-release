package auth

import (
	"strings"
	"testing"
	"time"

	"yuduan/internal/crypto"
)

// 本文件补齐复盘（v0.2.6 全面复盘）点名的测试盲区 TOP5 第 4 条：
// 「auth 包整体 0 测试（S-6/S-10 漏网原因）」。
//
// 覆盖：S-6（空密钥 fail-closed）、S-10（禁用账号须即时踢会话）、RBAC 权限矩阵、
// 口令强度口径（复盘曾指出前后端口径冲突：8 位 vs 10 位，此处锁定后端 10 位/3 类）。

// memStore 测试用内存账号仓储（不引入生产 store 依赖，保证 auth 包单测自洽）。
type memStore struct{ users map[string]User }

func newMemStore() *memStore { return &memStore{users: make(map[string]User)} }

func (m *memStore) UpsertUser(u User)                   { m.users[u.Username] = u }
func (m *memStore) GetUserByName(n string) (User, bool) { u, ok := m.users[n]; return u, ok }
func (m *memStore) ListUsers() []User {
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	return out
}
func (m *memStore) Count() int { return len(m.users) }

const testSecret = "unit-test-secret-not-for-production"
const strongPW = "Str0ngPass!2026" // ≥10 位，含大/小/数字/符号四类

// newSvc 构造带一个 admin 账号的认证服务。
func newSvc(t *testing.T) (*AuthService, *memStore) {
	t.Helper()
	st := newMemStore()
	svc := NewAuthService(st, testSecret, "test-pepper")
	if err := svc.CreateUser("alice", "Alice", RoleAdmin, strongPW); err != nil {
		t.Fatalf("准备 admin 账号失败: %v", err)
	}
	return svc, st
}

// TestVerifyToken_S6_NoSecretFailClosed 复盘 S-6：secret 为空时不得回退公开常量密钥，
// 登录与验签一律拒绝（此前任何读到源码者即可伪造 admin 令牌）。
func TestVerifyToken_S6_NoSecretFailClosed(t *testing.T) {
	st := newMemStore()
	svc := NewAuthService(st, "", "pepper") // 无密钥

	if _, err := svc.Login("alice", strongPW); err == nil {
		t.Error("S-6 回归：无密钥时 Login 应拒绝")
	}
	// 即便给出一个结构完整、用空密钥签出的令牌，也必须拒绝
	forged := crypto.SignToken("", "alice", RoleAdmin, time.Now().Add(time.Hour).Unix(), false)
	if _, err := svc.VerifyToken(forged); err == nil {
		t.Error("S-6 回归：无密钥时 VerifyToken 应拒绝（空密钥可伪造令牌）")
	}
}

// TestVerifyToken_S10_DisabledRevokesSession 复盘 S-10：账号被禁用后，其**已签发且未
// 过期**的令牌必须立即失效。此前 VerifyToken 只验签，禁用仅影响下次登录，
// 既有令牌最长 24h 仍可全权限操作。
func TestVerifyToken_S10_DisabledRevokesSession(t *testing.T) {
	svc, st := newSvc(t)

	res, err := svc.Login("alice", strongPW)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if _, err := svc.VerifyToken(res.Token); err != nil {
		t.Fatalf("禁用前令牌应有效: %v", err)
	}

	// 管理员禁用账号（人员离职/账号失陷场景）
	u, _ := st.GetUserByName("alice")
	u.Disabled = true
	st.UpsertUser(u)

	// 注意：此处不可写成 `if _, err := ...; err == nil` —— 该 err 会遮蔽外层 Login 的
	// err，后续断言将引用到 nil 的登录错误（编译通过但语义错误，曾致空指针 panic）。
	_, verr := svc.VerifyToken(res.Token)
	if verr == nil {
		t.Fatal("S-10 回归失败：账号禁用后既有令牌仍被接受，权限无法即时收回")
	}
	if !strings.Contains(verr.Error(), "disabled") {
		t.Errorf("错误信息应指明禁用原因，实际: %v", verr)
	}

	// 账号被彻底删除同样必须失效
	delete(st.users, "alice")
	if _, err := svc.VerifyToken(res.Token); err == nil {
		t.Error("S-10 回归失败：账号删除后既有令牌仍被接受")
	}
}

// TestVerifyToken_HappyPath 正常令牌可解析出正确声明（防止 S-10 修复误伤正常链路）。
func TestVerifyToken_HappyPath(t *testing.T) {
	svc, _ := newSvc(t)
	res, err := svc.Login("alice", strongPW)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	claims, err := svc.VerifyToken(res.Token)
	if err != nil {
		t.Fatalf("有效令牌被拒（S-10 修复误伤）: %v", err)
	}
	if claims.Username != "alice" || claims.Role != RoleAdmin {
		t.Errorf("声明不符: %+v", claims)
	}
	if claims.Exp <= time.Now().Unix() {
		t.Error("令牌有效期异常（应 24h）")
	}
	if res.MustChangePassword {
		t.Error("新建账号不应带强制改密标记")
	}
}

// TestVerifyToken_StoreNilSkipsRevocation store 为 nil 时跳过账号回查，保持既有行为。
func TestVerifyToken_StoreNilSkipsRevocation(t *testing.T) {
	svc := NewAuthService(nil, testSecret, "pepper")
	tok := crypto.SignToken(testSecret, "bob", RoleAdmin, time.Now().Add(time.Hour).Unix(), false)
	if _, err := svc.VerifyToken(tok); err != nil {
		t.Errorf("store 为 nil 时应跳过回查并保持通过: %v", err)
	}
}

// TestHasPerm_RBACMatrix 锁住三角色权限矩阵，尤其 W2-4 设计意图：
// operator 可发起远控（PermRCSession），但敏感设备二级审批 PermRCApprove 仅 admin。
func TestHasPerm_RBACMatrix(t *testing.T) {
	svc := NewAuthService(nil, testSecret, "pepper")
	cases := []struct {
		role, perm string
		want       bool
		why        string
	}{
		{RoleAdmin, PermUserManage, true, "用户管理仅 admin"},
		{RoleOperator, PermUserManage, false, "operator 不得管理账号"},
		{RoleViewer, PermUserManage, false, "viewer 只读"},
		{RoleAdmin, PermRCApprove, true, "W2-4：敏感设备审批仅 admin"},
		{RoleOperator, PermRCApprove, false, "W2-4：发起与审批分离"},
		{RoleOperator, PermRCSession, true, "operator 可发起远控"},
		{RoleOperator, PermDeviceCmd, true, "operator 可下发指令"},
		{RoleViewer, PermDeviceCmd, false, "viewer 不得下发指令"},
		{RoleViewer, PermDeviceView, true, "viewer 可查看设备"},
		{RoleViewer, PermAuditView, true, "viewer 可查看审计"},
		{RoleViewer, PermSoftwareMgmt, false, "viewer 不得管理软件"},
		{"unknown-role", PermDeviceView, false, "未知角色一律无权限"},
	}
	for _, c := range cases {
		if got := svc.HasPerm(c.role, c.perm); got != c.want {
			t.Errorf("HasPerm(%s,%s)=%v，期望 %v（%s）", c.role, c.perm, got, c.want, c.why)
		}
	}
	if !ValidRole(RoleAdmin) || !ValidRole(RoleOperator) || !ValidRole(RoleViewer) {
		t.Error("三个内置角色应均为合法角色")
	}
	if ValidRole("root") {
		t.Error("未知角色不应判为合法")
	}
}

// TestValidatePasswordStrength 锁定后端口令强度口径为「≥10 位 + 大/小/数字/符号至少 3 类」
// （复盘曾指出前端 8 位与后端 10 位口径冲突；此处固化后端为权威口径）。
func TestValidatePasswordStrength(t *testing.T) {
	cases := []struct {
		pw   string
		want bool
		why  string
	}{
		{"Abc123!!!!", true, "10 位 + 大/小/数字/符号 4 类"},
		{"Abc12!!!!", false, "仅 9 位，不足 10 位"},
		{"abcdefghij", false, "仅小写 1 类"},
		{"ABCDEFGHIJ", false, "仅大写 1 类"},
		{"Abcdefghij", false, "大+小 仅 2 类（复盘口径要求 ≥3 类）"},
		{"Abc1234567", true, "大/小/数字 3 类且 10 位"},
		{"", false, "空口令"},
	}
	for _, c := range cases {
		err := ValidatePasswordStrength(c.pw)
		if (err == nil) != c.want {
			t.Errorf("ValidatePasswordStrength(%q) err=%v，期望通过=%v（%s）", c.pw, err, c.want, c.why)
		}
	}
}

// TestLogin_DisabledAndBadPassword 登录路径的负向用例（禁用账号/错口令/不存在账号）。
func TestLogin_DisabledAndBadPassword(t *testing.T) {
	svc, st := newSvc(t)
	u, _ := st.GetUserByName("alice")
	u.Disabled = true
	st.UpsertUser(u)

	if _, err := svc.Login("alice", strongPW); err == nil {
		t.Error("禁用账号不应能登录")
	}
	st.users["alice"] = User{Username: "alice", Role: RoleAdmin, Password: crypto.HashPassword(strongPW, "test-pepper")}
	if _, err := svc.Login("alice", "Wr0ngPassword!"); err == nil {
		t.Error("错误口令不应能登录")
	}
	if _, err := svc.Login("ghost", strongPW); err == nil {
		t.Error("不存在账号不应能登录")
	}
	// 错误信息不区分"账号不存在/口令错误"，避免账号枚举
	if _, e1 := svc.Login("ghost", strongPW); e1 != nil && !strings.Contains(e1.Error(), "invalid credentials") {
		t.Errorf("账号不存在应返回通用凭据错误以免枚举，实际: %v", e1)
	}
}

// TestTokenFromHeader Authorization 头解析。
func TestTokenFromHeader(t *testing.T) {
	cases := map[string]string{
		"Bearer abc.def":    "abc.def",
		"Bearer  abc.def  ": "abc.def",
		"Basic abc.def":     "",
		"":                  "",
		"bearer abc.def":    "",
	}
	for in, want := range cases {
		if got := TokenFromHeader(in); got != want {
			t.Errorf("TokenFromHeader(%q)=%q，期望 %q", in, got, want)
		}
	}
}
