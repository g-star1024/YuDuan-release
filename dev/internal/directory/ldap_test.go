package directory

import (
	"testing"

	"yuduan/internal/auth"
	"yuduan/internal/ldap"
	"yuduan/internal/store"
)

// mockADUsers 与 directory-sample.json 等价，含一个禁用账户（eve）。
func mockADUsers() []ldap.MockUser {
	return []ldap.MockUser{
		{Username: "alice", DisplayName: "Alice Admin", Email: "alice@corp.local", MemberOf: []string{"yd-admins"}, Password: "Alice@2026"},
		{Username: "bob", DisplayName: "Bob Operator", Email: "bob@corp.local", MemberOf: []string{"yd-operators"}, Password: "Bob@2026"},
		{Username: "carol", DisplayName: "Carol Viewer", Email: "carol@corp.local", MemberOf: []string{"yd-viewers"}, Password: "Carol@2026"},
		{Username: "dave", DisplayName: "Dave Default", Email: "dave@corp.local", MemberOf: nil, Password: "Dave@2026"},
		{Username: "eve", DisplayName: "Eve Disabled", Email: "eve@corp.local", MemberOf: []string{"yd-viewers"}, Disabled: true, Password: "Eve@2026"},
	}
}

func startMockAD(t *testing.T) *ldap.MockServer {
	t.Helper()
	srv, err := ldap.NewMockServer("cn=admin,dc=corp,dc=local", "admin-pass", "dc=corp,dc=local", mockADUsers())
	if err != nil {
		t.Fatalf("mock server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func TestLDAPBindAndSync(t *testing.T) {
	srv := startMockAD(t)
	dir := NewLDAPDirectory(LDAPConfig{
		Host: "127.0.0.1", Port: srv.Port,
		BindDN: "cn=admin,dc=corp,dc=local", BindPwd: "admin-pass",
		BaseDN: "dc=corp,dc=local",
	})
	us := store.NewMemUserStore()
	eng := NewSyncEngine(dir, DefaultRoleMapping(), us, "pepper")
	res, err := eng.Sync()
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// LDAP 路径：禁用账户在搜索过滤器层即被排除（userAccountControl 位 2），
	// 故 UsersSynced=4、Skipped=0；FileDirectory 路径才走 SyncEngine 的 Disabled 跳过。
	if res.UsersSynced != 4 || res.Skipped != 0 {
		t.Fatalf("unexpected sync result: %+v", res)
	}
	want := map[string]string{"alice": auth.RoleAdmin, "bob": auth.RoleOperator, "carol": auth.RoleViewer, "dave": auth.RoleViewer}
	for name, role := range want {
		u, ok := us.GetUserByName(name)
		if !ok {
			t.Fatalf("user %s missing after sync", name)
		}
		if u.Role != role {
			t.Fatalf("user %s role=%s want %s", name, u.Role, role)
		}
		if !u.MustChangePW {
			t.Fatalf("user %s should require password change", name)
		}
		if u.Source != "directory" {
			t.Fatalf("user %s source=%s want directory", name, u.Source)
		}
	}
	if _, ok := us.GetUserByName("eve"); ok {
		t.Fatal("disabled user eve must not be synced")
	}
}

func TestLDAPBindFailure(t *testing.T) {
	srv := startMockAD(t)
	dir := NewLDAPDirectory(LDAPConfig{
		Host: "127.0.0.1", Port: srv.Port,
		BindDN: "cn=admin,dc=corp,dc=local", BindPwd: "WRONG-PASSWORD",
		BaseDN: "dc=corp,dc=local",
	})
	if _, err := dir.ListUsers(); err == nil {
		t.Fatal("bind with wrong password must fail")
	}
}

func TestLDAPReSyncKeepsPassword(t *testing.T) {
	srv := startMockAD(t)
	dir := NewLDAPDirectory(LDAPConfig{
		Host: "127.0.0.1", Port: srv.Port,
		BindDN: "cn=admin,dc=corp,dc=local", BindPwd: "admin-pass",
		BaseDN: "dc=corp,dc=local",
	})
	us := store.NewMemUserStore()
	eng := NewSyncEngine(dir, DefaultRoleMapping(), us, "pepper")
	if _, err := eng.Sync(); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	before, _ := us.GetUserByName("alice")
	if _, err := eng.Sync(); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	after, _ := us.GetUserByName("alice")
	if after.Password != before.Password {
		t.Fatal("re-sync must not reset existing user's password")
	}
}
