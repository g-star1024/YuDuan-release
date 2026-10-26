// Package auth 实现御端 M6 管理与审计所需的身份认证与 RBAC。
// 角色：admin（全部权限）/ operator（运维操作）/ viewer（只读）。
// 仅依赖标准库，登录令牌由 internal/crypto 签发。
package auth

import (
	"strings"
	"time"

	"yuduan/internal/crypto"
)

// 角色定义。
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// 权限点（用于接口级门禁）。
const (
	PermDeviceView   = "device:view"
	PermDeviceCmd    = "device:command"
	PermRCSession    = "rc:session"
	PermSoftwareMgmt = "software:manage"
	PermAuditView    = "audit:view"
	PermUserManage   = "user:manage"
	PermDirSync      = "dir:sync"
)

// rolePerms 定义各角色拥有的权限集合。
var rolePerms = map[string]map[string]bool{
	RoleAdmin:    {PermDeviceView: true, PermDeviceCmd: true, PermRCSession: true, PermSoftwareMgmt: true, PermAuditView: true, PermUserManage: true, PermDirSync: true},
	RoleOperator: {PermDeviceView: true, PermDeviceCmd: true, PermRCSession: true, PermSoftwareMgmt: true, PermAuditView: true},
	RoleViewer:   {PermDeviceView: true, PermAuditView: true},
}

// User 表示一个后台账号。
type User struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Password    string `json:"-"` // 仅存储摘要
	Disabled    bool   `json:"disabled"`
	// MustChangePW 为 true 时，登录后仅允许调用改密接口，其余一律 403。
	MustChangePW bool   `json:"must_change_password"`
	Source       string `json:"source"` // local=本地账号 / directory=目录同步
}

// UserStore 账号持久化接口；内存与 PostgreSQL 两种实现都遵循它。
type UserStore interface {
	UpsertUser(u User)
	GetUserByName(name string) (User, bool)
	ListUsers() []User
	Count() int
}

// AuthService 提供登录与令牌校验。
type AuthService struct {
	store  UserStore
	secret string
	pepper string
}

// NewAuthService 构造认证服务。
func NewAuthService(store UserStore, secret, pepper string) *AuthService {
	if secret == "" {
		secret = "yuduan-dev-secret"
	}
	if pepper == "" {
		pepper = "yuduan-dev-pepper"
	}
	return &AuthService{store: store, secret: secret, pepper: pepper}
}

// LoginResult 登录成功后的会话信息。
type LoginResult struct {
	Token              string
	Role               string
	MustChangePassword bool
}

// Login 校验口令并签发会话令牌（24h 有效）。
// 旧格式口令（无盐 HMAC）在验证通过后透明升级为 argon2id。
func (s *AuthService) Login(username, password string) (*LoginResult, error) {
	u, ok := s.store.GetUserByName(username)
	if !ok || u.Disabled {
		return nil, fmtError("invalid credentials")
	}
	if !crypto.VerifyPassword(password, s.pepper, u.Password) {
		return nil, fmtError("invalid credentials")
	}
	if crypto.NeedsRehash(u.Password) {
		if upgraded := crypto.HashPassword(password, s.pepper); upgraded != "" {
			u.Password = upgraded
			s.store.UpsertUser(u)
		}
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	token := crypto.SignToken(s.secret, u.Username, u.Role, exp, u.MustChangePW)
	return &LoginResult{Token: token, Role: u.Role, MustChangePassword: u.MustChangePW}, nil
}

// ChangePassword 用户自助改密：校验旧口令、执行强度策略、清除改密标记。
func (s *AuthService) ChangePassword(username, oldPassword, newPassword string) error {
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	u, ok := s.store.GetUserByName(username)
	if !ok || u.Disabled {
		return fmtError("user not found")
	}
	if !crypto.VerifyPassword(oldPassword, s.pepper, u.Password) {
		return fmtError("invalid old password")
	}
	if oldPassword == newPassword {
		return fmtError("new password must differ from old")
	}
	hash := crypto.HashPassword(newPassword, s.pepper)
	if hash == "" {
		return fmtError("password hashing failed")
	}
	u.Password = hash
	u.MustChangePW = false
	s.store.UpsertUser(u)
	return nil
}

// ForcePasswordChange 由 admin 对指定账号设置强制改密（下次登录即生效）。
func (s *AuthService) ForcePasswordChange(username string) error {
	u, ok := s.store.GetUserByName(username)
	if !ok {
		return fmtError("user not found")
	}
	u.MustChangePW = true
	s.store.UpsertUser(u)
	return nil
}

// ValidatePasswordStrength 口令强度策略：≥10 位，且包含大写、小写、数字三类中的至少两类。
func ValidatePasswordStrength(pw string) error {
	if len([]rune(pw)) < 10 {
		return fmtError("password too short: at least 10 characters required")
	}
	var upper, lower, digit, other bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, ok := range []bool{upper, lower, digit, other} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return fmtError("password too weak: need at least 3 of upper/lower/digit/symbol")
	}
	return nil
}

// VerifyToken 校验并返回声明。
func (s *AuthService) VerifyToken(token string) (crypto.Claims, error) {
	return crypto.VerifyToken(s.secret, token)
}

// HasPerm 判断某角色是否拥有某权限。
func (s *AuthService) HasPerm(role, perm string) bool {
	set, ok := rolePerms[role]
	if !ok {
		return false
	}
	return set[perm]
}

// ValidRole 判断角色名是否合法。
func ValidRole(r string) bool {
	_, ok := rolePerms[r]
	return ok
}

func fmtError(s string) error { return &authErr{s} }

type authErr struct{ m string }

func (e *authErr) Error() string { return e.m }

// TokenFromHeader 从 Authorization: Bearer <token> 中提取令牌。
func TokenFromHeader(authz string) string {
	if strings.HasPrefix(authz, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	}
	return ""
}
