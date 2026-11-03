// 真实 AD/LDAP 目录源：经自研最小 LDAP 客户端（internal/ldap，纯标准库 BER 实现）
// 完成 simple bind 认证与子树搜索，将域用户映射为御端 RBAC 账号。
// 支持 ldap（明文，内网）与 ldaps（TLS）；过滤器语法子集见 internal/ldap。
package directory

import (
	"strings"

	"yuduan/internal/ldap"
)

// LDAPConfig 是 AD/LDAP 连接配置。
type LDAPConfig struct {
	Host     string
	Port     int
	UseTLS   bool
	Insecure bool // ldaps 自签证书时跳过校验（内网）
	BindDN   string
	BindPwd  string
	BaseDN   string
	UserOU   string // 用户搜索基（可空则用 BaseDN）
	GroupOU  string
}

// LDAPDirectory 真实目录源。
type LDAPDirectory struct {
	cfg LDAPConfig
}

// NewLDAPDirectory 构造 LDAP 目录源。
func NewLDAPDirectory(cfg LDAPConfig) *LDAPDirectory { return &LDAPDirectory{cfg: cfg} }

func (l *LDAPDirectory) dial() (*ldap.Conn, error) {
	if l.cfg.UseTLS {
		return ldap.DialTLS(l.cfg.Host, l.cfg.Port, l.cfg.Insecure)
	}
	return ldap.Dial(l.cfg.Host, l.cfg.Port)
}

// ListUsers 查询域内用户并映射为 DirUser（过滤禁用账户）。
func (l *LDAPDirectory) ListUsers() ([]DirUser, error) {
	conn, err := l.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPwd); err != nil {
		return nil, err
	}
	base := l.cfg.UserOU
	if base == "" {
		base = l.cfg.BaseDN
	}
	entries, err := conn.Search(ldap.SearchRequest{
		BaseDN:     base,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		Attributes: []string{"sAMAccountName", "displayName", "mail", "memberOf"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]DirUser, 0, len(entries))
	for _, e := range entries {
		memberOf := []string{}
		for _, dn := range e.Attributes["memberOf"] {
			memberOf = append(memberOf, cnOf(dn))
		}
		out = append(out, DirUser{
			Username:    e.Get("sAMAccountName"),
			DisplayName: e.Get("displayName"),
			Email:       e.Get("mail"),
			MemberOf:    memberOf,
		})
	}
	return out, nil
}

// ListGroups 查询域内组。
func (l *LDAPDirectory) ListGroups() ([]DirGroup, error) {
	conn, err := l.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPwd); err != nil {
		return nil, err
	}
	base := l.cfg.GroupOU
	if base == "" {
		base = l.cfg.BaseDN
	}
	entries, err := conn.Search(ldap.SearchRequest{
		BaseDN: base, Scope: ldap.ScopeWholeSubtree, Filter: "(objectClass=group)",
		Attributes: []string{"cn"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]DirGroup, 0, len(entries))
	for _, e := range entries {
		out = append(out, DirGroup{Name: e.Get("cn")})
	}
	return out, nil
}

func cnOf(dn string) string {
	// 取 DN 中第一个 CN= 组件
	for i := 0; i < len(dn); i++ {
		if i+3 <= len(dn) && strings.EqualFold(dn[i:i+3], "CN=") {
			end := i + 3
			for end < len(dn) && dn[end] != ',' {
				end++
			}
			return dn[i+3 : end]
		}
	}
	return dn
}
