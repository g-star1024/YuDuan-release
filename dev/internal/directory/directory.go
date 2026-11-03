// Package directory 实现御端 M6 的 AD/LDAP 目录同步引擎。
// 设计：以 DirectorySource 抽象任意目录（文件导出 / 真实 LDAP），
// SyncEngine 将目录用户/组按映射规则 upsert 为 RBAC 账号，与具体目录协议解耦。
package directory

import (
	"encoding/json"
	"os"
	"sort"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
)

// DirUser 是目录中的一个用户（与具体目录协议无关）。
type DirUser struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	MemberOf    []string `json:"member_of"` // 所属组名
	Disabled    bool     `json:"disabled"`
}

// DirGroup 是目录中的一个组。
type DirGroup struct {
	Name string `json:"name"`
}

// DirectorySource 抽象一个目录源，屏蔽 AD/LDAP 与文件导出的差异。
type DirectorySource interface {
	ListUsers() ([]DirUser, error)
	ListGroups() ([]DirGroup, error)
}

// FileDirectory 从 JSON 文件读取目录导出（用于演示与离线验证，形态等同一次 LDAP 查询的结果）。
type FileDirectory struct {
	Path string
}

// DirExport 是文件目录导出的结构。
type DirExport struct {
	Users  []DirUser  `json:"users"`
	Groups []DirGroup `json:"groups"`
}

// ListUsers 读取文件中的用户。
func (f *FileDirectory) ListUsers() ([]DirUser, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	var ex DirExport
	if err := json.Unmarshal(data, &ex); err != nil {
		return nil, err
	}
	return ex.Users, nil
}

// ListGroups 读取文件中的组。
func (f *FileDirectory) ListGroups() ([]DirGroup, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	var ex DirExport
	if err := json.Unmarshal(data, &ex); err != nil {
		return nil, err
	}
	return ex.Groups, nil
}

// RoleMapping 定义「组名 -> RBAC 角色」的映射；优先级 admin > operator > viewer。
type RoleMapping struct {
	GroupToRole map[string]string // 组名 -> role
}

// DefaultRoleMapping 提供一组默认映射（御端管理相关组 -> 角色）。
func DefaultRoleMapping() RoleMapping {
	return RoleMapping{GroupToRole: map[string]string{
		"yd-admins":    auth.RoleAdmin,
		"yd-operators": auth.RoleOperator,
		"yd-viewers":   auth.RoleViewer,
	}}
}

// resolveRole 根据用户所属组解析最终角色（取优先级最高者）。
func (m RoleMapping) resolveRole(memberOf []string) string {
	rank := map[string]int{auth.RoleAdmin: 3, auth.RoleOperator: 2, auth.RoleViewer: 1}
	best := auth.RoleViewer
	bestRank := 0
	for _, g := range memberOf {
		if r, ok := m.GroupToRole[g]; ok {
			if rank[r] > bestRank {
				best = r
				bestRank = rank[r]
			}
		}
	}
	return best
}

// SyncResult 汇总一次同步的结果。
type SyncResult struct {
	UsersSynced int      `json:"users_synced"`
	Roles       []string `json:"roles"`
	Skipped     int      `json:"skipped"`
}

// SyncEngine 执行目录 -> RBAC 的同步。
type SyncEngine struct {
	Source  DirectorySource
	Mapping RoleMapping
	Users   auth.UserStore
	Pepper  string
}

// NewSyncEngine 构造同步引擎。
func NewSyncEngine(src DirectorySource, m RoleMapping, users auth.UserStore, pepper string) *SyncEngine {
	return &SyncEngine{Source: src, Mapping: m, Users: users, Pepper: pepper}
}

// Sync 拉取目录用户并按映射 upsert 为 RBAC 账号。
// 新同步账户的默认口令为 "Synced@2026"（演示用）并标记必须改密；
// 已存在账户仅更新资料与角色，保留其口令与改密状态（重复同步不会重置用户已改的口令）。
// 生产应改用目录认证（LDAP bind/Kerberos），见 HA/安全文档。
func (e *SyncEngine) Sync() (SyncResult, error) {
	dirUsers, err := e.Source.ListUsers()
	if err != nil {
		return SyncResult{}, err
	}
	res := SyncResult{Roles: []string{}}
	roleSet := map[string]bool{}
	for _, du := range dirUsers {
		if du.Disabled {
			res.Skipped++
			continue
		}
		role := e.Mapping.resolveRole(du.MemberOf)
		roleSet[role] = true
		existing, ok := e.Users.GetUserByName(du.Username)
		if ok {
			// 已存在：保留口令与改密状态，仅更新资料/角色
			existing.DisplayName = du.DisplayName
			existing.Role = role
			existing.Source = "directory"
			e.Users.UpsertUser(existing)
		} else {
			pw := crypto.HashPassword("Synced@2026", e.Pepper)
			e.Users.UpsertUser(auth.User{
				Username:     du.Username,
				DisplayName:  du.DisplayName,
				Role:         role,
				Password:     pw,
				MustChangePW: true,
				Source:       "directory",
			})
		}
		res.UsersSynced++
	}
	for r := range roleSet {
		res.Roles = append(res.Roles, r)
	}
	sort.Strings(res.Roles)
	return res, nil
}
