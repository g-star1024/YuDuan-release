// Package audit 提供御端 M6 审计能力：记录并查询关键管理动作。
// WORM（一次写入多次读取）保障：
//   - 每条记录携带 prev_hash/hash 组成哈希链，任何篡改都会被 VerifyChain 发现；
//   - PostgreSQL 侧另有 BEFORE UPDATE/DELETE 触发器 + REVOKE 权限双保险（见 store/postgres.go migrate）。
//
// Auditor 接口同时被内存实现与 PostgreSQL 实现遵循。
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Event 是一条审计记录。
type Event struct {
	ID       int64  `json:"id"`
	Time     int64  `json:"time"`   // unix 秒
	Actor    string `json:"actor"`  // 操作人（登录账号）
	Action   string `json:"action"` // 动作类型，如 login/shell/rc_start/sw_push/software_upload
	Target   string `json:"target"` // 作用对象，如 device_id / software_id
	Detail   string `json:"detail"` // 摘要
	Result   string `json:"result"` // success / failed
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// ChainReport 哈希链校验结果。
type ChainReport struct {
	Valid      bool   `json:"valid"`
	Checked    int64  `json:"checked"`
	FirstBadID int64  `json:"first_bad_id"`
	Reason     string `json:"reason"`
}

// Auditor 审计存储接口。
type Auditor interface {
	Record(e Event) Event
	Query(limit int) []Event
	AuditCount() int64
	VerifyChain() ChainReport
}

// EventHash 计算单条审计记录的链上哈希（canonical 串经 SHA-256）。
// 注意：不含 ID——PostgreSQL 实现的 ID 由库自增分配（INSERT ... RETURNING id），
// 落库前不可知；链的完整性由 prev_hash 逐条链接 + WORM 触发器（禁改删）保障，
// 重放校验时按存储内容重算即可一致。MemAuditor 先分配 ID 后哈希，两者保持同一口径。
func EventHash(e Event) string {
	canonical := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s",
		e.Time, e.Actor, e.Action, e.Target, e.Detail, e.Result, e.PrevHash)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// MemAuditor 内存版审计（演示/无 PG 时使用）。
type MemAuditor struct {
	mu       sync.Mutex
	events   []Event
	seq      int64
	lastHash string
}

// NewMemAuditor 构造内存审计器。
func NewMemAuditor() *MemAuditor { return &MemAuditor{} }

// Record 追加一条审计记录并分配自增 ID，同时链接哈希链。
func (m *MemAuditor) Record(e Event) Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	e.ID = m.seq
	if e.Time == 0 {
		e.Time = time.Now().Unix()
	}
	if e.Result == "" {
		e.Result = "success"
	}
	e.PrevHash = m.lastHash
	e.Hash = EventHash(e)
	m.lastHash = e.Hash
	m.events = append(m.events, e)
	// 控制内存占用：保留最近 5000 条
	if len(m.events) > 5000 {
		m.events = m.events[len(m.events)-5000:]
	}
	return e
}

// Query 返回最近 limit 条（倒序）。
func (m *MemAuditor) Query(limit int) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.events)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Event, 0, limit)
	for i := n - limit; i < n; i++ {
		out = append(out, m.events[i])
	}
	return out
}

// AuditCount 返回审计总数。
func (m *MemAuditor) AuditCount() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.events))
}

// VerifyChain 重放哈希链，检测任何篡改/缺失。
func (m *MemAuditor) VerifyChain() ChainReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	var prev string
	for _, e := range m.events {
		if e.PrevHash != prev {
			return ChainReport{Valid: false, Checked: e.ID, FirstBadID: e.ID,
				Reason: fmt.Sprintf("prev_hash 断裂 at id=%d", e.ID)}
		}
		if EventHash(e) != e.Hash {
			return ChainReport{Valid: false, Checked: e.ID, FirstBadID: e.ID,
				Reason: fmt.Sprintf("hash 不匹配 at id=%d", e.ID)}
		}
		prev = e.Hash
	}
	return ChainReport{Valid: true, Checked: int64(len(m.events))}
}
