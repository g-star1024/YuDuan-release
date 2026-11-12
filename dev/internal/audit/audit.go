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
// v0.4.31-D：新增链尾外锚字段，全部 omitempty——签名器默认关闭时不输出，
// 旧四字段（valid/checked/first_bad_id/reason）对健康链的取值逐字节不变，前端/e2e 零改动。
type ChainReport struct {
	Valid      bool   `json:"valid"`
	Checked    int64  `json:"checked"`
	FirstBadID int64  `json:"first_bad_id"`
	Reason     string `json:"reason"`
	// ---- 链尾外锚（独立外锚，不进 Event、不 UPDATE audit_events）----
	Anchored       bool   `json:"anchored,omitempty"`
	AnchorTailID   int64  `json:"anchor_tail_id,omitempty"`
	AnchorSig      string `json:"anchor_sig,omitempty"`
	AnchorSignedAt int64  `json:"anchor_signed_at,omitempty"`
}

// ChainAnchor 是一次链尾外锚的完整记录（v0.4.31-D），同时是库外 append-only
// 锚文件（data/audit-anchor.jsonl）的一行 JSON，也投影出 ChainReport 的四个锚点字段。
// 独立于 Event/哈希链：签名使用服务端外部密钥（三级优先，见 ResolveAnchorKey），
// 不落入被审计库；锚点实体落在库外文件，整库重放/伪造也无法同步伪造该文件的历史行。
// KeySource 标注密钥来源（独立密钥或回退同 secret），供离线核验标注强度。
type ChainAnchor struct {
	TailID       int64  `json:"tail_id"`
	TailHash     string `json:"tail_hash"`
	Sig          string `json:"sig"`
	SignedAt     int64  `json:"signed_at"`
	AnchorFromID int64  `json:"anchor_from_id"` // 本锚点覆盖链的起始 ID（首条，兼容裁剪 / RESTART IDENTITY 恢复 / 旧库）
	KeySource    string `json:"key_source"`     // 密钥来源：YUDUAN_AUDIT_ANCHOR_KEY / hmac-secret-fallback
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

// anchorSigner 为链尾外锚签名器（包级可注入）。
// 默认 nil → Anchored=false，保证默认零回归；由 hub/audit_anchor_wire.go 的 init 注入。
// 读写经 anchorSignerMu 保护，允许测试并发安全地替换/复位。
var (
	anchorSignerMu sync.RWMutex
	anchorSigner   func(tailID int64, tailHash string) (sig string, signedAt int64)
)

// SetAnchorSigner 注入/复位链尾外锚签名器（传 nil 复位为关闭）。
// 约定：仅在程序初始化期（init）注入一次；测试可反复设置。签名器签名
// 「本次 VerifyChain 计算时刻的链尾快照」(tailID, tailHash)，返回空 sig 表示不锚定。
func SetAnchorSigner(fn func(tailID int64, tailHash string) (sig string, signedAt int64)) {
	anchorSignerMu.Lock()
	defer anchorSignerMu.Unlock()
	anchorSigner = fn
}

func currentAnchorSigner() func(tailID int64, tailHash string) (sig string, signedAt int64) {
	anchorSignerMu.RLock()
	defer anchorSignerMu.RUnlock()
	return anchorSigner
}

// anchorSink 为「库外锚点记录器」（包级可注入）。签名器只负责签名，锚文件的
// 落盘（路径/密钥来源标注）交给接线层注入的 sink，audit 包保持无文件/密钥策略。
// 默认 nil（未接库外文件时不落盘）；读写经 anchorSinkMu 保护。
var (
	anchorSinkMu sync.RWMutex
	anchorSink   func(a ChainAnchor) error
)

// SetAnchorSink 注入/复位库外锚点记录器（传 nil 复位）。sink 返回 error 表示
// 落盘失败，调用方只记日志并放弃锚定（Anchored=false），绝不把链判为损坏。
func SetAnchorSink(fn func(a ChainAnchor) error) {
	anchorSinkMu.Lock()
	defer anchorSinkMu.Unlock()
	anchorSink = fn
}

func currentAnchorSink() func(a ChainAnchor) error {
	anchorSinkMu.RLock()
	defer anchorSinkMu.RUnlock()
	return anchorSink
}

// makeAnchor 对链尾构造外锚记录；签名器未注入 / 无密钥（空 sig）/ 库外文件写入
// 失败时返回 nil（不锚定），但链本身仍按校验结果返回 Valid，绝不因缺锚误报损坏。
func makeAnchor(tailID int64, tailHash string, fromID int64) *ChainAnchor {
	fn := currentAnchorSigner()
	if fn == nil {
		return nil
	}
	sig, signedAt := fn(tailID, tailHash)
	if sig == "" {
		return nil
	}
	a := &ChainAnchor{
		TailID: tailID, TailHash: tailHash,
		Sig: sig, SignedAt: signedAt, AnchorFromID: fromID,
	}
	if sink := currentAnchorSink(); sink != nil {
		if err := sink(*a); err != nil {
			return nil
		}
	}
	return a
}

// ReplayChain 以按 ID 升序的 events 重放哈希链并生成报告。
// 判据本身是纯函数（不访问被审计库、不依赖随机）；链尾锚定经包级注入的
// 签名器 / 库外文件 sink 完成——两者默认 nil 时零副作用，故可离线单测。
//
// basePrevHash 为「首条之前」的链哈希：
//   - 全量链传 ""（首条 prev_hash 应为 ""，与旧版逐字节一致）；
//   - 裁剪 / 窗口化场景传「保留段首条的 PrevHash」（Mem 裁剪、PG 尾部窗口），
//     使裁剪后不再误报 prev_hash 断裂。
//
// 校验顺序：prev_hash 链接 → hash 重算 → ID 连续性。ID 检查置于最后，是为了
// 在「简单删行」场景仍由旧的 prev_hash 断裂判据先命中（旧四字段语义不变）；
// 它额外捕获「哈希链自洽但 ID 跳号」的整链伪造（旧判据漏检）。首条不要求 id==1，
// 兼容裁剪 / TRUNCATE ... RESTART IDENTITY 恢复 / 旧库。ID 绝不纳入 EventHash。
//
// 锚点语义：仅在校验通过且链非空时，对「本次 ReplayChain 计算时刻的链尾快照」
// (lastID, lastHash) 签名，并经 sink 追加到库外 append-only 锚文件（见 audit_anchor.go）。
// hub.handleAuditVerify 会在 VerifyChain 返回后再写一条 audit 记录，故锚点固定为
// 本次计算的链尾快照，而非页面刷新后的最新链尾。
func ReplayChain(events []Event, basePrevHash string) ChainReport {
	prev := basePrevHash
	var prevID, lastID int64
	var lastHash string
	for _, e := range events {
		if e.PrevHash != prev {
			return ChainReport{Valid: false, Checked: e.ID, FirstBadID: e.ID,
				Reason: fmt.Sprintf("prev_hash 断裂 at id=%d", e.ID)}
		}
		if EventHash(e) != e.Hash {
			return ChainReport{Valid: false, Checked: e.ID, FirstBadID: e.ID,
				Reason: fmt.Sprintf("hash 不匹配 at id=%d", e.ID)}
		}
		// ID 连续性：相对首条严格 +1（prevID != 0 跳过首条）；绝不把 ID 纳入 EventHash。
		if prevID != 0 && e.ID != prevID+1 {
			return ChainReport{Valid: false, Checked: e.ID, FirstBadID: e.ID,
				Reason: fmt.Sprintf("ID 连续性断裂 at id=%d", e.ID)}
		}
		prev = e.Hash
		prevID = e.ID
		lastID, lastHash = e.ID, e.Hash
	}
	rep := ChainReport{Valid: true, Checked: int64(len(events))}
	if len(events) > 0 {
		if a := makeAnchor(lastID, lastHash, events[0].ID); a != nil {
			rep.Anchored = true
			rep.AnchorTailID = a.TailID
			rep.AnchorSig = a.Sig
			rep.AnchorSignedAt = a.SignedAt
		}
	}
	return rep
}

// MemAuditor 内存版审计（演示/无 PG 时使用）。
type MemAuditor struct {
	mu           sync.Mutex
	events       []Event
	seq          int64
	lastHash     string
	basePrevHash string // 裁剪后保留段首条的 PrevHash，作为 VerifyChain 起点
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
	// 控制内存占用：保留最近 5000 条。裁剪后首条的 PrevHash 指向被裁掉的前一条，
	// 记录下来作为重放起点，避免 >5000 条时从 prev="" 起校验而误报 prev_hash 断裂。
	if len(m.events) > 5000 {
		drop := len(m.events) - 5000
		m.events = m.events[drop:]
		m.basePrevHash = m.events[0].PrevHash
	}
	return e
}

// Query 返回最近 limit 条（倒序），返回新建 slice 的值拷贝，保持 append-only 对外语义。
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

// AuditCount 返回累计审计总数（seq 单调递增，不随裁剪减少），与 PG 的
// SELECT count(*) FROM audit_events 语义对齐；旧实现返回裁剪后的 len(events) 会偏小。
func (m *MemAuditor) AuditCount() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seq
}

// VerifyChain 重放哈希链，检测任何篡改/缺失/跳号，并在校验通过时生成链尾外锚。
func (m *MemAuditor) VerifyChain() ChainReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ReplayChain(m.events, m.basePrevHash)
}
