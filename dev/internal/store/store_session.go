// store_session.go —— v0.4.31-E 安全 P2「会话安全」的 PostgreSQL 会话存储。
//
// 约束：沿用 exec.go 扩展点（RegisterMigrate 幂等建表 + Exec/QueryOne 读写），
// 零修改 postgres.go / store.go 主体（照抄 store_login_guard.go 范式）。
// 内存模式不执行 RegisterMigrate，故内存后端改用 auth.NewMemSessionStore（见 main.go）。
package store

import (
	"strconv"

	"yuduan/internal/auth"
)

func init() {
	RegisterMigrate(func(p *PostgresStore) error {
		return p.Exec(`CREATE TABLE IF NOT EXISTS yuduan_sessions (
			sid TEXT PRIMARY KEY,
			username TEXT,
			role TEXT,
			issued_at BIGINT,
			last_active BIGINT,
			expires_at BIGINT,
			revoked BOOLEAN DEFAULT FALSE
		)`)
	})
}

// PGSessionStore 把会话状态落在 PostgreSQL，实现 auth.SessionStore。
// 与 MemSessionStore 语义一致：吊销是「标记 revoked=TRUE」而非删行，避免与 legacy
// 宽限（仅在无记录时触发）混淆；空闲/过期判定统一在 auth.VerifyToken 完成。
type PGSessionStore struct{ p *PostgresStore }

func NewPGSessionStore(p *PostgresStore) *PGSessionStore { return &PGSessionStore{p: p} }

var _ auth.SessionStore = (*PGSessionStore)(nil)

const sessionTableCols = `sid,username,role,issued_at,last_active,expires_at,revoked`

func (s *PGSessionStore) Create(sess auth.Session) error {
	return s.p.Exec(`INSERT INTO yuduan_sessions (`+sessionTableCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (sid) DO UPDATE SET username=EXCLUDED.username, role=EXCLUDED.role,
			issued_at=EXCLUDED.issued_at, last_active=EXCLUDED.last_active,
			expires_at=EXCLUDED.expires_at, revoked=EXCLUDED.revoked`,
		sess.SID, sess.Username, sess.Role, sess.IssuedAt, sess.LastActive, sess.ExpiresAt, sess.Revoked)
}

func (s *PGSessionStore) Get(sid string) (auth.Session, bool) {
	row, ok, err := s.p.QueryOne(`SELECT `+sessionTableCols+` FROM yuduan_sessions WHERE sid=$1`, sid)
	if err != nil || !ok || len(row) < 7 {
		return auth.Session{}, false
	}
	return rowToSession(row), true
}

func (s *PGSessionStore) Touch(sid string, now int64) error {
	return s.p.Exec(`UPDATE yuduan_sessions SET last_active=$1 WHERE sid=$2 AND revoked=FALSE`, now, sid)
}

func (s *PGSessionStore) Revoke(sid string) error {
	return s.p.Exec(`UPDATE yuduan_sessions SET revoked=TRUE WHERE sid=$1`, sid)
}

func (s *PGSessionStore) RevokeUser(username string) error {
	return s.p.Exec(`UPDATE yuduan_sessions SET revoked=TRUE WHERE username=$1`, username)
}

// rowToSession 把 QueryOne 返回的字符串切片解析为 auth.Session（自行 ParseInt/ParseBool）。
func rowToSession(r []string) auth.Session {
	atoi64 := func(v string) int64 { n, _ := strconv.ParseInt(v, 10, 64); return n }
	return auth.Session{
		SID: r[0], Username: r[1], Role: r[2],
		IssuedAt: atoi64(r[3]), LastActive: atoi64(r[4]), ExpiresAt: atoi64(r[5]),
		Revoked: sessionBool(r[6]),
	}
}

// sessionBool 兼容 PG BOOLEAN 的常见文本形态（t/true/1/TRUE...）。
func sessionBool(v string) bool {
	switch v {
	case "t", "T", "true", "TRUE", "True", "1", "y", "Y", "yes", "on":
		return true
	default:
		return false
	}
}
