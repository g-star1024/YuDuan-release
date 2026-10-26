package store

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"yuduan/internal/audit"
	"yuduan/internal/auth"
	"yuduan/internal/pg"
)

// PostgresStore 以 PostgreSQL 作为持久化后端，实现 Store / Auditor / UserStore。
// 连接走最小 PG 客户端的连接池（internal/pg）；全部 SQL 使用 $n 参数化（扩展协议），
// 杜绝注入。审计表为 WORM：应用层哈希链 + PG 侧触发器/权限双保险。
type PostgresStore struct {
	pool *pg.Pool
	dsn  string
}

// DSN 形如 host=127.0.0.1 port=5432 user=postgres dbname=yuduan password=postgres
func parseDSN(dsn string) (host string, port int, user, dbname, password string) {
	host = "127.0.0.1"
	port = 5432
	for _, kv := range strings.Fields(dsn) {
		p := strings.SplitN(kv, "=", 2)
		if len(p) != 2 {
			continue
		}
		switch p[0] {
		case "host":
			host = p[1]
		case "port":
			port, _ = strconv.Atoi(p[1])
		case "user":
			user = p[1]
		case "dbname", "database":
			dbname = p[1]
		case "password":
			password = p[1]
		}
	}
	return
}

// NewPostgresStore 建立连接池并建表（幂等）。
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	host, port, user, dbname, password := parseDSN(dsn)
	dial := func() (*pg.Conn, error) {
		return pg.Connect(host, port, user, dbname, password)
	}
	pool, err := pg.NewPool(4, 8, dial)
	if err != nil {
		return nil, err
	}
	p := &PostgresStore{pool: pool, dsn: dsn}
	if err := p.migrate(); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

// Pool 暴露底层连接池（供多中枢总线/监听器复用）。
func (p *PostgresStore) Pool() *pg.Pool { return p.pool }

// Close 关闭连接池。
func (p *PostgresStore) Close() { p.pool.Close() }

func (p *PostgresStore) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY, hostname TEXT, os TEXT, os_version TEXT, arch TEXT,
			cpu TEXT, memory_gb INT, disk_gb INT, serial_no TEXT, mac TEXT, ip TEXT,
			agent_version TEXT, token TEXT UNIQUE, online BOOLEAN, last_seen TIMESTAMP, created_at TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id BIGSERIAL PRIMARY KEY, time BIGINT, actor TEXT, action TEXT, target TEXT,
			detail TEXT, result TEXT, prev_hash TEXT, hash TEXT)`,
		`CREATE TABLE IF NOT EXISTS users (
			username TEXT PRIMARY KEY, display_name TEXT, role TEXT, password TEXT,
			disabled BOOLEAN, must_change_pw BOOLEAN NOT NULL DEFAULT FALSE, source TEXT NOT NULL DEFAULT 'local')`,
		// 兼容旧库：补列（幂等）
		`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash TEXT`,
		`ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hash TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_pw BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'local'`,
		`CREATE INDEX IF NOT EXISTS idx_audit_id ON audit_events (id)`,
		// WORM：更新/删除触发器（超级用户亦不可绕过，仅 session_replication_role=replica 可禁用）
		`CREATE OR REPLACE FUNCTION yuduan_audit_worm() RETURNS trigger AS $fn$
BEGIN
    RAISE EXCEPTION 'yuduan audit is WORM: % is not allowed on audit_events', TG_OP;
END;
$fn$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS yuduan_audit_worm_trg ON audit_events`,
		`CREATE TRIGGER yuduan_audit_worm_trg BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION yuduan_audit_worm()`,
		// WORM：权限层兜底（非超级用户角色连修改权限都没有）
		`REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC`,
	}
	for _, s := range stmts {
		if err := p.exec(s); err != nil {
			return fmt.Errorf("migrate: %v", err)
		}
	}
	return nil
}

// ---- 连接池辅助 ----

func (p *PostgresStore) query(sql string, args ...any) ([][]string, error) {
	c, err := p.pool.Acquire()
	if err != nil {
		return nil, err
	}
	_, rows, err := c.QueryArgs(sql, args...)
	if err != nil {
		p.pool.Discard(c)
		return nil, err
	}
	p.pool.Release(c)
	return rows, nil
}

func (p *PostgresStore) queryRow(sql string, args ...any) ([]string, bool, error) {
	rows, err := p.query(sql, args...)
	if err != nil || len(rows) == 0 {
		return nil, false, err
	}
	return rows[0], true, nil
}

func (p *PostgresStore) exec(sql string, args ...any) error {
	c, err := p.pool.Acquire()
	if err != nil {
		return err
	}
	if err := c.ExecArgs(sql, args...); err != nil {
		p.pool.Discard(c)
		return err
	}
	p.pool.Release(c)
	return nil
}

// ---- Store：设备 ----

const deviceCols = `id,hostname,os,os_version,arch,cpu,memory_gb,disk_gb,serial_no,mac,ip,agent_version,token,online,last_seen,created_at`

func (p *PostgresStore) Upsert(d Device) Device {
	now := time.Now().UTC()
	// 令牌复用：按 token 找回既有设备身份
	if d.Token != "" {
		if row, ok, _ := p.queryRow("SELECT id,created_at FROM devices WHERE token=$1", d.Token); ok {
			d.ID = row[0]
			if t, err := time.Parse("2006-01-02 15:04:05", row[1]); err == nil {
				d.CreatedAt = t
			}
		}
	}
	if d.ID == "" {
		d.ID = newID()
	}
	if d.Token == "" {
		d.Token = newToken()
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	d.Online = true
	d.LastSeen = now
	sql := `INSERT INTO devices (` + deviceCols + `) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,true,$14,$15)
ON CONFLICT (id) DO UPDATE SET hostname=EXCLUDED.hostname,os=EXCLUDED.os,os_version=EXCLUDED.os_version,
arch=EXCLUDED.arch,cpu=EXCLUDED.cpu,memory_gb=EXCLUDED.memory_gb,disk_gb=EXCLUDED.disk_gb,
serial_no=EXCLUDED.serial_no,mac=EXCLUDED.mac,ip=EXCLUDED.ip,agent_version=EXCLUDED.agent_version,
token=EXCLUDED.token,online=true,last_seen=EXCLUDED.last_seen`
	_ = p.exec(sql, d.ID, d.Hostname, d.OS, d.OSVersion, d.Arch, d.CPU,
		d.MemoryGB, d.DiskGB, d.SerialNo, d.MAC, d.IP, d.AgentVersion, d.Token, d.LastSeen, d.CreatedAt)
	return d
}

func (p *PostgresStore) Get(id string) (Device, bool) {
	row, ok, err := p.queryRow("SELECT "+deviceCols+" FROM devices WHERE id=$1", id)
	if err != nil || !ok {
		return Device{}, false
	}
	return rowToDevice(row), true
}

func (p *PostgresStore) List() []Device {
	rows, err := p.query("SELECT " + deviceCols + " FROM devices ORDER BY created_at")
	if err != nil {
		return nil
	}
	out := make([]Device, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToDevice(r))
	}
	return out
}

func (p *PostgresStore) MarkOffline(id string) {
	_ = p.exec("UPDATE devices SET online=false WHERE id=$1", id)
}

func (p *PostgresStore) Touch(id string) {
	_ = p.exec("UPDATE devices SET online=true,last_seen=$1 WHERE id=$2", time.Now().UTC(), id)
}

func (p *PostgresStore) Count() int {
	row, ok, err := p.queryRow("SELECT count(*) FROM devices")
	if err != nil || !ok {
		return 0
	}
	n, _ := strconv.Atoi(row[0])
	return n
}

func rowToDevice(r []string) Device {
	gb := func(s string) int { n, _ := strconv.Atoi(s); return n }
	online := r[13] == "t" || r[13] == "true"
	d := Device{
		ID: r[0], Hostname: r[1], OS: r[2], OSVersion: r[3], Arch: r[4], CPU: r[5],
		MemoryGB: gb(r[6]), DiskGB: gb(r[7]), SerialNo: r[8], MAC: r[9], IP: r[10],
		AgentVersion: r[11], Token: r[12], Online: online,
	}
	if t, err := time.Parse("2006-01-02 15:04:05", r[14]); err == nil {
		d.LastSeen = t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", r[15]); err == nil {
		d.CreatedAt = t
	}
	return d
}

// ---- Auditor（含 WORM 哈希链） ----

func (p *PostgresStore) Record(e audit.Event) audit.Event {
	if e.Time == 0 {
		e.Time = time.Now().Unix()
	}
	if e.Result == "" {
		e.Result = "success"
	}
	// 取链尾哈希（同库串行写入，竞态窗口由唯一自增 id 兜底）
	prev := ""
	if row, ok, err := p.queryRow("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1"); err == nil && ok {
		prev = row[0]
	}
	e.PrevHash = prev
	e.Hash = audit.EventHash(e)
	row, ok, err := p.queryRow(
		`INSERT INTO audit_events (time,actor,action,target,detail,result,prev_hash,hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		e.Time, e.Actor, e.Action, e.Target, e.Detail, e.Result, e.PrevHash, e.Hash)
	if err != nil {
		return e
	}
	if ok {
		if id, perr := strconv.ParseInt(row[0], 10, 64); perr == nil {
			e.ID = id
		}
	}
	return e
}

func (p *PostgresStore) Query(limit int) []audit.Event {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.query(
		"SELECT id,time,actor,action,target,detail,result,prev_hash,hash FROM audit_events ORDER BY id DESC LIMIT $1",
		limit)
	if err != nil {
		return nil
	}
	out := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		t, _ := strconv.ParseInt(r[1], 10, 64)
		id, _ := strconv.ParseInt(r[0], 10, 64)
		out = append(out, audit.Event{
			ID: id, Time: t, Actor: r[2], Action: r[3], Target: r[4],
			Detail: r[5], Result: r[6], PrevHash: r[7], Hash: r[8],
		})
	}
	return out
}

func (p *PostgresStore) AuditCount() int64 {
	row, ok, err := p.queryRow("SELECT count(*) FROM audit_events")
	if err != nil || !ok {
		return 0
	}
	n, _ := strconv.ParseInt(row[0], 10, 64)
	return n
}

// VerifyChain 重放全量哈希链，检测篡改/断链。
func (p *PostgresStore) VerifyChain() audit.ChainReport {
	rows, err := p.query(
		"SELECT id,time,actor,action,target,detail,result,prev_hash,hash FROM audit_events ORDER BY id LIMIT 200000")
	if err != nil {
		return audit.ChainReport{Valid: false, Reason: "query failed: " + err.Error()}
	}
	var prev string
	for _, r := range rows {
		t, _ := strconv.ParseInt(r[1], 10, 64)
		id, _ := strconv.ParseInt(r[0], 10, 64)
		e := audit.Event{
			ID: id, Time: t, Actor: r[2], Action: r[3], Target: r[4],
			Detail: r[5], Result: r[6], PrevHash: r[7], Hash: r[8],
		}
		if e.PrevHash != prev {
			return audit.ChainReport{Valid: false, Checked: id, FirstBadID: id,
				Reason: fmt.Sprintf("prev_hash 断裂 at id=%d", id)}
		}
		if audit.EventHash(e) != e.Hash {
			return audit.ChainReport{Valid: false, Checked: id, FirstBadID: id,
				Reason: fmt.Sprintf("hash 不匹配 at id=%d", id)}
		}
		prev = e.Hash
	}
	return audit.ChainReport{Valid: true, Checked: int64(len(rows))}
}

// ---- UserStore ----

const userCols = `username,display_name,role,password,disabled,must_change_pw,source`

func rowToUser(r []string) auth.User {
	return auth.User{
		Username: r[0], DisplayName: r[1], Role: r[2], Password: r[3],
		Disabled:     r[4] == "t" || r[4] == "true",
		MustChangePW: r[5] == "t" || r[5] == "true",
		Source:       r[6],
	}
}

func (p *PostgresStore) UpsertUser(u auth.User) {
	src := u.Source
	if src == "" {
		src = "local"
	}
	_ = p.exec(`INSERT INTO users (`+userCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (username) DO UPDATE SET display_name=EXCLUDED.display_name,role=EXCLUDED.role,
password=EXCLUDED.password,disabled=EXCLUDED.disabled,must_change_pw=EXCLUDED.must_change_pw,source=EXCLUDED.source`,
		u.Username, u.DisplayName, u.Role, u.Password, u.Disabled, u.MustChangePW, src)
}

func (p *PostgresStore) GetUserByName(name string) (auth.User, bool) {
	row, ok, err := p.queryRow("SELECT "+userCols+" FROM users WHERE username=$1", name)
	if err != nil || !ok {
		return auth.User{}, false
	}
	return rowToUser(row), true
}

func (p *PostgresStore) ListUsers() []auth.User {
	rows, err := p.query("SELECT " + userCols + " FROM users ORDER BY username")
	if err != nil {
		return nil
	}
	out := make([]auth.User, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToUser(r))
	}
	return out
}

func (p *PostgresStore) UserCount() int {
	row, ok, err := p.queryRow("SELECT count(*) FROM users")
	if err != nil || !ok {
		return 0
	}
	n, _ := strconv.Atoi(row[0])
	return n
}
