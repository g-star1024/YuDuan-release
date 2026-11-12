package store

import (
	"encoding/json"
	"fmt"
	"log"
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
	dsn = strings.TrimSpace(dsn)
	// URL 格式：postgres://user:pass@host:port/dbname?sslmode=disable&connect_timeout=10
	// 自研 pg 客户端为明文连接，sslmode/其余查询参数忽略（连接本身不启用 TLS）。
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		rest := dsn[strings.Index(dsn, "://")+3:]
		if i := strings.IndexByte(rest, '?'); i >= 0 {
			rest = rest[:i]
		}
		var userinfo string
		if i := strings.LastIndexByte(rest, '@'); i >= 0 {
			userinfo, rest = rest[:i], rest[i+1:]
		}
		if userinfo != "" {
			if j := strings.IndexByte(userinfo, ':'); j >= 0 {
				user, password = userinfo[:j], userinfo[j+1:]
			} else {
				user = userinfo
			}
		}
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			dbname, rest = rest[i+1:], rest[:i]
		}
		if rest != "" {
			if h, p, ok := splitHostPort(rest); ok {
				host, port = h, p
			} else {
				host = rest
			}
		}
		return
	}
	// libpq 键值格式：host=x port=5432 user=y dbname=z password=w
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

// splitHostPort 解析 host[:port]，兼容 [::1]:5432；无端口时用默认 5432。
func splitHostPort(s string) (string, int, bool) {
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i >= 0 {
			host := s[1:i]
			if rest := s[i+1:]; strings.HasPrefix(rest, ":") {
				if p, err := strconv.Atoi(rest[1:]); err == nil {
					return host, p, true
				}
			}
			return host, 5432, true
		}
		return s, 5432, false
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		if p, err := strconv.Atoi(s[i+1:]); err == nil {
			return s[:i], p, true
		}
	}
	return s, 5432, false
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
			agent_version TEXT, token TEXT UNIQUE, online BOOLEAN, last_seen TIMESTAMP, created_at TIMESTAMP, source_addr TEXT)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id BIGSERIAL PRIMARY KEY, time BIGINT, actor TEXT, action TEXT, target TEXT,
			detail TEXT, result TEXT, prev_hash TEXT, hash TEXT)`,
		`CREATE TABLE IF NOT EXISTS users (
			username TEXT PRIMARY KEY, display_name TEXT, role TEXT, password TEXT,
			disabled BOOLEAN, must_change_pw BOOLEAN NOT NULL DEFAULT FALSE, source TEXT NOT NULL DEFAULT 'local')`,
		// W1-1/2/3 资产台账扩展：软件清单(JSON)、分组(部门/楼层/批次/标签)、生命周期
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS software_json TEXT`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS department TEXT`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS floor TEXT`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS batch TEXT`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS tags_json TEXT`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS lifecycle TEXT`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS assignee TEXT`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMP`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS lifecycle_note TEXT`,
		// W2-4 敏感设备标记（敏感终端远控须 admin 二级审批）
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS sensitive BOOLEAN NOT NULL DEFAULT FALSE`,
		// v0.4.32 §9.2 设备证明：副端公钥与证明态（幂等加列，旧库兼容，默认值 false）
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_pubkey TEXT`,
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS attested BOOLEAN NOT NULL DEFAULT FALSE`,
		// v0.4.40 P3-9：服务端观察的连接来源地址（反代下为 XFF 首段；旧库幂等补列）
		`ALTER TABLE devices ADD COLUMN IF NOT EXISTS source_addr TEXT`,
		// W1-5 实时告警
		`CREATE TABLE IF NOT EXISTS alerts (
			id BIGSERIAL PRIMARY KEY, type TEXT, severity TEXT, device_id TEXT, device_name TEXT,
			message TEXT, detail TEXT, created_at TIMESTAMP, read BOOLEAN NOT NULL DEFAULT FALSE)`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_id ON alerts (id DESC)`,
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
		// W1-5 一次性幂等清理：合并同 (device_id,type) 的重复未读告警，仅保留最新一条
		`DELETE FROM alerts a USING alerts b
WHERE a.read=false AND b.read=false
  AND a.device_id=b.device_id AND a.type=b.type AND a.id<b.id`,
		// v0.4.40 P2-4：历史 rc_timeout 告警降级并移出未读（severityOf 仅影响新事件；徽章只数 read=false）
		`UPDATE alerts SET severity='info', read=true WHERE type='rc_timeout' AND severity='warning'`,
	}
	for _, s := range stmts {
		if err := p.exec(s); err != nil {
			return fmt.Errorf("migrate: %v", err)
		}
	}
	// 波次 3/4/5 的扩展建表（RegisterMigrate 注册，幂等）
	if err := p.runMigrateHooks(); err != nil {
		return fmt.Errorf("migrate hooks: %v", err)
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

const deviceCols = `id,hostname,os,os_version,arch,cpu,memory_gb,disk_gb,serial_no,mac,ip,agent_version,token,online,last_seen,created_at,software_json,department,floor,batch,tags_json,lifecycle,assignee,assigned_at,lifecycle_note,sensitive,agent_pubkey,attested,source_addr`

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
	if d.Lifecycle == "" {
		d.Lifecycle = DefaultLifecycle()
	}
	d.Online = true
	d.LastSeen = now
	sql := `INSERT INTO devices (` + deviceCols + `) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,true,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
ON CONFLICT (id) DO UPDATE SET hostname=EXCLUDED.hostname,os=EXCLUDED.os,os_version=EXCLUDED.os_version,
arch=EXCLUDED.arch,cpu=EXCLUDED.cpu,memory_gb=EXCLUDED.memory_gb,disk_gb=EXCLUDED.disk_gb,
serial_no=EXCLUDED.serial_no,mac=EXCLUDED.mac,ip=EXCLUDED.ip,agent_version=EXCLUDED.agent_version,
token=EXCLUDED.token,online=true,last_seen=EXCLUDED.last_seen,
software_json=CASE WHEN EXCLUDED.software_json <> '' THEN EXCLUDED.software_json ELSE devices.software_json END,
department=EXCLUDED.department,floor=EXCLUDED.floor,batch=EXCLUDED.batch,tags_json=EXCLUDED.tags_json,
lifecycle=COALESCE(EXCLUDED.lifecycle,devices.lifecycle),assignee=COALESCE(EXCLUDED.assignee,devices.assignee),
assigned_at=COALESCE(EXCLUDED.assigned_at,devices.assigned_at),lifecycle_note=COALESCE(EXCLUDED.lifecycle_note,devices.lifecycle_note),
sensitive=EXCLUDED.sensitive,agent_pubkey=EXCLUDED.agent_pubkey,attested=EXCLUDED.attested,
source_addr=CASE WHEN EXCLUDED.source_addr <> '' THEN EXCLUDED.source_addr ELSE devices.source_addr END`
	if err := p.exec(sql, d.ID, d.Hostname, d.OS, d.OSVersion, d.Arch, d.CPU,
		d.MemoryGB, d.DiskGB, d.SerialNo, d.MAC, d.IP, d.AgentVersion, d.Token, d.LastSeen, d.CreatedAt,
		d.SoftwareJSON, d.Department, d.Floor, d.Batch, d.TagsJSON, d.Lifecycle, d.Assignee, d.AssignedAt, d.LifecycleNote,
		boolPG(d.Sensitive), d.AgentPubkey, boolPG(d.Attested), d.SourceAddr); err != nil {
		// 此前 _ = p.exec 吞错误，devices 持久化静默失败（25 参数 vs 26 占位符 bug）未被发现。
		log.Printf("[store] upsert device failed: %v", err)
	}
	return d
}

func (p *PostgresStore) Get(id string) (Device, bool) {
	row, ok, err := p.queryRow("SELECT "+deviceCols+" FROM devices WHERE id=$1", id)
	if err != nil || !ok {
		return Device{}, false
	}
	return rowToDevice(row), true
}

func (p *PostgresStore) GetByToken(token string) (Device, bool) {
	row, ok, err := p.queryRow("SELECT "+deviceCols+" FROM devices WHERE token=$1", token)
	if err != nil || !ok {
		return Device{}, false
	}
	return rowToDevice(row), true
}

// FindByIdentity 按硬件身份查找设备（v0.4.8 幂等注册）：serial 优先，其次 hostname+mac。
func (p *PostgresStore) FindByIdentity(hostname, mac, serial string) (Device, bool) {
	if serial != "" {
		if row, ok, err := p.queryRow(
			"SELECT "+deviceCols+" FROM devices WHERE serial_no=$1 ORDER BY created_at LIMIT 1", serial); err == nil && ok {
			return rowToDevice(row), true
		}
	}
	if hostname != "" && mac != "" {
		if row, ok, err := p.queryRow(
			"SELECT "+deviceCols+" FROM devices WHERE hostname=$1 AND mac=$2 ORDER BY created_at LIMIT 1", hostname, mac); err == nil && ok {
			return rowToDevice(row), true
		}
	}
	return Device{}, false
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

// Count 实现 auth.UserStore.Count——返回用户数。
// 注意：PostgresStore 同时充当 store.Store（设备数）与 auth.UserStore（用户数），
// 但 store.Store.Count() 全库无调用者；用户数语义以此为准（复用 UserCount）。
// 若未来确需"设备数"，请用专门查询（SELECT count(*) FROM devices），勿改本方法
// （否则 handleAdminUsers.total 会误报设备数、SeedDefaultAdmin 的"账号库为空"判断也会失真）。
func (p *PostgresStore) Count() int {
	return p.UserCount()
}

// boolPG 将 Go 布尔值序列化为 PG 文本协议可接受的布尔字面量。
func boolPG(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func rowToDevice(r []string) Device {
	gb := func(s string) int { n, _ := strconv.Atoi(s); return n }
	online := r[13] == "t" || r[13] == "true"
	ts := func(i int) time.Time {
		if i >= len(r) {
			return time.Time{}
		}
		if t, err := time.Parse("2006-01-02 15:04:05", r[i]); err == nil {
			return t
		}
		return time.Time{}
	}
	// 兼容旧列（PG 迁移前查询缺列时按索引安全取）
	get := func(i int) string {
		if i < len(r) {
			return r[i]
		}
		return ""
	}
	d := Device{
		ID: r[0], Hostname: r[1], OS: r[2], OSVersion: r[3], Arch: r[4], CPU: r[5],
		MemoryGB: gb(r[6]), DiskGB: gb(r[7]), SerialNo: r[8], MAC: r[9], IP: r[10],
		AgentVersion: r[11], Token: r[12], Online: online,
		LastSeen: ts(14), CreatedAt: ts(15),
		SoftwareJSON: get(16), Department: get(17), Floor: get(18), Batch: get(19),
		TagsJSON: get(20), Lifecycle: get(21), Assignee: get(22),
		AssignedAt: ts(23), LifecycleNote: get(24),
		// W2-4 敏感设备标记（列缺失时 get 返回 "" → false，兼容迁移前旧库）
		Sensitive: get(25) == "t" || get(25) == "true",
		// v0.4.32 §9.2 设备证明（列缺失时 get 返回 "" → 空公钥 / false，兼容迁移前旧库）
		AgentPubkey: get(26),
		Attested:    get(27) == "t" || get(27) == "true",
		// v0.4.40 P3-9：服务端观察的连接来源（列缺失时 get 返回 "" 兼容迁移前旧库）
		SourceAddr: get(28),
	}
	// 填充 API 视图（解析 backing JSON 列）
	d.Software = d.SoftwareList()
	d.Tags = d.TagList()
	return d
}

// ---- W1-2 台账分组元数据 ----

func (p *PostgresStore) UpdateMeta(id string, meta DeviceMeta) (Device, bool) {
	tags, _ := json.Marshal(meta.Tags)
	if meta.Sensitive != nil {
		_ = p.exec(`UPDATE devices SET department=$1,floor=$2,batch=$3,tags_json=$4,sensitive=$5 WHERE id=$6`,
			meta.Department, meta.Floor, meta.Batch, string(tags), boolPG(*meta.Sensitive), id)
		return p.Get(id)
	}
	_ = p.exec(`UPDATE devices SET department=$1,floor=$2,batch=$3,tags_json=$4 WHERE id=$5`,
		meta.Department, meta.Floor, meta.Batch, string(tags), id)
	return p.Get(id)
}

// ---- W1-3 生命周期状态流转 ----

func (p *PostgresStore) TransitionLifecycle(id string, lc LifecycleTransition) (Device, bool) {
	var assignedAt any
	if lc.State == LifecycleIssued || lc.State == LifecycleTransferred {
		assignedAt = time.Now().UTC()
	}
	_ = p.exec(`UPDATE devices SET lifecycle=$1,assignee=$2,lifecycle_note=$3,
		assigned_at=COALESCE($4,assigned_at) WHERE id=$5`,
		lc.State, lc.Assignee, lc.Note, assignedAt, id)
	return p.Get(id)
}

// ---- W1-5 实时告警 ----

func (p *PostgresStore) AddAlert(a Alert) Alert {
	// 去重：同 device+type 且未读 → 更新既有的未读告警，避免重复插入
	if a.DeviceID != "" && a.Type != "" {
		row, ok, err := p.queryRow(
			`SELECT id FROM alerts WHERE device_id=$1 AND type=$2 AND read=false LIMIT 1`,
			a.DeviceID, a.Type)
		if err == nil && ok {
			if id, e := strconv.ParseInt(row[0], 10, 64); e == nil {
				_ = p.exec(`UPDATE alerts SET message=$1, detail=$2, created_at=$3 WHERE id=$4`,
					a.Message, a.Detail, time.Now().UTC(), id)
				a.ID = id
				a.Read = false
				return a
			}
		}
	}
	row, ok, err := p.queryRow(
		`INSERT INTO alerts (type,severity,device_id,device_name,message,detail,created_at,read)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,false) RETURNING id`,
		a.Type, a.Severity, a.DeviceID, a.DeviceName, a.Message, a.Detail, time.Now().UTC())
	if err != nil {
		return a
	}
	if ok {
		a.ID, _ = strconv.ParseInt(row[0], 10, 64)
	}
	a.Read = false
	return a
}

func (p *PostgresStore) ListAlerts(limit int) []Alert {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.query(
		`SELECT id,type,severity,device_id,device_name,message,detail,created_at,read
		 FROM alerts ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil
	}
	out := make([]Alert, 0, len(rows))
	for _, r := range rows {
		id, _ := strconv.ParseInt(r[0], 10, 64)
		out = append(out, Alert{
			ID: id, Type: r[1], Severity: r[2], DeviceID: r[3], DeviceName: r[4],
			Message: r[5], Detail: r[6], CreatedAt: tsOrZero(r[7]),
			Read: r[8] == "t" || r[8] == "true",
		})
	}
	return out
}

func (p *PostgresStore) MarkAlertRead(id int64) {
	_ = p.exec("UPDATE alerts SET read=true WHERE id=$1", id)
}

func (p *PostgresStore) MarkAllAlertsRead() {
	_ = p.exec("UPDATE alerts SET read=true WHERE read=false")
}

func (p *PostgresStore) UnreadAlertCount() int {
	row, ok, err := p.queryRow("SELECT count(*) FROM alerts WHERE read=false")
	if err != nil || !ok {
		return 0
	}
	n, _ := strconv.Atoi(row[0])
	return n
}

func tsOrZero(s string) time.Time {
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t
	}
	return time.Time{}
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

// VerifyChain 重放哈希链，检测篡改/断链/跳号，并在校验通过时生成链尾外锚。
//
// 覆盖边界：单次最多回放最近 200000 行（LIMIT 防止超大表撑爆内存）。
// 用 ORDER BY id DESC LIMIT 200000 取「链尾方向」的最新 200000 行后反转为升序，
// 保证锚点签的始终是真实链尾（旧版 ORDER BY id LIMIT 取最旧 200000，锚点/覆盖均会偏到链头）。
// 窗口未触顶（行数 < 200000）时等价于全量链、起点 prev=""、判据逐字节同旧版；
// 触顶时窗口首条或为链中段，按 Mem 裁剪同口径以其 PrevHash 为重放起点。
// 判据与锚点逻辑统一委托给 audit.ReplayChain（纯函数，可离线单测），
// 本函数只负责取数与构造 Event；绝不 UPDATE audit_events（PG WORM 触发器物理禁止）。
func (p *PostgresStore) VerifyChain() audit.ChainReport {
	const window = 200000
	rows, err := p.query(
		"SELECT id,time,actor,action,target,detail,result,prev_hash,hash FROM audit_events ORDER BY id DESC LIMIT 200000")
	if err != nil {
		return audit.ChainReport{Valid: false, Reason: "query failed: " + err.Error()}
	}
	// rows 为 id 降序（最新在前）；反转为升序后委托 ReplayChain 重放，锚点落在链尾。
	events := make([]audit.Event, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		t, _ := strconv.ParseInt(r[1], 10, 64)
		id, _ := strconv.ParseInt(r[0], 10, 64)
		events = append(events, audit.Event{
			ID: id, Time: t, Actor: r[2], Action: r[3], Target: r[4],
			Detail: r[5], Result: r[6], PrevHash: r[7], Hash: r[8],
		})
	}
	// 触顶时窗口不含链头，以窗口首条 PrevHash 为起点（同裁剪口径，避免误报断链）；
	// 未触顶时窗口含链头，起点保持 ""（与旧版一致，保留链头 prev_hash 校验）。
	basePrevHash := ""
	if len(events) == window && len(events) > 0 {
		basePrevHash = events[0].PrevHash
	}
	return audit.ReplayChain(events, basePrevHash)
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
