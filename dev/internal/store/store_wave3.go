package store

// store_wave3.go —— 波次 3 的 PostgreSQL 仓储（软件分发模板/任务/执行记录 + 中枢高可用节点表）。
//
// 约束：本波次不修改既有 postgres.go / store.go（多波次并行避免文件冲突），全部通过
// exec.go 暴露的扩展点实现：RegisterMigrate 注册幂等建表，Exec/QueryRows 读写。
//
// 内存模式（e2e 与默认部署）不经过本文件——由 hub 包的 wave3.go 内存表承载；
// 仅当仓储为 *PostgresStore 时中枢才做「内存 + PG 双写」。

import (
	"encoding/json"
	"time"
)

func init() { RegisterMigrate(migrateWave3) }

func migrateWave3(p *PostgresStore) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS swdist_templates (
			platform TEXT NOT NULL, pkg_type TEXT NOT NULL, args TEXT, descr TEXT,
			builtin BOOLEAN, updated_at TIMESTAMP, updated_by TEXT,
			PRIMARY KEY (platform, pkg_type))`,
		`CREATE TABLE IF NOT EXISTS dist_tasks (
			id TEXT PRIMARY KEY, state TEXT, payload TEXT, created_at TIMESTAMP)`,
		`CREATE INDEX IF NOT EXISTS idx_dist_tasks_state ON dist_tasks (state)`,
		`CREATE TABLE IF NOT EXISTS dist_records (
			id TEXT PRIMARY KEY, task_id TEXT NOT NULL, state TEXT,
			payload TEXT, updated_at TIMESTAMP)`,
		`CREATE INDEX IF NOT EXISTS idx_dist_records_task ON dist_records (task_id)`,
		`CREATE TABLE IF NOT EXISTS ha_nodes (
			hub_id TEXT PRIMARY KEY, addr TEXT, role TEXT,
			last_seen TIMESTAMP, lease_until TIMESTAMP)`,
	}
	for _, s := range stmts {
		if err := p.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// ---- 波次 3 行结构（store 包不感知 hub 的领域类型，统一以 JSON 载荷落 PG） ----

// Wave3TemplateRow 静默安装参数模板行（W3-1）。
type Wave3TemplateRow struct {
	Platform  string
	PkgType   string
	Args      string
	Desc      string
	Builtin   bool
	UpdatedAt time.Time
	UpdatedBy string
}

// Wave3TaskRow 分发任务行（W3-2）。Payload 为任务 JSON（不含执行记录）。
type Wave3TaskRow struct {
	ID        string
	State     string
	Payload   string
	CreatedAt time.Time
}

// Wave3RecordRow 分发任务-设备执行记录行（W3-2/W3-4）。
type Wave3RecordRow struct {
	ID        string
	TaskID    string
	State     string
	Payload   string
	UpdatedAt time.Time
}

// Wave3NodeRow 中枢高可用节点行（W3-5）。
type Wave3NodeRow struct {
	HubID      string
	Addr       string
	Role       string
	LastSeen   time.Time
	LeaseUntil time.Time
}

func wave3JSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// ---- 模板（W3-1） ----

func Wave3UpsertTemplate(p *PostgresStore, r Wave3TemplateRow) error {
	return p.Exec(`INSERT INTO swdist_templates (platform,pkg_type,args,descr,builtin,updated_at,updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (platform,pkg_type) DO UPDATE SET args=EXCLUDED.args, descr=EXCLUDED.descr,
			builtin=EXCLUDED.builtin, updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by`,
		r.Platform, r.PkgType, r.Args, r.Desc, r.Builtin, r.UpdatedAt, r.UpdatedBy)
}

func Wave3ListTemplates(p *PostgresStore) ([]Wave3TemplateRow, error) {
	rows, err := p.QueryRows(`SELECT platform,pkg_type,args,descr,builtin,updated_at,updated_by FROM swdist_templates`)
	if err != nil {
		return nil, err
	}
	out := make([]Wave3TemplateRow, 0, len(rows))
	for _, r := range rows {
		if len(r) < 7 {
			continue
		}
		out = append(out, Wave3TemplateRow{
			Platform: r[0], PkgType: r[1], Args: r[2], Desc: r[3],
			Builtin: wave3Bool(r[4]), UpdatedAt: wave3Time(r[5]), UpdatedBy: r[6],
		})
	}
	return out, nil
}

func Wave3DeleteTemplate(p *PostgresStore, platform, pkgType string) error {
	return p.Exec(`DELETE FROM swdist_templates WHERE platform=$1 AND pkg_type=$2`, platform, pkgType)
}

// ---- 任务（W3-2） ----

func Wave3UpsertTask(p *PostgresStore, r Wave3TaskRow) error {
	return p.Exec(`INSERT INTO dist_tasks (id,state,payload,created_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (id) DO UPDATE SET state=EXCLUDED.state, payload=EXCLUDED.payload`,
		r.ID, r.State, r.Payload, r.CreatedAt)
}

func Wave3ListTasks(p *PostgresStore) ([]Wave3TaskRow, error) {
	rows, err := p.QueryRows(`SELECT id,state,payload,created_at FROM dist_tasks`)
	if err != nil {
		return nil, err
	}
	out := make([]Wave3TaskRow, 0, len(rows))
	for _, r := range rows {
		if len(r) < 4 {
			continue
		}
		out = append(out, Wave3TaskRow{ID: r[0], State: r[1], Payload: r[2], CreatedAt: wave3Time(r[3])})
	}
	return out, nil
}

func Wave3DeleteTask(p *PostgresStore, id string) error {
	return p.Exec(`DELETE FROM dist_tasks WHERE id=$1`, id)
}

// ---- 执行记录（W3-2/W3-4） ----

func Wave3UpsertRecord(p *PostgresStore, r Wave3RecordRow) error {
	return p.Exec(`INSERT INTO dist_records (id,task_id,state,payload,updated_at) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (id) DO UPDATE SET state=EXCLUDED.state, payload=EXCLUDED.payload, updated_at=EXCLUDED.updated_at`,
		r.ID, r.TaskID, r.State, r.Payload, r.UpdatedAt)
}

func Wave3ListRecords(p *PostgresStore) ([]Wave3RecordRow, error) {
	rows, err := p.QueryRows(`SELECT id,task_id,state,payload,updated_at FROM dist_records`)
	if err != nil {
		return nil, err
	}
	out := make([]Wave3RecordRow, 0, len(rows))
	for _, r := range rows {
		if len(r) < 5 {
			continue
		}
		out = append(out, Wave3RecordRow{ID: r[0], TaskID: r[1], State: r[2], Payload: r[3], UpdatedAt: wave3Time(r[4])})
	}
	return out, nil
}

func Wave3DeleteTaskRecords(p *PostgresStore, taskID string) error {
	return p.Exec(`DELETE FROM dist_records WHERE task_id=$1`, taskID)
}

// ---- 高可用节点（W3-5） ----

func Wave3UpsertNode(p *PostgresStore, r Wave3NodeRow) error {
	return p.Exec(`INSERT INTO ha_nodes (hub_id,addr,role,last_seen,lease_until) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (hub_id) DO UPDATE SET addr=EXCLUDED.addr, role=EXCLUDED.role,
			last_seen=EXCLUDED.last_seen, lease_until=EXCLUDED.lease_until`,
		r.HubID, r.Addr, r.Role, r.LastSeen, r.LeaseUntil)
}

func Wave3ListNodes(p *PostgresStore) ([]Wave3NodeRow, error) {
	rows, err := p.QueryRows(`SELECT hub_id,addr,role,last_seen,lease_until FROM ha_nodes`)
	if err != nil {
		return nil, err
	}
	out := make([]Wave3NodeRow, 0, len(rows))
	for _, r := range rows {
		if len(r) < 5 {
			continue
		}
		out = append(out, Wave3NodeRow{
			HubID: r[0], Addr: r[1], Role: r[2], LastSeen: wave3Time(r[3]), LeaseUntil: wave3Time(r[4]),
		})
	}
	return out, nil
}

func Wave3DeleteNode(p *PostgresStore, hubID string) error {
	return p.Exec(`DELETE FROM ha_nodes WHERE hub_id=$1`, hubID)
}

// ---- 小工具 ----

func wave3Bool(s string) bool {
	return s == "t" || s == "true" || s == "1" || s == "T"
}

// wave3Time 兼容 PG 的两种常见文本形态（带/不带时区与小数秒）。
func wave3Time(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
