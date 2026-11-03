package store

// store_wave4.go —— 波次 4（文件分发与采集 / 批量命令与脚本）的持久化扩展点。
//
// 设计约束：不得修改既有 store.go / postgres.go；全部经 exec.go 的扩展点实现
// （RegisterMigrate 幂等建表，Exec/QueryRows 读写）。内存模式（e2e 与默认）由
// hub 包的 wave4.go 内存态承载；仅 *PostgresStore 时中枢做尽力而为的双写。

import "time"

func init() { RegisterMigrate(migrateWave4) }

func migrateWave4(p *PostgresStore) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS filesync_tasks (
			id TEXT PRIMARY KEY, state TEXT, payload TEXT, created_at TIMESTAMP)`,
		`CREATE INDEX IF NOT EXISTS idx_filesync_state ON filesync_tasks (state)`,
		`CREATE TABLE IF NOT EXISTS batchcmd_tasks (
			id TEXT PRIMARY KEY, state TEXT, payload TEXT, created_at TIMESTAMP)`,
		`CREATE INDEX IF NOT EXISTS idx_batchcmd_state ON batchcmd_tasks (state)`,
	}
	for _, s := range stmts {
		if err := p.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// ---- 波次 4 行结构（JSON 载荷落 PG，store 不感知 hub 领域类型） ----

type Wave4TaskRow struct {
	ID        string
	State     string
	Payload   string
	CreatedAt time.Time
}

func Wave4UpsertTask(p *PostgresStore, table, id, state, payload string, created time.Time) error {
	return p.Exec(`INSERT INTO `+table+` (id,state,payload,created_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (id) DO UPDATE SET state=EXCLUDED.state, payload=EXCLUDED.payload`,
		id, state, payload, created)
}

func Wave4ListTasks(p *PostgresStore, table string) ([]Wave4TaskRow, error) {
	rows, err := p.QueryRows(`SELECT id,state,payload,created_at FROM ` + table)
	if err != nil {
		return nil, err
	}
	out := make([]Wave4TaskRow, 0, len(rows))
	for _, r := range rows {
		if len(r) < 4 {
			continue
		}
		out = append(out, Wave4TaskRow{ID: r[0], State: r[1], Payload: r[2], CreatedAt: wave4Time(r[3])})
	}
	return out, nil
}

func wave4Time(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999-07:00", "2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999", "2006-01-02 15:04:05", time.RFC3339Nano, time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
