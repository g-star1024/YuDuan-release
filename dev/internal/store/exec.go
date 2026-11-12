package store

// exec.go —— 波次 3/4/5 的仓储扩展点。
//
// 设计目的：新增波次不应修改既有 postgres.go / store.go 的核心逻辑（避免多波次并行
// 开发时的文件冲突）。这里提供两个能力：
//
//  1. RegisterMigrate：注册自定义建表/加列语句，migrate() 结尾统一执行（幂等）。
//  2. Exec / QueryRows / QueryOne：把私有连接池辅助方法导出，供波次模块写自己的仓储。

import "sync"

var (
	migrateMu    sync.Mutex
	migrateHooks []func(p *PostgresStore) error
)

// RegisterMigrate 注册一条迁移钩子。钩子在 migrate() 建完核心表后按注册顺序执行，
// 每条语句都应写成幂等（CREATE TABLE IF NOT EXISTS / ALTER TABLE ... IF NOT EXISTS）。
// 返回 error 会中断 migrate（进而中断中枢启动），因此仅用于真正的致命错误。
func RegisterMigrate(fn func(p *PostgresStore) error) {
	migrateMu.Lock()
	defer migrateMu.Unlock()
	migrateHooks = append(migrateHooks, fn)
}

// runMigrateHooks 由 migrate() 调用。
func (p *PostgresStore) runMigrateHooks() error {
	migrateMu.Lock()
	defer migrateMu.Unlock()
	for _, fn := range migrateHooks {
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}

// Exec 执行写语句（INSERT/UPDATE/DELETE/DDL），参数用 $1,$2... 占位。
func (p *PostgresStore) Exec(sql string, args ...any) error { return p.exec(sql, args...) }

// QueryRows 执行查询语句，返回行集合；每行为字符串切片（按列顺序）。
func (p *PostgresStore) QueryRows(sql string, args ...any) ([][]string, error) {
	return p.query(sql, args...)
}

// QueryOne 执行查询语句并取首行；ok=false 表示无结果。
func (p *PostgresStore) QueryOne(sql string, args ...any) ([]string, bool, error) {
	return p.queryRow(sql, args...)
}
