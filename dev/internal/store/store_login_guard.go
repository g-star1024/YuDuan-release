// store_login_guard.go —— v0.4.31-C 登录防爆破「全局按源 IP」的 PG 分布式锁定状态。
//
// 约束：沿用 exec.go 扩展点（RegisterMigrate 幂等建表 + Exec/QueryOne 读写），
// 零修改 postgres.go / store.go 主体。内存模式不触达本文件，单实例行为不变。
//
// 表只存「锁定截止」而非失败计数：失败计数保留在各中枢实例内存（低延迟、无写放大），
// 达阈值后把锁定发布到 PG，多中枢实例共享同一把锁；登录成功即清除共享锁。
package store

func init() {
	RegisterMigrate(func(p *PostgresStore) error {
		return p.Exec(`CREATE TABLE IF NOT EXISTS yuduan_login_guard_ip (
			ip TEXT PRIMARY KEY,
			locked_until TIMESTAMPTZ,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`)
	})
}
