package store

import (
	"fmt"
	"strings"
	"time"
)

// Backupable 表示可导出/恢复全库快照的存储实现。
// 仅 PostgreSQL 生产后端实现（内存后端为开发/演示，不投产，无需备份）。
type Backupable interface {
	// BackupSQL 导出全库为可执行的 SQL 脚本（BEGIN; INSERT...; COMMIT;）。
	// 每列用 coalesce(quote_literal(col),'NULL') 生成字面量，
	// NULL→NULL、空串→''、单引号→'' 转义均正确（修复 parseDataRow 把 NULL 当空串的失真）。
	BackupSQL() ([]byte, error)
	// RestoreSQL 全量恢复：单事务内 TRUNCATE 全部表 + 重放备份 INSERT（原子，失败回滚）。
	RestoreSQL(data []byte) error
}

// splitSQLStatements 按分号分割 SQL，跳过字符串字面量内的分号（'a;b' 不分割）。
// 字符串外的 `--` 行注释整体跳到行尾（不作为语句输出，避免恢复时被误判跳过）。
// 备份仅含 INSERT/BEGIN/COMMIT（无 $$ 函数体），此分割器足够。
func splitSQLStatements(sql string) []string {
	var stmts []string
	var cur strings.Builder
	inStr := false
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if inStr {
			cur.WriteByte(c)
			if c == '\'' {
				if i+1 < len(sql) && sql[i+1] == '\'' { // '' 转义（SQL 内字面单引号）
					cur.WriteByte(sql[i+1])
					i++
				} else {
					inStr = false
				}
			}
			continue
		}
		if c == '-' && i+1 < len(sql) && sql[i+1] == '-' {
			// 行注释：跳过至行尾（注释总在语句之间，缓冲此时为空或仅空白）
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			continue
		}
		switch c {
		case '\'':
			inStr = true
			cur.WriteByte(c)
		case ';':
			if s := strings.TrimSpace(cur.String()); s != "" {
				stmts = append(stmts, s)
			}
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}

// quoteIdent 用双引号包裹标识符（表/列名），保留大小写与关键字安全。
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// ---- PostgreSQL 实现 ----

// sessionBackupTable 是会话安全（v0.4.31-E）的服务端会话表。
// 会话是易失鉴权态，不进快照；恢复后所有客户端重新登录。
const sessionBackupTable = "yuduan_sessions"

// isSessionTableInsert 判断一条备份 INSERT 是否针对会话表。RestoreSQL 重放时跳过，
// 否则「历史备份」（旧代码导出时含会话表 INSERT）会把已吊销/已过期的旧会话写回，
// 令牌随之复活 = 越权。抽成纯函数便于离线单测。
//
// 注意：strings.ToUpper 会把表名一并大写，故前缀常量必须写成大写
// "YUDUAN_SESSIONS"（若写成小写 "yuduan_sessions" 将永远匹配不上——本次复核
// 规避的常见坑）。前缀以闭合双引号收尾，避免误伤 "yuduan_sessions_xxx" 等同前缀表。
func isSessionTableInsert(stmt string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(stmt)), `INSERT INTO "YUDUAN_SESSIONS"`)
}

func (p *PostgresStore) listTables() ([]string, error) {
	rows, err := p.query(
		`SELECT tablename FROM pg_tables
		 WHERE schemaname='public' AND tablename NOT LIKE 'pg_%' ORDER BY tablename`)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r[0])
	}
	return out, nil
}

func (p *PostgresStore) columnsOf(table string) ([]string, error) {
	rows, err := p.query(
		`SELECT column_name FROM information_schema.columns
		 WHERE table_name=$1 AND table_schema='public' ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r[0])
	}
	return out, nil
}

// BackupSQL 导出全部 public 表为 INSERT 脚本（可读、可 psql 恢复）。
func (p *PostgresStore) BackupSQL() ([]byte, error) {
	tables, err := p.listTables()
	if err != nil {
		return nil, fmt.Errorf("list tables: %v", err)
	}
	var sb strings.Builder
	sb.WriteString("-- yuduan-hub full database backup\n")
	sb.WriteString("-- generated: " + time.Now().UTC().Format(time.RFC3339) + "\n")
	sb.WriteString("BEGIN;\n")
	for _, t := range tables {
		// v0.4.31-E：会话是易失鉴权态，不进快照；否则恢复一次备份即把旧会话
		//（含已吊销/已过期）原样写回、令牌复活 = 越权。排除只做在导出循环里：
		// listTables() 被 BackupSQL/RestoreSQL 共用，若改它的 SQL 排除，RestoreSQL
		// 的 TRUNCATE 会漏掉会话表，反而更糟（旧会话根本没被清空）。
		if t == sessionBackupTable {
			continue
		}
		cols, err := p.columnsOf(t)
		if err != nil {
			return nil, fmt.Errorf("columns of %s: %v", t, err)
		}
		if len(cols) == 0 {
			continue
		}
		exprs := make([]string, len(cols))
		colList := make([]string, len(cols))
		for i, c := range cols {
			// quote_literal 正确转义 NULL/引号；NULL 结果本身是 SQL NULL（parseDataRow 会
			// 变 ""），故用 coalesce 兜成字面量字符串 'NULL'，拼接后即合法 NULL 关键字。
			exprs[i] = "coalesce(quote_literal(" + quoteIdent(c) + "), 'NULL')"
			colList[i] = quoteIdent(c)
		}
		rows, err := p.query("SELECT " + strings.Join(exprs, ",") + " FROM " + quoteIdent(t))
		if err != nil {
			return nil, fmt.Errorf("dump %s: %v", t, err)
		}
		for _, r := range rows {
			sb.WriteString("INSERT INTO " + quoteIdent(t) + " (" + strings.Join(colList, ",") +
				") VALUES (" + strings.Join(r, ",") + ");\n")
		}
	}
	sb.WriteString("COMMIT;\n")
	return []byte(sb.String()), nil
}

// RestoreSQL 全量恢复：同一连接单事务 TRUNCATE + 重放 INSERT（原子）。
func (p *PostgresStore) RestoreSQL(data []byte) error {
	tables, err := p.listTables()
	if err != nil {
		return fmt.Errorf("list tables: %v", err)
	}
	c, err := p.pool.Acquire()
	if err != nil {
		return err
	}
	defer p.pool.Release(c)
	rollback := func() { _, _, _ = c.Query("ROLLBACK") }

	if _, _, err := c.Query("BEGIN"); err != nil {
		return fmt.Errorf("begin: %v", err)
	}
	// TRUNCATE 不触发行级 DML 触发器（WORM 触发器是 BEFORE UPDATE OR DELETE），安全。
	qt := make([]string, len(tables))
	for i, t := range tables {
		qt[i] = quoteIdent(t)
	}
	if _, _, err := c.Query("TRUNCATE " + strings.Join(qt, ",") + " RESTART IDENTITY CASCADE"); err != nil {
		rollback()
		return fmt.Errorf("truncate: %v", err)
	}
	// 重放备份 INSERT（跳过事务控制/注释语句）
	for _, stmt := range splitSQLStatements(string(data)) {
		s := strings.TrimSpace(stmt)
		if s == "" || strings.HasPrefix(s, "--") {
			continue
		}
		up := strings.ToUpper(s)
		if strings.HasPrefix(up, "BEGIN") || strings.HasPrefix(up, "COMMIT") || strings.HasPrefix(up, "ROLLBACK") {
			continue
		}
		// v0.4.31-E：跳过针对会话表的 INSERT（兼容历史备份）。TRUNCATE 已全量清空
		// 会话表，只要不重放会话 INSERT，恢复后会话表即空，旧令牌不复活。
		// 故无需「恢复后兜底清空」，改动最小且对历史备份同样生效。
		if isSessionTableInsert(s) {
			continue
		}
		if _, _, err := c.Query(s); err != nil {
			rollback()
			return fmt.Errorf("restore stmt: %v", err)
		}
	}
	if _, _, err := c.Query("COMMIT"); err != nil {
		rollback()
		return fmt.Errorf("commit: %v", err)
	}
	return nil
}
