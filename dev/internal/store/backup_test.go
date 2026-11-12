package store

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplitSQLStatements(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want []string
	}{
		{"单语句", "INSERT INTO t VALUES (1);", []string{"INSERT INTO t VALUES (1)"}},
		{"多语句", "INSERT INTO t VALUES (1);INSERT INTO t VALUES (2);", []string{"INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (2)"}},
		{"字符串内分号不分割", `INSERT INTO t VALUES ('a;b');INSERT INTO t VALUES (2);`, []string{"INSERT INTO t VALUES ('a;b')", "INSERT INTO t VALUES (2)"}},
		{"单引号转义", `INSERT INTO t VALUES ('it''s;ok');`, []string{"INSERT INTO t VALUES ('it''s;ok')"}},
		{"NULL 字面量", `INSERT INTO t VALUES (NULL, 'abc');`, []string{"INSERT INTO t VALUES (NULL, 'abc')"}},
		{"注释与空语句跳过", "-- header\n\nINSERT INTO t VALUES (1);\n;", []string{"INSERT INTO t VALUES (1)"}},
		{"行内注释后语句", "-- header\nINSERT INTO t VALUES (1);", []string{"INSERT INTO t VALUES (1)"}},
		{"尾部无分号", "INSERT INTO t VALUES (1)", []string{"INSERT INTO t VALUES (1)"}},
	}
	for _, c := range cases {
		got := splitSQLStatements(c.sql)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: splitSQLStatements(%q) = %#v, want %#v", c.name, c.sql, got, c.want)
		}
	}
}

func TestQuoteIdent(t *testing.T) {
	cases := map[string]string{
		"devices":  `"devices"`,
		"my table": `"my table"`,
		`we"ird`:   `"we""ird"`,
	}
	for in, want := range cases {
		if got := quoteIdent(in); got != want {
			t.Errorf("quoteIdent(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- v0.4.31-E：备份/恢复不复活会话（离线，复用 splitSQLStatements/quoteIdent）----

// TestIsSessionTableInsert 钉死会话表 INSERT 识别：修正 strings.ToUpper 会把表名
// 一并大写、前缀常量须为大写的坑（小写前缀将永不匹配），并验证不误伤同前缀表 / 值。
func TestIsSessionTableInsert(t *testing.T) {
	yes := []string{
		`INSERT INTO "yuduan_sessions" ("sid") VALUES ('s1')`,
		`insert into "yuduan_sessions" ("sid") VALUES ('s1')`,     // 小写关键字
		`  INSERT INTO "yuduan_sessions" ("sid") VALUES ('s1')  `, // 前后空白
		`INSERT INTO "YUDUAN_SESSIONS" ("sid") VALUES ('s1')`,     // 表名大写
	}
	for _, s := range yes {
		if !isSessionTableInsert(s) {
			t.Errorf("会话表 INSERT 应被识别并跳过: %q", s)
		}
	}
	no := []string{
		`INSERT INTO "devices" ("id") VALUES ('d1')`,
		`INSERT INTO "yuduan_sessions_archive" ("sid") VALUES ('s1')`, // 同前缀不误伤
		`INSERT INTO "users" ("name") VALUES ('yuduan_sessions')`,     // 值含表名不误判
		`BEGIN`, `COMMIT`, `-- comment`, ``,
	}
	for _, s := range no {
		if isSessionTableInsert(s) {
			t.Errorf("非会话表语句不应被跳过: %q", s)
		}
	}
}

// TestRestoreSkipsSessionInserts 离线证明「备份恢复不复活会话」：
// 构造一份含会话表 INSERT 的历史备份文本，走 splitSQLStatements + 与 RestoreSQL
// 相同的跳过逻辑，断言会话 INSERT 被丢弃、其它表 INSERT 全部保留。TRUNCATE 已
// 全量清空会话表，不重放即空 ⇒ 恢复后已吊销/过期旧令牌不复活。
func TestRestoreSkipsSessionInserts(t *testing.T) {
	legacy := "BEGIN;\n" +
		`INSERT INTO "devices" ("id") VALUES ('d1');` + "\n" +
		`INSERT INTO "yuduan_sessions" ("sid","revoked") VALUES ('old-sid',FALSE);` + "\n" +
		`INSERT INTO "users" ("name") VALUES ('alice');` + "\n" +
		"COMMIT;"
	var replay []string
	for _, stmt := range splitSQLStatements(legacy) {
		s := strings.TrimSpace(stmt)
		if s == "" || strings.HasPrefix(s, "--") {
			continue
		}
		up := strings.ToUpper(s)
		if strings.HasPrefix(up, "BEGIN") || strings.HasPrefix(up, "COMMIT") || strings.HasPrefix(up, "ROLLBACK") {
			continue
		}
		if isSessionTableInsert(s) {
			continue
		}
		replay = append(replay, s)
	}
	if len(replay) != 2 {
		t.Fatalf("应重放 2 条（devices + users），实际 %d: %#v", len(replay), replay)
	}
	for _, s := range replay {
		if isSessionTableInsert(s) {
			t.Fatalf("重放集合仍含会话表 INSERT（会复活旧会话）: %q", s)
		}
	}
}
