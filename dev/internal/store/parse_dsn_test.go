package store

import "testing"

// TestParseDSN 覆盖 DSN 解析：libpq 键值格式与 postgres:// URL 格式（含 query/ipv6/默认值）。
// URL 格式是 env.example 曾给出的示例，此前 parseDSN 不支持，用户照示例配置会解析失败。
func TestParseDSN(t *testing.T) {
	cases := []struct {
		name             string
		dsn              string
		wantHost         string
		wantPort         int
		wantUser, wantDB string
		wantPass         string
	}{
		{"键值全量", "host=db.internal port=5433 user=yuduan dbname=yuduan password=secret",
			"db.internal", 5433, "yuduan", "yuduan", "secret"},
		{"URL全量", "postgres://yuduan:secret@db.internal:5433/yuduan",
			"db.internal", 5433, "yuduan", "yuduan", "secret"},
		{"URL无端口", "postgres://yuduan@db.internal/yuduan",
			"db.internal", 5432, "yuduan", "yuduan", ""},
		{"URL带query忽略", "postgres://yuduan:secret@127.0.0.1:5432/yuduan?sslmode=disable&connect_timeout=10",
			"127.0.0.1", 5432, "yuduan", "yuduan", "secret"},
		{"URL ipv6", "postgres://yuduan@[::1]:5433/yuduan",
			"::1", 5433, "yuduan", "yuduan", ""},
		{"URL password含冒号", "postgres://yuduan:p@ss:w0rd@h:5432/db",
			"h", 5432, "yuduan", "db", "p@ss:w0rd"},
		{"URL 无dbname", "postgres://yuduan:secret@db.internal:5433",
			"db.internal", 5433, "yuduan", "", "secret"},
		{"空串默认", "", "127.0.0.1", 5432, "", "", ""},
		{"键值部分", "host=localhost", "localhost", 5432, "", "", ""},
		{"键值 database 别名", "host=h user=u database=mydb",
			"h", 5432, "u", "mydb", ""},
	}
	for _, c := range cases {
		host, port, user, db, pass := parseDSN(c.dsn)
		if host != c.wantHost || port != c.wantPort || user != c.wantUser || db != c.wantDB || pass != c.wantPass {
			t.Errorf("%s: parseDSN(%q) = (%q,%d,%q,%q,%q), want (%q,%d,%q,%q,%q)",
				c.name, c.dsn, host, port, user, db, pass,
				c.wantHost, c.wantPort, c.wantUser, c.wantDB, c.wantPass)
		}
	}
}
