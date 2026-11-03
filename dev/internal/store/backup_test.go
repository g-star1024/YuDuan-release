package store

import (
	"reflect"
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
		"devices":    `"devices"`,
		"my table":   `"my table"`,
		`we"ird`:     `"we""ird"`,
	}
	for in, want := range cases {
		if got := quoteIdent(in); got != want {
			t.Errorf("quoteIdent(%q) = %q, want %q", in, got, want)
		}
	}
}
