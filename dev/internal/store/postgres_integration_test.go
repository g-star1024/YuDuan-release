package store

import (
	"os"
	"testing"
	"time"

	"yuduan/internal/audit"
	"yuduan/internal/auth"
)

// TestPostgresPersistence 是针对真实 PostgreSQL 的集成测试，默认跳过。
// 运行方式（本地有 PG 时）：
//
//	YUDUAN_TEST_DSN="host=127.0.0.1 port=5432 user=postgres dbname=yuduan" go test ./internal/store/ -run TestPostgres -v
//
// 验证点：建表迁移 / 设备 Upsert+跨连接持久化（模拟中枢重启）/ 审计落库 / 用户存储。
func TestPostgresPersistence(t *testing.T) {
	dsn := os.Getenv("YUDUAN_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 YUDUAN_TEST_DSN，跳过 PostgreSQL 集成测试")
	}

	p, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("连接/迁移失败: %v", err)
	}

	// 唯一 hostname 避免与历史数据冲突
	host := "pgtest-" + newID()
	dev := Device{
		Hostname: host, OS: "linux", OSVersion: "test", Arch: "x86_64",
		CPU: "test-cpu", MemoryGB: 8, DiskGB: 64, SerialNo: "SN-" + newID(), MAC: "00:11:22:33:44:55",
		IP: "10.0.0.9", AgentVersion: "0.1.0",
	}
	saved := p.Upsert(dev)
	if saved.ID == "" {
		t.Fatalf("Upsert 未生成 ID")
	}
	if !saved.Online {
		t.Fatalf("Upsert 后应在线")
	}

	// 审计 + 用户
	p.Record(audit.Event{Actor: "pgtest", Action: "test_action", Target: saved.ID, Detail: "detail", Result: "success"})
	p.UpsertUser(auth.User{Username: "pguser", DisplayName: "PG Tester", Role: "viewer"})

	// 模拟“中枢重启”：新建一个连接（全新 PostgresStore），数据应仍在。
	p2, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("二次连接失败: %v", err)
	}
	got, ok := p2.Get(saved.ID)
	if !ok {
		t.Fatalf("重启后设备丢失（持久化失败）id=%s", saved.ID)
	}
	if got.Hostname != host {
		t.Fatalf("重启后 hostname 不符: %s != %s", got.Hostname, host)
	}
	u, ok := p2.GetUserByName("pguser")
	if !ok || u.Role != "viewer" {
		t.Fatalf("重启后用户丢失: %+v ok=%v", u, ok)
	}
	if p2.AuditCount() < 1 {
		t.Fatalf("重启后审计为空")
	}

	// 清理测试数据
	p2.MarkOffline(saved.ID)
	t.Logf("OK: 设备 %s 跨连接持久化成功，审计 %d 条", saved.ID, p2.AuditCount())
	_ = time.Now
}
