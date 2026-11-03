package store

import (
	"os"
	"strings"
	"testing"

	"yuduan/internal/auth"
)

// TestBackupRestoreRoundtrip 真实 PostgreSQL 备份/恢复往返验证，默认跳过。
// 运行（本地有 PG 时）：
//
//	YUDUAN_TEST_DSN="host=127.0.0.1 port=5432 user=postgres dbname=yuduan" go test ./internal/store/ -run TestBackupRestore -v
//
// 验证点：BackupSQL 生成合法 SQL / RestoreSQL 还原数据 / NULL+单引号+分号+空串精确往返。
func TestBackupRestoreRoundtrip(t *testing.T) {
	dsn := os.Getenv("YUDUAN_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 YUDUAN_TEST_DSN，跳过备份/恢复集成测试")
	}
	p, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("连接/迁移失败: %v", err)
	}

	// 造含边界值的设备：单引号 / 分号 / 空串 / NULL 字段
	dev := Device{
		Hostname:   "it's-a;test-host", // 单引号 + 分号
		OS:         "linux",
		OSVersion:  "",
		Arch:       "x86_64",
		CPU:        "test",
		MemoryGB:   8,
		DiskGB:     64,
		SerialNo:   "SN-boundary",
		MAC:        "00:11:22:33:44:55",
		IP:         "10.0.0.10",
		Department: "", // 空串
		// Floor/Batch 留空 → NULL（不设置）
	}
	// 强制 NULL 列（Department 置空后 Upsert 会把空串写入；用 Floor 演示 NULL）
	saved := p.Upsert(dev)
	p.AddAlert(Alert{Type: "device_offline", Severity: "critical", DeviceID: saved.ID, DeviceName: "host", Message: "offline;alert"})
	p.UpsertUser(auth.User{Username: "bk-user", DisplayName: "备份用户", Role: "viewer"})

	// 1) 备份
	data, err := p.BackupSQL()
	if err != nil {
		t.Fatalf("BackupSQL 失败: %v", err)
	}
	sqlText := string(data)
	if !strings.Contains(sqlText, "INSERT INTO") {
		t.Fatalf("备份未包含 INSERT 语句")
	}
	if !strings.Contains(sqlText, "INSERT INTO \"devices\"") {
		t.Fatalf("备份未包含 devices 表（设备持久化失败？）")
	}
	if !strings.Contains(sqlText, "it''s-a;test-host") {
		t.Fatalf("备份未正确转义单引号/分号 hostname")
	}

	// 2) 改数据（验证恢复后还原）
	p.Upsert(Device{ID: saved.ID, Hostname: "mutated", OS: "windows"}) // 覆盖
	p.MarkOffline(saved.ID)

	// 3) 恢复
	if err := p.RestoreSQL(data); err != nil {
		t.Fatalf("RestoreSQL 失败: %v", err)
	}

	// 4) 验证还原
	got, ok := p.Get(saved.ID)
	if !ok {
		t.Fatalf("恢复后设备丢失")
	}
	if got.Hostname != "it's-a;test-host" {
		t.Fatalf("hostname 还原错误: %q", got.Hostname)
	}
	if !got.Online {
		t.Fatalf("恢复后应在线（MarkOffline 被回滚）")
	}
	if got.Department != "" {
		t.Fatalf("Department 应为空串，得到 %q", got.Department)
	}
	// 告警还原
	alerts := p.ListAlerts(10)
	found := false
	for _, a := range alerts {
		if a.Message == "offline;alert" {
			found = true
		}
	}
	if !found {
		t.Fatalf("恢复后告警丢失")
	}
	// 用户还原
	if _, ok := p.GetUserByName("bk-user"); !ok {
		t.Fatalf("恢复后用户丢失")
	}
}
