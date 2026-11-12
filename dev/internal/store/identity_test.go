package store

import "testing"

// v0.4.8（实测报告问题 4）：设备注册幂等化——token 轮换后按硬件身份（serial →
// hostname+mac）复用既有设备 ID，避免同一台机器重复建档（PG 模式台账重复、审计断链）。
func TestFindByIdentityReusesDevice(t *testing.T) {
	m := NewMemStore()

	first := m.Upsert(Device{Hostname: "PC-001", MAC: "aa:bb:cc:dd:ee:01", SerialNo: "SN-XYZ-1", Token: "tok-1"})
	if first.ID == "" {
		t.Fatal("首次注册应生成设备 ID")
	}

	// token 轮换（重新 claim）后：同 serial → 必须命中同一设备
	got, ok := m.FindByIdentity("PC-001", "aa:bb:cc:dd:ee:01", "SN-XYZ-1")
	if !ok || got.ID != first.ID {
		t.Fatalf("serial 应命中既有设备：ok=%v id=%s want=%s", ok, got.ID, first.ID)
	}

	// 无 serial 时 hostname+mac 兜底
	got2, ok2 := m.FindByIdentity("PC-001", "aa:bb:cc:dd:ee:01", "")
	if !ok2 || got2.ID != first.ID {
		t.Fatalf("hostname+mac 应命中既有设备：ok=%v id=%s want=%s", ok2, got2.ID, first.ID)
	}

	// 陌生机器不误命中
	if _, ok3 := m.FindByIdentity("PC-002", "ff:ee:dd:cc:bb:aa", "SN-OTHER"); ok3 {
		t.Fatal("陌生硬件身份不应命中")
	}
	if _, ok4 := m.FindByIdentity("PC-001", "ff:ee:dd:cc:bb:aa", ""); ok4 {
		t.Fatal("hostname 相同但 mac 不同不应命中")
	}
}

// Upsert 以既有 ID 覆盖更新（幂等注册路径）时：保留 CreatedAt、清理旧 token 映射。
func TestUpsertWithExistingIDPreservesCreatedAtAndRotatesToken(t *testing.T) {
	m := NewMemStore()

	first := m.Upsert(Device{Hostname: "PC-001", MAC: "aa:bb:cc:dd:ee:01", SerialNo: "SN-XYZ-1", Token: "tok-old"})
	created := first.CreatedAt
	if created.IsZero() {
		t.Fatal("CreatedAt 不应为零值")
	}

	// 模拟 token 轮换后注册：同 ID、新 token、硬件字段刷新
	second := m.Upsert(Device{
		ID: first.ID, Hostname: "PC-001", MAC: "aa:bb:cc:dd:ee:01", SerialNo: "SN-XYZ-1",
		Token: "tok-new", AgentVersion: "0.4.8", CreatedAt: created,
	})
	if second.ID != first.ID {
		t.Fatalf("显式 ID 的 Upsert 不应改设备 ID：got=%s want=%s", second.ID, first.ID)
	}
	if !second.CreatedAt.Equal(created) {
		t.Fatalf("CreatedAt 应保留：got=%v want=%v", second.CreatedAt, created)
	}
	if second.Online != true {
		t.Fatal("注册更新后应在线")
	}

	// 旧 token 不再命中；新 token 命中
	if _, ok := m.GetByToken("tok-old"); ok {
		t.Fatal("轮换后的旧 token 不应再命中该设备")
	}
	got, ok := m.GetByToken("tok-new")
	if !ok || got.ID != first.ID {
		t.Fatalf("新 token 应命中同一设备：ok=%v id=%s", ok, got.ID)
	}
}
