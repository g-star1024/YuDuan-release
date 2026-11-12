package hub

import (
	"testing"

	"yuduan/internal/audit"
	"yuduan/internal/store"
)

// ---- W1-3 生命周期状态机 ----

func TestValidTransition(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{store.LifecycleInStock, store.LifecycleIssued, true},
		{store.LifecycleInStock, store.LifecycleRetired, true},
		{store.LifecycleInStock, store.LifecycleTransferred, false},
		{store.LifecycleIssued, store.LifecycleTransferred, true},
		{store.LifecycleIssued, store.LifecycleReturned, true},
		{store.LifecycleTransferred, store.LifecycleReturned, true},
		{store.LifecycleReturned, store.LifecycleInStock, true},
		{store.LifecycleRetired, store.LifecycleInStock, false},
		{store.LifecycleIssued, store.LifecycleIssued, false},
		{"", store.LifecycleIssued, false},
	}
	for _, c := range cases {
		if got := validTransition(c.from, c.to); got != c.want {
			t.Errorf("validTransition(%q,%q)=%v want %v", c.from, c.to, got, c.want)
		}
	}
}

// ---- W1-4 资产变更检测 ----

func TestDetectAssetChange(t *testing.T) {
	st := store.NewMemStore()
	h := NewHub(HubConfig{Store: st, Auditor: audit.NewMemAuditor()})
	base := store.Device{ID: "dev-1", Hostname: "host1", CPU: "i7", MemoryGB: 16, DiskGB: 512, SerialNo: "SN1", MAC: "aa:bb", Token: "tk1"}
	st.Upsert(base)

	// 无变更：不告警
	after := base
	h.detectAssetChange(base, after)
	if n := st.UnreadAlertCount(); n != 0 {
		t.Fatalf("无变更不应告警，got %d 告警", n)
	}

	// 内存/磁盘变化：告警
	after = base
	after.MemoryGB = 32
	h.detectAssetChange(base, after)
	if n := st.UnreadAlertCount(); n != 1 {
		t.Fatalf("硬件变更应 1 条告警，got %d", n)
	}
	alerts := st.ListAlerts(10)
	if alerts[0].Type != store.AlertAssetChange || alerts[0].Severity != store.SeverityCritical {
		t.Fatalf("告警类型/级别错误: %s/%s", alerts[0].Type, alerts[0].Severity)
	}
}

func TestDetectAssetChangeFirstRegister(t *testing.T) {
	st := store.NewMemStore()
	h := NewHub(HubConfig{Store: st, Auditor: audit.NewMemAuditor()})
	// 首次纳管（before.ID 为空）不应算变更
	h.detectAssetChange(store.Device{}, store.Device{ID: "new", Hostname: "h"})
	if n := st.UnreadAlertCount(); n != 0 {
		t.Fatalf("首次纳管不应告警，got %d", n)
	}
}

// ---- W1-5 告警去重 ----

func TestAlertDedup(t *testing.T) {
	st := store.NewMemStore()
	h := NewHub(HubConfig{Store: st, Auditor: audit.NewMemAuditor()})
	a := store.Alert{Type: store.AlertDeviceOffline, DeviceID: "d1", DeviceName: "h1", Message: "设备离线"}
	h.addAlert(a)
	h.addAlert(a) // 同类型未读 → 去重不新增
	if n := st.UnreadAlertCount(); n != 1 {
		t.Fatalf("告警去重失败，got %d 未读", n)
	}
	// 标记已读后再来同类型 → 新增（已读不再去重）
	alerts := st.ListAlerts(10)
	st.MarkAlertRead(alerts[0].ID)
	h.addAlert(a)
	if n := st.UnreadAlertCount(); n != 1 {
		t.Fatalf("已读后同类型应新增 1 未读，got %d", n)
	}
}

// ---- W1-2 元数据 + W1-3 生命周期落库 ----

func TestUpdateMetaAndLifecycle(t *testing.T) {
	st := store.NewMemStore()
	d := st.Upsert(store.Device{ID: "d1", Hostname: "h1", Token: "tk"})
	// 新设备默认在库
	if d.Lifecycle != store.LifecycleInStock {
		t.Fatalf("新设备默认应在库，got %q", d.Lifecycle)
	}
	// 元数据
	got, ok := st.UpdateMeta("d1", store.DeviceMeta{Department: "IT", Floor: "3F", Batch: "2026-Q4", Tags: []string{"办公", "测试"}})
	if !ok || got.Department != "IT" || got.Floor != "3F" || len(got.Tags) != 2 {
		t.Fatalf("元数据更新失败: %+v ok=%v", got, ok)
	}
	// 生命周期
	got, ok = st.TransitionLifecycle("d1", store.LifecycleTransition{State: store.LifecycleIssued, Assignee: "zhang", Note: "领用"})
	if !ok || got.Lifecycle != store.LifecycleIssued || got.Assignee != "zhang" {
		t.Fatalf("生命周期流转失败: %+v ok=%v", got, ok)
	}
}
