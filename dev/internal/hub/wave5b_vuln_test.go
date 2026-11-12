package hub

// wave5b_vuln_test.go —— v0.4.25：stats/overview 漏洞统计接通波次 5a 真实数据源的回归测试。
// 覆盖：open 项按真实严重度（info/warning/critical）分桶；patched/accepted 不计入；
// 空数据源 available 仍为 true（真实空集而非「未接入」）；内存与 PG 共用同一状态入口。

import "testing"

func newVulnStatsHub(t *testing.T) *Hub {
	t.Helper()
	return NewHub(HubConfig{HMACSecret: "secret-vuln", HubID: "hub-vuln-stats-test"})
}

func seedVulnItems(h *Hub, items ...*VulnItem) {
	s := w5a(h)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vulnItems = map[string]*VulnItem{}
	for _, it := range items {
		s.vulnItems[it.ID] = it
	}
}

func TestW5aVulnSeverityCounts_OnlyOpenByRealSeverity(t *testing.T) {
	h := newVulnStatsHub(t)
	seedVulnItems(h,
		&VulnItem{ID: "v1", Severity: "critical", State: VulnStateOpen},
		&VulnItem{ID: "v2", Severity: "critical", State: VulnStateOpen},
		&VulnItem{ID: "v3", Severity: "warning", State: VulnStateOpen},
		&VulnItem{ID: "v4", Severity: "info", State: VulnStateOpen},
		&VulnItem{ID: "v5", Severity: "critical", State: VulnStatePatched},  // 已修复不计
		&VulnItem{ID: "v6", Severity: "critical", State: VulnStateAccepted}, // 已接受不计
		&VulnItem{ID: "v7", Severity: "custom-high", State: VulnStateOpen},  // 自定义取值兼容
	)
	open, bySev := h.w5aVulnSeverityCounts()
	if open != 5 {
		t.Fatalf("open 项应为 5（仅 open 状态），got %d", open)
	}
	want := map[string]int{"critical": 2, "warning": 1, "info": 1, "custom-high": 1}
	for k, v := range want {
		if bySev[k] != v {
			t.Fatalf("分桶 %s 应为 %d，got %d（全量 %v）", k, v, bySev[k], bySev)
		}
	}
	if len(bySev) != len(want) {
		t.Fatalf("分桶不应产生多余 key，got %v", bySev)
	}
}

func TestStatsOverviewVuln_UsesRealDataSource(t *testing.T) {
	h := newVulnStatsHub(t)
	seedVulnItems(h,
		&VulnItem{ID: "v1", Severity: "critical", State: VulnStateOpen},
		&VulnItem{ID: "v2", Severity: "warning", State: VulnStateOpen},
		&VulnItem{ID: "v3", Severity: "info", State: VulnStatePatched},
	)
	ov := h.buildStatsOverview()
	vu, ok := ov["vuln"].(map[string]any)
	if !ok {
		t.Fatal("overview 应含 vuln 段")
	}
	if vu["available"] != true {
		t.Fatalf("数据源已接通，available 应为 true，got %v", vu["available"])
	}
	if got := anyInt(vu["total"]); got != 2 {
		t.Fatalf("total 应为 2，got %d", got)
	}
	sev, ok := vu["by_severity"].(map[string]int)
	if !ok {
		t.Fatalf("by_severity 必须是 map[string]int（报表依赖该类型断言），got %T", vu["by_severity"])
	}
	if sev["critical"] != 1 || sev["warning"] != 1 {
		t.Fatalf("真实分桶错误: %v", sev)
	}
	if _, has := sev["info"]; has {
		t.Fatalf("patched 项不应进入分桶: %v", sev)
	}
}

func TestStatsOverviewVuln_EmptySourceIsAvailable(t *testing.T) {
	h := newVulnStatsHub(t)
	seedVulnItems(h) // 空数据源
	vu := h.buildStatsOverview()["vuln"].(map[string]any)
	if vu["available"] != true {
		t.Fatalf("空集也应标 available=true（真实空集，非未接入），got %v", vu["available"])
	}
	if got := anyInt(vu["total"]); got != 0 {
		t.Fatalf("空集 total 应为 0，got %d", got)
	}
	if _, ok := vu["by_severity"].(map[string]int); !ok {
		t.Fatal("空集 by_severity 仍须是 map[string]int，否则报表类型断言失败")
	}
}
