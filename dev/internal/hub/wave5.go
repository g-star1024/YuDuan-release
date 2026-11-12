package hub

import "net/http"

// wave5Routes —— 波次 5 路由聚合点。
//
// 波次 5 由两个并行开发单元实现，各自在自己的文件内提供挂载函数，
// 这里统一转发，避免多单元修改 hub.go 造成冲突：
//   - wave5a.go：W5-1 合规基线 / W5-2 违规软件黑名单 / W5-5 漏洞扫描与补丁闭环
//   - wave5b.go：W5-3 外设管控 / W5-4 网络准入 / W5-7 报表与统计
//   - wave5c.go：W5-6 策略中心（模板/分组差异化/灰度+回滚/生效统计）
func wave5Routes(mux *http.ServeMux, h *Hub) {
	wave5aRoutes(mux, h)
	wave5bRoutes(mux, h)
	wave5cRoutes(mux, h)
}

// v0.4.25 漏洞统计数据源接线：依赖倒置钩子（遵守上面的波次隔离纪律）。
// wave5b.go 只消费本钩子，不引用 wave5a.go 的任何符号；由 wave5a.go 的 init()
// 注册实现。provider 为 nil 时 stats/overview 自动回退到 v0.4.24 的占位结果，
// 便于灰度与秒级回滚。
//
// 返回契约：map[string]any 至少含 available(bool) / total(int) /
// by_severity(map[string]int —— w5bStatsTable 硬断言依赖该具体类型) / note(string)；
// by_severity 按波次 5a 真实严重度原值分桶，附加 by_severity_raw 保留原始分布。
var vulnOverviewProvider func(*Hub) map[string]any
