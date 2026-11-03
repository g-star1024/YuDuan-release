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
