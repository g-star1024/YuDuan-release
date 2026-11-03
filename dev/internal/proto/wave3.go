package proto

// 波次 3 协议扩展（PRD 5.3 D2/D3/D5/D6）。
//
// CommandPayload 是 M1 冻结结构，波次 3 不再改动其字段：新增参数统一以 JSON 承载在
// Command 字段内（SwDistDetail），由副端按 action 自行解析。这样未升级的旧副端收到
// sw_dist/sw_uninstall 时会落进 default 分支回 "unknown action"，不会误执行未知语义。

import (
	"encoding/json"
	"strings"
)

// 波次 3 新增指令 action。
const (
	ActionSwDist      = "sw_dist"      // 分发安装（W3-2；含模板静默参数 / 可选确认 / 卸载旧版）
	ActionSwUninstall = "sw_uninstall" // 卸载指定软件（W3-3，三平台）
	ActionSwConfirm   = "sw_confirm"   // 可选分发：终端用户已确认，继续安装（W3-2）
)

// 分发模式（W3-2）。
const (
	DistModeForced   = "forced"   // 强制：直接安装
	DistModeOptional = "optional" // 可选：副端须先回告「用户已确认」
)

// 安装包类型（与 W3-1 模板库的 pkg_type 一致）。
const (
	PkgTypeMSI = "msi"
	PkgTypeEXE = "exe"
	PkgTypeDMG = "dmg"
	PkgTypePKG = "pkg"
	PkgTypeDEB = "deb"
	PkgTypeRPM = "rpm"
	PkgTypeZIP = "zip"
)

// PkgTypes 返回全部受支持的包类型（顺序稳定，供模板库初始化与主端下拉框使用）。
func PkgTypes() []string {
	return []string{PkgTypeMSI, PkgTypeEXE, PkgTypeDMG, PkgTypePKG, PkgTypeDEB, PkgTypeRPM, PkgTypeZIP}
}

// ResultConfirmRequired 是 ResultPayload.State 的波次 3 扩展值：
// 可选分发下副端尚未取得终端用户确认（非终态，中枢据此挂起该设备的执行记录）。
const ResultConfirmRequired = "confirm_required"

// SwDistDetail 承载在 CommandPayload.Command 字段内的分发扩展参数（JSON）。
type SwDistDetail struct {
	PkgType        string `json:"pkg_type,omitempty"`         // msi/exe/dmg/pkg/deb/rpm/zip
	CustomArgs     string `json:"custom_args,omitempty"`      // 自定义命令行（覆盖模板）
	SilentArgs     string `json:"silent_args,omitempty"`      // 中枢按模板解析出的最终静默参数
	Mode           string `json:"mode,omitempty"`             // forced / optional
	Confirmed      bool   `json:"confirmed,omitempty"`        // optional：终端用户已确认（confirm 后重发为 true）
	TargetVersion  string `json:"target_version,omitempty"`   // W3-3 目标版本（空=不做版本比对）
	UninstallOld   bool   `json:"uninstall_old,omitempty"`    // W3-3 安装前卸载旧版
	CurrentVersion string `json:"current_version,omitempty"`  // 中枢侧比对到的设备当前版本
	Package        string `json:"package,omitempty"`          // 卸载目标名（sw_uninstall）
	DistTaskID     string `json:"dist_task_id,omitempty"`     // 所属分发任务（副端日志/回执可溯源）
	DistRecordID   string `json:"dist_record_id,omitempty"`   // 所属设备执行记录
	Attempt        int    `json:"attempt,omitempty"`          // 第几次尝试（1=首次）
}

// EncodeDistDetail 序列化为 CommandPayload.Command 承载的 JSON 串。
func EncodeDistDetail(d SwDistDetail) string {
	b, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(b)
}

// CompareVersion 语义化版本比较：a<b 返回 -1，相等返回 0，a>b 返回 1。
// 逐段按数值比较，缺失段补 0（1.0 == 1.0.0）；忽略前导 v 与预发布/构建元数据后缀。
// 任一为空串时视为「无版本」，排在任意具体版本之前。
func CompareVersion(a, b string) int {
	if a == "" && b == "" {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	as, bs := splitVersion(a), splitVersion(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		out = append(out, n)
	}
	return out
}
