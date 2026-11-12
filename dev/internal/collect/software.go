// 软件资产清单采集（W1-1，PRD 5.1 B2）。
// 入口 Software() 按平台分发：Windows 走注册表 Uninstall 键；macOS 扫 /Applications
// .app 包读 Info.plist；Linux 走 dpkg/rpm 查询。均返回归一化 []proto.InstalledSoftware。
// 采集粒度：Wave 1 基础版为「应用/包级」清单，许可证字段留空待主端手动补充。
package collect

import (
	"sync"

	"yuduan/internal/proto"
)

var (
	softwareOnce  sync.Once
	softwareCache []proto.InstalledSoftware
)

// Software 返回当前主机已安装软件清单（进程级缓存：重连不重复枚举）。
func Software() []proto.InstalledSoftware {
	softwareOnce.Do(func() { softwareCache = platformSoftware() })
	return softwareCache
}
