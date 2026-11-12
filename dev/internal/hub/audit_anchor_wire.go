// audit_anchor_wire.go —— v0.4.31-D 审计链尾外锚的签名器 / 库外锚文件接线。
//
// 本文件为「独立新建文件」：通过 init() 把服务端签名器与库外锚文件记录器注入 audit 包，
// 从而零修改 main.go / hub.go（并行 worker 正在改这两个文件实现会话安全，避免冲突）。
// audit 包本身不依赖 hub / keystore（密钥以 fallback 注入，无反向依赖）。
//
// 外锚落「库外」而非 PG 表：backup.go 的 BackupSQL 动态遍历全部 public 表导出、
// RestoreSQL 以 TRUNCATE ... RESTART IDENTITY CASCADE 全量重放 ⇒ 库内锚表会被导出/
// 清空/伪造，外锚失去意义。故锚点追加到独立 append-only 文件（默认
// data/audit-anchor.jsonl），被审计库之外的历史行无法被整库重放同步伪造。
//
// 默认零回归：开关 YUDUAN_AUDIT_ANCHOR 默认 0/关闭，关闭时签名器返回空 sig、
// 不写锚文件，ChainReport 的四个锚点字段（omitempty）不输出，行为与旧版逐字节一致。
package hub

import (
	"log"
	"os"
	"time"

	"yuduan/internal/audit"
	"yuduan/internal/keystore"
)

const defaultAnchorFile = "data/audit-anchor.jsonl"

// anchorFilePath 惰性解析锚文件路径：YUDUAN_AUDIT_ANCHOR_FILE 覆盖，默认与
// YUDUAN_CONFIG_OVERRIDES 同目录约定（data/）。init 时不读取，规避时序问题。
func anchorFilePath() string {
	if v := os.Getenv("YUDUAN_AUDIT_ANCHOR_FILE"); v != "" {
		return v
	}
	return defaultAnchorFile
}

func init() {
	// 签名器：仅对链尾快照签名，返回 (sig, signedAt)；开关关闭 / 无密钥 → 空 sig。
	// 密钥三级优先：① YUDUAN_AUDIT_ANCHOR_KEY（独立对称密钥，推荐、可轮换）
	//              ② 回退 keystore.LoadHMACSecret()（同 secret，强度打折，见 key_source）
	//              ③ 皆空 → 空 sig（anchor_enabled=false）。
	audit.SetAnchorSigner(func(tailID int64, tailHash string) (string, int64) {
		// 默认关闭：仅显式 YUDUAN_AUDIT_ANCHOR=1 才启用外锚。
		if os.Getenv("YUDUAN_AUDIT_ANCHOR") != "1" {
			return "", 0
		}
		// 惰性读 secret：init 时不触碰环境变量/文件，每次 VerifyChain（低频）才读取。
		key, _ := audit.ResolveAnchorKey(keystore.LoadHMACSecret)
		if key == "" {
			return "", 0
		}
		return audit.AnchorSig(key, tailID, tailHash), time.Now().Unix()
	})

	// 库外锚点记录器：把签名成功的锚点追加到独立 append-only 文件。
	// 只追加、绝不改写/删除/truncate；写入失败只记日志并返回 error，由 makeAnchor
	// 据此置 Anchored=false，绝不误报链损坏、绝不阻断 Record。
	audit.SetAnchorSink(func(a audit.ChainAnchor) error {
		_, source := audit.ResolveAnchorKey(keystore.LoadHMACSecret)
		a.KeySource = source
		if err := audit.AppendAnchorFile(anchorFilePath(), a); err != nil {
			log.Printf("[hub] 审计外锚写入失败(不影响链校验): %v", err)
			return err
		}
		return nil
	})
}
