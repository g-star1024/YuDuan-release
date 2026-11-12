// audit_anchor.go —— v0.4.31-D 审计链尾「库外外锚」的落盘与离线核验。
//
// 威胁模型：dev/internal/store/backup.go 的 BackupSQL 动态 listTables 遍历全部 public 表
// 导出，RestoreSQL 用 TRUNCATE ... RESTART IDENTITY CASCADE 全量重放。任何落在 PG 库内的
// 锚表都会被导出、清空、重放伪造 → 外锚失去唯一意义。故链尾锚点必须落在库外的独立
// append-only 文件（默认 data/audit-anchor.jsonl，YUDUAN_AUDIT_ANCHOR_FILE 可覆盖）。
//
// 本文件仅依赖标准库：密钥来源由接线层（hub/audit_anchor_wire.go）以 fallback 注入，
// audit 包不依赖 hub / keystore，保持可离线单测。
package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AnchorSig 用 key 对链尾快照 (tailID, tailHash) 做 HMAC-SHA256 → hex。
// 签名器（接线层）与离线核验（VerifyAnchorFile）共用此规范串，保证签名/验签闭环一致。
func AnchorSig(key string, tailID int64, tailHash string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(fmt.Sprintf("%d|%s", tailID, tailHash)))
	return hex.EncodeToString(mac.Sum(nil))
}

// ResolveAnchorKey 三级优先解析外锚签名密钥，返回 (密钥, 来源标识 key_source)。
//
//	① YUDUAN_AUDIT_ANCHOR_KEY：独立对称密钥（推荐、可轮换），source="YUDUAN_AUDIT_ANCHOR_KEY"；
//	② fallback()：回退密钥（接线层传 keystore.LoadHMACSecret）——与令牌签名同 secret，
//	   对称 ⇒ 能读 secret 者可自伪造，强度打折，source="hmac-secret-fallback"；
//	③ 皆空 → ("","")，调用方据此置 anchor_enabled=false、返回空 sig、不写锚文件，
//	   绝不把链判为损坏。
//
// 惰性：调用时才读环境变量/回退文件，init 不读，规避密钥文件注入时序问题。
func ResolveAnchorKey(fallback func() string) (key, source string) {
	if v := os.Getenv("YUDUAN_AUDIT_ANCHOR_KEY"); v != "" {
		return v, "YUDUAN_AUDIT_ANCHOR_KEY"
	}
	if fallback != nil {
		if v := fallback(); v != "" {
			return v, "hmac-secret-fallback"
		}
	}
	return "", ""
}

// AppendAnchorFile 以 append-only 方式把一条锚点追加到库外文件：
//   - O_APPEND|O_CREATE|O_WRONLY、0600，绝不 O_TRUNC / 改写 / 删除；
//   - 一行 = 一条 ChainAnchor 的 JSON + '\n'。
//
// 写入失败返回 error，由调用方只记日志并放弃锚定（Anchored=false），
// 绝不把链判为损坏、绝不阻断 Record。
func AppendAnchorFile(path string, a ChainAnchor) error {
	if path == "" {
		return fmt.Errorf("audit anchor: empty file path")
	}
	b, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("audit anchor: marshal: %w", err)
	}
	b = append(b, '\n')
	// 父目录不存在时创建（目录创建不属于对锚文件的改写/truncate）。
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("audit anchor: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit anchor: open: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("audit anchor: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("audit anchor: sync: %w", err)
	}
	return f.Close()
}

// AnchorFileReport 库外锚文件的离线核验结果。
type AnchorFileReport struct {
	Lines        int    `json:"lines"`
	Valid        bool   `json:"valid"`
	Reason       string `json:"reason,omitempty"`
	FirstBadLine int    `json:"first_bad_line,omitempty"`
	LastTailID   int64  `json:"last_tail_id,omitempty"`
	LastTailHash string `json:"last_tail_hash,omitempty"`
}

// VerifyAnchorFile 离线核验库外锚文件：
//   - 逐行 JSON 解析；tail_id 单调不减（TRUNCATE 恢复导致回退会被检出）；
//   - key 非空时，每行 sig 用当前 secret 对 (tail_id|tail_hash) 复算并恒定时间比对。
//
// key 为空时只做结构/单调性检查（不给签名结论）——用于「无密钥也别误报」的场景。
//
// 离线核验用法（运维/CLI）：用 writeAuditJSON（审计导出 JSON）取最后一条事件的
// (id, hash) 作为库内链尾，再调用 VerifyAnchorTail(path, key, tailID, tailHash)
// 比对库外锚尾与库内链尾是否一致。
func VerifyAnchorFile(path, key string) AnchorFileReport {
	data, err := os.ReadFile(path)
	if err != nil {
		return AnchorFileReport{Valid: false, Reason: "read failed: " + err.Error()}
	}
	rep := AnchorFileReport{Valid: true}
	raw := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	lineNo := 0
	var prevTailID int64
	for _, ln := range raw {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		lineNo++
		var a ChainAnchor
		if err := json.Unmarshal(ln, &a); err != nil {
			rep.Valid = false
			rep.FirstBadLine = lineNo
			rep.Reason = fmt.Sprintf("第 %d 行 JSON 解析失败: %v", lineNo, err)
			return rep
		}
		if lineNo > 1 && a.TailID < prevTailID {
			rep.Valid = false
			rep.FirstBadLine = lineNo
			rep.Reason = fmt.Sprintf("tail_id 非单调 at line %d", lineNo)
			return rep
		}
		if key != "" {
			want := AnchorSig(key, a.TailID, a.TailHash)
			if !hmac.Equal([]byte(want), []byte(a.Sig)) {
				rep.Valid = false
				rep.FirstBadLine = lineNo
				rep.Reason = fmt.Sprintf("sig 不匹配 at line %d", lineNo)
				return rep
			}
		}
		prevTailID = a.TailID
		rep.Lines++
		rep.LastTailID, rep.LastTailHash = a.TailID, a.TailHash
	}
	if rep.Lines == 0 {
		rep.Reason = "锚文件为空或无有效行"
	}
	return rep
}

// VerifyAnchorTail 人工比对入口：先核验锚文件自身，再比对锚尾 (tail_id, tail_hash)
// 与「导出 JSON 的库内链尾」是否一致。
//
// 诚实边界：服务端级整库替换（伪造整条链）只能靠人工比对库外锚文件发现，
// 不能自动告警——锚文件在被审计库之外，服务端无法感知库内已被替换。
func VerifyAnchorTail(path, key string, tailID int64, tailHash string) (bool, string) {
	rep := VerifyAnchorFile(path, key)
	if !rep.Valid {
		return false, "锚文件自身核验失败: " + rep.Reason
	}
	if rep.Lines == 0 {
		return false, "锚文件为空，无法比对"
	}
	if rep.LastTailID != tailID || rep.LastTailHash != tailHash {
		return false, fmt.Sprintf("库外锚尾 (%d,%s) 与库内链尾 (%d,%s) 不一致",
			rep.LastTailID, rep.LastTailHash, tailID, tailHash)
	}
	return true, "一致"
}
