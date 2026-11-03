// Package keystore 统一收口密钥/凭据的获取来源，为「密钥入 KMS」提供解耦点。
//
// 御端所有密钥（软件包签名种子、指令 HMAC 密钥）不应硬编码，而应由环境变量或
// 挂载文件（由 KMS / secrets-manager 注入）提供。生产环境可将本包替换为从
// 云 KMS（如 KMS/Secrets Manager）拉取并缓存的实现，调用方无需改动。
package keystore

import (
	"fmt"
	"os"
	"strings"
)

// LoadSignSeed 取得软件包签名 Ed25519 种子（32 字节 hex）。
// 优先级：YUDUAN_SIGN_SEED 环境变量 → YUDUAN_SIGN_SEED_FILE 文件内容。
// 返回 nil 表示未配置（软件包不签名，仅记哈希）。
func LoadSignSeed() []byte {
	if v := os.Getenv("YUDUAN_SIGN_SEED"); v != "" {
		return parseHexSeed(v)
	}
	if f := os.Getenv("YUDUAN_SIGN_SEED_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return parseHexSeed(strings.TrimSpace(string(b)))
		}
	}
	return nil
}

// LoadHMACSecret 取得指令 HMAC 密钥。
// 优先级：YUDUAN_HMAC_SECRET 环境变量 → YUDUAN_HMAC_SECRET_FILE 文件内容。
// 返回空串表示开发态放行（副端同样未配置时放行）。
func LoadHMACSecret() string {
	if v := os.Getenv("YUDUAN_HMAC_SECRET"); v != "" {
		return v
	}
	if f := os.Getenv("YUDUAN_HMAC_SECRET_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// LoadRecordKey 取得远控录像加密主密钥（32 字节 hex，§5 录像留存）。
// 优先级：YUDUAN_RECORD_KEY 环境变量 → YUDUAN_RECORD_KEY_FILE 文件内容。
// 返回 nil 表示未配置——调用方应从 HMAC 密钥派生开发态兜底密钥（record.DeriveMaster），
// 生产环境必须显式配置独立密钥（与信令密钥隔离，避免录像泄露波及控制面）。
func LoadRecordKey() []byte {
	if v := os.Getenv("YUDUAN_RECORD_KEY"); v != "" {
		return parseHexSeed(v)
	}
	if f := os.Getenv("YUDUAN_RECORD_KEY_FILE"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return parseHexSeed(strings.TrimSpace(string(b)))
		}
	}
	return nil
}

// parseHexSeed 将 64 字符 hex 解析为 32 字节；非法返回 nil。
func parseHexSeed(s string) []byte {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return nil
	}
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var v int
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &v); err != nil {
			return nil
		}
		b[i] = byte(v)
	}
	return b
}
