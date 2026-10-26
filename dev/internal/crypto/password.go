package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"yuduan/internal/argon2"
)

// 口令编码格式（argon2id，RFC 9106）：
//
//	argon2id$v=19$m=65536,t=3,p=4$<base64(salt)>$<base64(tag)>
//
// pepper 为服务端密钥（YUDUAN_PW_PEPPER），与口令拼接后作为 argon2 输入，
// 即使库泄露也无法直接离线爆破。旧格式（无盐 HMAC-SHA256 十六进制）仅保留校验
// 与登录时透明升级能力，新口令一律按 argon2id 落库。

const (
	pwArgon2Time   = 3         // 迭代次数
	pwArgon2MemKiB = 64 * 1024 // 64 MiB 内存（OWASP 推荐量级）
	pwArgon2Par    = 4         // 并行度
	pwSaltLen      = 16
	pwTagLen       = 32
	pwArgon2Ver    = 19
)

// HashPassword 生成 argon2id 口令编码串（含随机盐）。
func HashPassword(password, pepper string) string {
	salt := make([]byte, pwSaltLen)
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand 失败时不降级：返回空串由调用方判错，避免弱口令落库。
		return ""
	}
	tag := argon2.IDKey([]byte(pepper+password), salt, pwArgon2Time, pwArgon2MemKiB, pwArgon2Par, pwTagLen)
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		pwArgon2Ver, pwArgon2MemKiB, pwArgon2Time, pwArgon2Par,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(tag))
}

// VerifyPassword 校验口令；支持 argon2id 与旧版无盐 HMAC 格式，恒定时间比较。
func VerifyPassword(password, pepper, encoded string) bool {
	if encoded == "" {
		return false
	}
	if strings.HasPrefix(encoded, "argon2id$") {
		return verifyArgon2id(password, pepper, encoded)
	}
	// 旧格式：hmac_sha256(pepper, password) 十六进制
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(legacyHash(password, pepper))) == 1
}

// NeedsRehash 判断已存编码是否低于当前策略（旧格式或参数弱于当前），
// 供登录成功后透明升级。
func NeedsRehash(encoded string) bool {
	if !strings.HasPrefix(encoded, "argon2id$") {
		return true
	}
	fields := strings.Split(encoded, "$")
	if len(fields) != 5 {
		return true
	}
	// 版本段 v=19
	if v := strings.TrimPrefix(fields[1], "v="); v == fields[1] {
		return true
	} else if n, err := strconv.Atoi(v); err != nil || n != pwArgon2Ver {
		return true
	}
	for _, kv := range strings.Split(fields[2], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil {
			return true
		}
		switch parts[0] {
		case "v":
			if n != pwArgon2Ver {
				return true
			}
		case "m":
			if n < pwArgon2MemKiB {
				return true
			}
		case "t":
			if n < pwArgon2Time {
				return true
			}
		case "p":
			if n < pwArgon2Par {
				return true
			}
		}
	}
	return false
}

// legacyHash 旧版无盐摘要（仅用于兼容历史库，恒定时间比较见 VerifyPassword）。
func legacyHash(password, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(password))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyArgon2id(password, pepper, encoded string) bool {
	fields := strings.Split(encoded, "$")
	if len(fields) != 5 || fields[0] != "argon2id" {
		return false
	}
	// 段布局：argon2id | v=19 | m=..,t=..,p=.. | salt | tag
	var mem, tm, par, ver int
	if v := strings.TrimPrefix(fields[1], "v="); v != fields[1] {
		ver, _ = strconv.Atoi(v)
	}
	for _, kv := range strings.Split(fields[2], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return false
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil {
			return false
		}
		switch parts[0] {
		case "v":
			ver = n
		case "m":
			mem = n
		case "t":
			tm = n
		case "p":
			par = n
		}
	}
	if ver != pwArgon2Ver || mem <= 0 || tm <= 0 || par <= 0 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(fields[3])
	if err != nil || len(salt) < 8 {
		return false
	}
	tag, err := base64.StdEncoding.DecodeString(fields[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pepper+password), salt, uint32(tm), uint32(mem), uint8(par), uint32(len(tag)))
	return subtle.ConstantTimeCompare(got, tag) == 1
}
