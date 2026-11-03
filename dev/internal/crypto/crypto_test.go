package crypto

import (
	"strings"
	"testing"
	"time"
)

// 未来有效期统一动态生成，禁止硬编码时间戳（曾因硬编码"3 天后"导致 2026-10-24 全线过期）。
func futureUnix() int64 { return time.Now().Add(24 * time.Hour).Unix() }

func TestTokenRoundTrip(t *testing.T) {
	secret := "yuduan-dev-secret"
	tok := SignToken(secret, "admin", "admin", futureUnix(), false)
	c, err := VerifyToken(secret, tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if c.Username != "admin" || c.Role != "admin" || c.MustChange {
		t.Fatalf("bad claims: %+v", c)
	}
}

func TestTokenMustChangeFlag(t *testing.T) {
	secret := "yuduan-dev-secret"
	tok := SignToken(secret, "admin", "admin", futureUnix(), true)
	c, err := VerifyToken(secret, tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !c.MustChange {
		t.Fatalf("must_change flag lost: %+v", c)
	}
}

func TestTokenTamper(t *testing.T) {
	secret := "yuduan-dev-secret"
	exp := futureUnix()
	tok := SignToken(secret, "admin", "admin", exp, false)
	// 篡改 role 部分（保持 4 段结构）
	bad := "attacker|admin|" + itoa64(exp) + "|0." + tok[strings.Index(tok, ".")+1:]
	if _, err := VerifyToken(secret, bad); err == nil {
		t.Fatalf("tampered token should fail")
	}
}

func TestTokenExpired(t *testing.T) {
	secret := "yuduan-dev-secret"
	tok := SignToken(secret, "admin", "admin", 1, false) // 1970
	if _, err := VerifyToken(secret, tok); err == nil {
		t.Fatalf("expired token should fail")
	}
}

func TestPasswordArgon2RoundTrip(t *testing.T) {
	enc := HashPassword("Str0ng-Pass!", "pepper")
	if !strings.HasPrefix(enc, "argon2id$") {
		t.Fatalf("expected argon2id encoding, got %q", enc)
	}
	if !VerifyPassword("Str0ng-Pass!", "pepper", enc) {
		t.Fatal("correct password should verify")
	}
	if VerifyPassword("wrong-pass", "pepper", enc) {
		t.Fatal("wrong password should not verify")
	}
	if VerifyPassword("Str0ng-Pass!", "other-pepper", enc) {
		t.Fatal("wrong pepper should not verify")
	}
	if NeedsRehash(enc) {
		t.Fatal("fresh argon2id should not need rehash")
	}
	// 旧格式（无盐 HMAC）应可校验且标记需升级
	legacy := legacyHash("old-pass", "pepper")
	if !VerifyPassword("old-pass", "pepper", legacy) {
		t.Fatal("legacy password should still verify")
	}
	if !NeedsRehash(legacy) {
		t.Fatal("legacy hash should need rehash")
	}
	// 两次哈希应不同（随机盐）
	if HashPassword("same-pass", "pepper") == HashPassword("same-pass", "pepper") {
		t.Fatal("salt should be random")
	}
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
