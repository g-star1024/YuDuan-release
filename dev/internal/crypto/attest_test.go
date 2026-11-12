// 副端设备证明（§9.2）黄金向量——Go / Rust 跨实现防漂移护栏。
//
// 与 Rust 副端 secure.rs::attestation_golden_vector 使用**同一组硬编码常量**
// （nonce/token/measurement/ts/seed/期望 digest/pubkey/sig），逐字对齐。
// 规范串、ts 单位（秒）、「签名消息 = 规范串的 32 字节 SHA-256 摘要」三者任一
// 在任一侧漂移，都会在本用例与 Rust 侧同名用例同时暴露，避免「两端各自全绿
// 但整网验签互锁失败」。改动须同步两侧。
package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"
	"testing"
)

const (
	attestNonce       = "000102030405060708090a0b0c0d0e0f"
	attestToken       = "dev-token-1"
	attestMeasurement = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	attestTS          = int64(1700000000)
	attestSeed        = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	attestCanonical = "yuduan-attest|000102030405060708090a0b0c0d0e0f|dev-token-1|" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|1700000000"
	attestDigest = "f94aec7edd47b1c06891895a1a39bea630b880b079aa0018e09907dc063eee7a"
	attestPubkey = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	attestSig    = "47aa279435e1ffa0a0689fc37f90c8475f862463849fdc01303ebcc82303d028027c7ab825407f7677eb348c32342037af0547c478793c1ea1adbdeced1dfb09"
)

// 规范串必须与 Rust 侧逐字节一致（含字段顺序、分隔符、ts 十进制表示）。
func TestAttestationCanonicalGolden(t *testing.T) {
	got := AttestationCanonical(attestNonce, attestToken, attestMeasurement, attestTS)
	if !hmac.Equal([]byte(got), []byte(attestCanonical)) {
		t.Fatalf("规范串与黄金向量不一致（可能已漂移）：\ngot  = %s\nwant = %s", got, attestCanonical)
	}
}

// 全链路互锁：摘要 → 公钥 → 签名 → 验签，全部用常数时间比较锁定硬编码期望值。
//
// 跨语言**真闭环**（不是两端各自自签自验）：attestPubkey / attestSig 是 Rust 副端
// `ed25519::public_key(seed)` / `ed25519::sign(seed, digest)` 产出的固定常量（由 Rust
// secure.rs::attestation_golden_vector 用同一组向量断言锁定）；本用例用 Go 侧
// VerifyAttestation **直接验这个 Rust 产出的常量签名**，再叠加篡改 measurement 为 false
// （见 TestVerifyAttestationNegative）。下方 Go 标准库 ed25519.Sign 重算仅用于佐证
// 「Go crypto/ed25519 与 Rust 手写实现同为 RFC 8032 纯 Ed25519、无 prehash/context/二次哈希」，
// 不作为验签输入。历史固定 ts=1700000000 能验过，正好证明验签不依赖当前时间。
func TestAttestationGoldenVector(t *testing.T) {
	digest := AttestationDigest(attestNonce, attestToken, attestMeasurement, attestTS)
	digestHex := hex.EncodeToString(digest)
	if !hmac.Equal([]byte(digestHex), []byte(attestDigest)) {
		t.Fatalf("摘要与黄金向量不一致：got=%s want=%s", digestHex, attestDigest)
	}

	seed, err := hex.DecodeString(attestSeed)
	if err != nil {
		t.Fatalf("黄金向量 seed 非法: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)
	if !hmac.Equal([]byte(pubHex), []byte(attestPubkey)) {
		t.Fatalf("公钥与黄金向量不一致：got=%s want=%s", pubHex, attestPubkey)
	}

	// 仅作标准兼容佐证：Go 标准库重算应等于 Rust 产出的 attestSig 常量。
	// 真正的验签输入是 attestSig 本身（下一行 VerifyAttestation 直接用它）。
	sig := ed25519.Sign(priv, digest)
	sigHex := hex.EncodeToString(sig)
	if !hmac.Equal([]byte(sigHex), []byte(attestSig)) {
		t.Fatalf("签名与黄金向量不一致（跨语言互锁失败）：\ngot  = %s\nwant = %s", sigHex, attestSig)
	}

	if !VerifyAttestation(attestPubkey, attestSig, attestNonce, attestToken, attestMeasurement, attestTS) {
		t.Fatal("黄金向量未能通过 VerifyAttestation")
	}
}

func TestVerifyAttestationNegative(t *testing.T) {
	flipSig := func(s string) string {
		b := []byte(s)
		if b[0] == 'a' {
			b[0] = 'b'
		} else {
			b[0] = 'a'
		}
		return string(b)
	}
	shortHex := attestPubkey[:len(attestPubkey)-2] // 31 字节
	shortSig := attestSig[:len(attestSig)-2]       // 63 字节

	cases := []struct {
		name                                string
		pub, sig, nonce, token, measurement string
		ts                                  int64
	}{
		{"篡改 measurement", attestPubkey, attestSig, attestNonce, attestToken, "deadbeef" + attestMeasurement[8:], attestTS},
		{"篡改 nonce", attestPubkey, attestSig, "ffffffffffffffffffffffffffffffff", attestToken, attestMeasurement, attestTS},
		{"换身份 token", attestPubkey, attestSig, attestNonce, "dev-token-2", attestMeasurement, attestTS},
		{"篡改 ts(+1)", attestPubkey, attestSig, attestNonce, attestToken, attestMeasurement, attestTS + 1},
		{"空 pubkey", "", attestSig, attestNonce, attestToken, attestMeasurement, attestTS},
		{"空 sig", attestPubkey, "", attestNonce, attestToken, attestMeasurement, attestTS},
		{"pubkey 长度不足", shortHex, attestSig, attestNonce, attestToken, attestMeasurement, attestTS},
		{"sig 长度不足", attestPubkey, shortSig, attestNonce, attestToken, attestMeasurement, attestTS},
		{"pubkey 非法 hex", "zz" + attestPubkey[2:], attestSig, attestNonce, attestToken, attestMeasurement, attestTS},
		{"sig 非法 hex", attestPubkey, "zz" + attestSig[2:], attestNonce, attestToken, attestMeasurement, attestTS},
		{"sig 单字节翻转", attestPubkey, flipSig(attestSig), attestNonce, attestToken, attestMeasurement, attestTS},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if VerifyAttestation(c.pub, c.sig, c.nonce, c.token, c.measurement, c.ts) {
				t.Fatal("应拒绝，却通过验签")
			}
		})
	}
}

// 绑定维度：同一 seed 对两个不同 measurement 必须得到不同签名（防把 A 证明挪用到 B）。
func TestAttestationSignatureBindsMeasurement(t *testing.T) {
	seed, _ := hex.DecodeString(attestSeed)
	priv := ed25519.NewKeyFromSeed(seed)
	d1 := AttestationDigest(attestNonce, attestToken, attestMeasurement, attestTS)
	d2 := AttestationDigest(attestNonce, attestToken, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", attestTS)
	if hmac.Equal(ed25519.Sign(priv, d1), ed25519.Sign(priv, d2)) {
		t.Fatal("不同 measurement 竟产生相同签名（未绑定二进制度量）")
	}
}
