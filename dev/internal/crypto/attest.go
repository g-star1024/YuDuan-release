package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// AttestationCanonical 是副端设备证明（§9.2）的签名规范串：
//
//	"yuduan-attest|" + nonce + "|" + token + "|" + measurement + "|" + ts
//
// 与 Rust 副端 secure.rs::attestation_canonical **同名同串**：三端（Go 中枢验签 /
// Rust 生产副端签名 / 黄金向量单测）必须逐字节一致。绑定 nonce（逐连接挑战）、
// token（声明的设备身份）、measurement（自身可执行文件 SHA-256 hex）、ts（挑战
// 下发的 unix 秒），任一项被改都会使验签失败，防重放与换身份。
//
// 设计取舍（与 §9.1 RegisterAuthCanonical 的互锁模式一致）：ts 一律为 unix 秒，
// 且**唯一来源 = 中枢下发的 auth_challenge.TS**（proto/util.go nowUnix，服务端时间；
// 绝非副端 Rust main.rs now_secs 现取的本地时间）。规范串使用 **原始 ts 值**（十进制
// 整数），不做归一、不改写；±300s 时间窗判定由中枢接线时对 challenge.TS 旁路做
// （参考 secure.rs::verify_command / crypto.VerifyCommand 的既有 ts 归一逻辑），
// 不写死在本函数里——否则固定历史 ts 的黄金向量会永远验不过。绝不用毫秒。
func AttestationCanonical(nonce, token, measurement string, ts int64) string {
	return fmt.Sprintf("yuduan-attest|%s|%s|%s|%d", nonce, token, measurement, ts)
}

// AttestationDigest 返回规范串的 SHA-256 摘要（32 字节），即 Ed25519 的签名消息。
// 与两侧既有口径一致：Rust ed25519::sign(seed, digest) / Go hub.signSoftware 的
// ed25519.Sign(priv, sum[:]) 都以「32 字节摘要本身」为消息，而非规范串原文。
func AttestationDigest(nonce, token, measurement string, ts int64) []byte {
	sum := sha256.Sum256([]byte(AttestationCanonical(nonce, token, measurement, ts)))
	return sum[:]
}

// VerifyAttestation 校验一条副端设备证明。
//
//	pubkeyHex : 32 字节 Ed25519 公钥（hex 小写，64 字符）
//	sigHex    : 64 字节 Ed25519 签名（hex 小写，128 字符）
//	nonce/token/measurement/ts : 与签名时完全相同的规范串参数
//
// 解析严格：非法 hex、长度不符一律 false；验签用标准库 ed25519.Verify（常数时间）。
// 本期仅为「副端产出、中枢验签」的契约基座，中枢侧叠加到 auth_response 验收
// （含 require_attest 开关、时间窗、pubkey 台账白名单）由后续接线完成。
func VerifyAttestation(pubkeyHex, sigHex, nonce, token, measurement string, ts int64) bool {
	pk, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	digest := AttestationDigest(nonce, token, measurement, ts)
	return ed25519.Verify(ed25519.PublicKey(pk), digest, sig)
}
