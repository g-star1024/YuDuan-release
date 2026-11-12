// v0.4.32 §9.2 设备证明（中枢接线）回归用例。
//
// 覆盖：require_attest 灰度开关下——
//  1. 旧副端（无证明字段）在强制模式被拒；
//  2. 合规副端（有效证明）在强制模式被接受且台账记录 Attested=true / AgentPubkey；
//  3. 篡改签名 → 握手即拒（不建档）；
//  4. 度量白名单：未命中拒绝、命中接受；
//  5. 证明公钥与注册公钥不一致 → 拒绝建档；
//  6. 默认 LAN（require_attest=false）对旧副端逐字节兼容放行；
//  7. 默认 LAN 下副端附带证明字段亦被无害接受。
//
// 本文件复用 regauth_test.go 的 readTypedEnv / mustJSON / wsURL。
package hub

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"yuduan/internal/crypto"
	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

// attestFields 是 §9.2 设备证明三字段的本地载体。
type attestFields struct {
	Pubkey, AttestSig, Measurement string
}

// readChallenge 读取中枢连接建立后下发的 §9.1 注册挑战（含 Nonce / TS / RequireAttest）。
func readChallenge(c *ws.Conn) (proto.AuthChallengePayload, error) {
	chEnv, err := readTypedEnv(c)
	if err != nil {
		return proto.AuthChallengePayload{}, err
	}
	var ch proto.AuthChallengePayload
	if err := chEnv.DecodePayload(&ch); err != nil {
		return proto.AuthChallengePayload{}, err
	}
	if chEnv.Type != proto.TypeAuthChallenge {
		return proto.AuthChallengePayload{}, fmt.Errorf("期望 auth_challenge，实得 %q", chEnv.Type)
	}
	return ch, nil
}

// sendHandshake 发送 §9.1 握手应答，可选附带 §9.2 设备证明。
// attest 为 nil → 回旧三字段（旧副端）；非 nil → 携带 {pubkey, sig, measurement}。
// 挑战 ch 须由 readChallenge 先行取得（证明签名需用到 ch.Nonce / ch.TS）。
func sendHandshake(c *ws.Conn, secret, token string, ch proto.AuthChallengePayload, attest *attestFields) error {
	ap := proto.AuthResponsePayload{
		Nonce: ch.Nonce,
		Token: token,
		MAC:   crypto.SignRegisterAuth(secret, ch.Nonce, token),
	}
	if attest != nil {
		ap.Pubkey = attest.Pubkey
		ap.AttestSig = attest.AttestSig
		ap.Measurement = attest.Measurement
	}
	resp, err := proto.NewEnvelope(proto.TypeAuthResponse, 0, ap)
	if err != nil {
		return err
	}
	return c.WriteMessage(mustJSON(resp))
}

// makeAttest 用给定 seed 对 §9.2 规范串签名，返回 (pubkeyHex, sigHex)。
func makeAttest(seed [32]byte, nonce, token, measurement string, ts int64) (string, string) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	digest := crypto.AttestationDigest(nonce, token, measurement, ts)
	sig := ed25519.Sign(priv, digest)
	return hex.EncodeToString(pub), hex.EncodeToString(sig)
}

// registerAndAck 发送 register 并读取回执；连接已断（拒绝场景）时返回 (ack,false)。
func registerAndAck(c *ws.Conn, p proto.RegisterPayload) (proto.RegisterAckPayload, bool) {
	reg, _ := proto.NewEnvelope(proto.TypeRegister, 0, p)
	if err := c.WriteMessage(mustJSON(reg)); err != nil {
		return proto.RegisterAckPayload{}, false
	}
	env, err := readTypedEnv(c)
	if err != nil {
		return proto.RegisterAckPayload{}, false
	}
	var ack proto.RegisterAckPayload
	_ = env.DecodePayload(&ack)
	return ack, env.Type == proto.TypeRegisterAck
}

// TestAttestRequireOldAgentRejected：强制模式 + 旧副端（无证明字段）→ 拒绝、不建档。
func TestAttestRequireOldAgentRejected(t *testing.T) {
	h := NewHub(HubConfig{HMACSecret: "attest-secret"})
	h.attestRequire = true // 灰度强制证明
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	ch, err := readChallenge(c)
	if err != nil {
		t.Fatalf("读挑战失败: %v", err)
	}
	// 旧副端：握手只回三字段（attest=nil），强制模式下必被拒。
	if err := sendHandshake(c, "attest-secret", "tok-old", ch, nil); err != nil {
		t.Fatalf("握手写入失败: %v", err)
	}
	ack, _ := registerAndAck(c, proto.RegisterPayload{Hostname: "legacy", OS: "linux", Token: "tok-old"})
	if ack.OK {
		t.Fatal("强制模式下旧副端竟被接受——attestation 接线失守")
	}
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("拒绝的副端仍写入 %d 台设备", n)
	}
}

// TestAttestRequireValidProofAccepted：强制模式 + 合规证明 → 接受并记录证明态。
func TestAttestRequireValidProofAccepted(t *testing.T) {
	const (
		secret = "attest-secret"
		token  = "tok-valid"
		meas   = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	)
	h := NewHub(HubConfig{HMACSecret: secret})
	h.attestRequire = true
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	ch, err := readChallenge(c)
	if err != nil {
		t.Fatalf("读挑战失败: %v", err)
	}
	if !ch.RequireAttest {
		t.Fatal("强制模式下挑战未携带 require_attest=true")
	}
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pubHex, sigHex := makeAttest(seed, ch.Nonce, token, meas, ch.TS)
	if err := sendHandshake(c, secret, token, ch, &attestFields{pubHex, sigHex, meas}); err != nil {
		t.Fatalf("证明应答写入失败: %v", err)
	}
	ack, ok := registerAndAck(c, proto.RegisterPayload{
		Hostname: "proven", OS: "windows", Arch: "x86_64", Token: token, AgentPubkey: pubHex,
	})
	if !ok || !ack.OK {
		t.Fatalf("合规证明副端被拒: ok=%v ack=%+v", ok, ack)
	}
	devs := h.store.List()
	if len(devs) != 1 {
		t.Fatalf("台账设备数应为 1，实为 %d", len(devs))
	}
	d := devs[0]
	if !d.Attested {
		t.Fatal("设备未记录 Attested=true")
	}
	if d.AgentPubkey != pubHex {
		t.Fatalf("设备 AgentPubkey 不符：got=%q want=%q", d.AgentPubkey, pubHex)
	}
}

// TestAttestRequireTamperedSigRejected：强制模式 + 签名对不上 → 拒绝。
func TestAttestRequireTamperedSigRejected(t *testing.T) {
	const (
		secret = "attest-secret"
		token  = "tok-tamper"
		meas   = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	)
	h := NewHub(HubConfig{HMACSecret: secret})
	h.attestRequire = true
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	ch, err := readChallenge(c)
	if err != nil {
		t.Fatalf("读挑战失败: %v", err)
	}
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	// 故意用不同 measurement 签名 → 验签失败。
	pubHex, sigHex := makeAttest(seed, ch.Nonce, token, "deadbeef"+meas[8:], ch.TS)
	if err := sendHandshake(c, secret, token, ch, &attestFields{pubHex, sigHex, meas}); err != nil {
		t.Fatalf("证明应答写入失败: %v", err)
	}
	ack, _ := registerAndAck(c, proto.RegisterPayload{Hostname: "tamper", OS: "linux", Token: token, AgentPubkey: pubHex})
	if ack.OK {
		t.Fatal("篡改签名竟通过——Ed25519 验签接线失守")
	}
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("篡改签名的副端仍写入 %d 台设备", n)
	}
}

// TestAttestRequireWhitelistMissRejected / HitAccepted：度量白名单命中判定。
func TestAttestRequireWhitelistMissRejected(t *testing.T) {
	const (
		secret = "attest-secret"
		token  = "tok-wl"
		meas   = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
		good   = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	)
	h := NewHub(HubConfig{HMACSecret: secret})
	h.attestRequire = true
	h.attestTrustedMeasurements = map[string]bool{strings.ToLower(good): true}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	ch, _ := readChallenge(c)
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 2)
	}
	pubHex, sigHex := makeAttest(seed, ch.Nonce, token, meas, ch.TS)
	if err := sendHandshake(c, secret, token, ch, &attestFields{pubHex, sigHex, meas}); err != nil {
		t.Fatalf("证明应答写入失败: %v", err)
	}
	ack, _ := registerAndAck(c, proto.RegisterPayload{Hostname: "wl-miss", OS: "linux", Token: token, AgentPubkey: pubHex})
	if ack.OK {
		t.Fatal("度量未命中白名单竟被接受")
	}
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("白名单未命中副端仍写入 %d 台设备", n)
	}
}

func TestAttestRequireWhitelistHitAccepted(t *testing.T) {
	const (
		secret = "attest-secret"
		token  = "tok-wl-hit"
		meas   = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	)
	h := NewHub(HubConfig{HMACSecret: secret})
	h.attestRequire = true
	h.attestTrustedMeasurements = map[string]bool{strings.ToLower(meas): true}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	ch, _ := readChallenge(c)
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	pubHex, sigHex := makeAttest(seed, ch.Nonce, token, meas, ch.TS)
	if err := sendHandshake(c, secret, token, ch, &attestFields{pubHex, sigHex, meas}); err != nil {
		t.Fatalf("证明应答写入失败: %v", err)
	}
	ack, ok := registerAndAck(c, proto.RegisterPayload{Hostname: "wl-hit", OS: "linux", Token: token, AgentPubkey: pubHex})
	if !ok || !ack.OK {
		t.Fatalf("白名单命中却被拒: ok=%v ack=%+v", ok, ack)
	}
}

// TestAttestPubkeyMismatchRejected：握手证明公钥 ≠ 注册上报公钥 → 拒绝建档。
func TestAttestPubkeyMismatchRejected(t *testing.T) {
	const (
		secret = "attest-secret"
		token  = "tok-mismatch"
		meas   = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	)
	h := NewHub(HubConfig{HMACSecret: secret})
	h.attestRequire = true
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	ch, _ := readChallenge(c)
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 4)
	}
	pubHex, sigHex := makeAttest(seed, ch.Nonce, token, meas, ch.TS)
	// 握手用 pubHex 证明，但注册上报另一把（不同）公钥。
	var otherSeed [32]byte
	for i := range otherSeed {
		otherSeed[i] = byte(i + 40)
	}
	otherPriv := ed25519.NewKeyFromSeed(otherSeed[:])
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	otherHex := hex.EncodeToString(otherPub)
	if err := sendHandshake(c, secret, token, ch, &attestFields{pubHex, sigHex, meas}); err != nil {
		t.Fatalf("证明应答写入失败: %v", err)
	}
	ack, _ := registerAndAck(c, proto.RegisterPayload{Hostname: "mismatch", OS: "linux", Token: token, AgentPubkey: otherHex})
	if ack.OK {
		t.Fatal("证明公钥与注册公钥不一致竟被接受——换身份漏洞")
	}
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("公钥不一致副端仍写入 %d 台设备", n)
	}
}

// TestAttestDefaultLANOldAgentAccepted：默认 LAN（require_attest=false）旧副端逐字节兼容。
func TestAttestDefaultLANOldAgentAccepted(t *testing.T) {
	h := NewHub(HubConfig{HMACSecret: "attest-secret"}) // 默认 attestRequire=false
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	ch, err := readChallenge(c)
	if err != nil {
		t.Fatalf("读挑战失败: %v", err)
	}
	if err := sendHandshake(c, "attest-secret", "tok-lan", ch, nil); err != nil {
		t.Fatalf("握手写入失败: %v", err)
	}
	ack, ok := registerAndAck(c, proto.RegisterPayload{Hostname: "lan-legacy", OS: "linux", Token: "tok-lan"})
	if !ok || !ack.OK {
		t.Fatalf("默认 LAN 旧副端被拒（破坏兼容）: ok=%v ack=%+v", ok, ack)
	}
	devs := h.store.List()
	if len(devs) != 1 {
		t.Fatalf("台账设备数应为 1，实为 %d", len(devs))
	}
	if devs[0].Attested {
		t.Fatal("默认 LAN 未要求证明，设备不应被标记 Attested=true")
	}
}

// TestAttestDefaultLANWithFieldsAccepted：默认 LAN 下副端附带证明字段亦无害接受。
func TestAttestDefaultLANWithFieldsAccepted(t *testing.T) {
	const (
		secret = "attest-secret"
		token  = "tok-lan-fields"
		meas   = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	)
	h := NewHub(HubConfig{HMACSecret: secret}) // 默认 attestRequire=false
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	ch, _ := readChallenge(c)
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 5)
	}
	pubHex, sigHex := makeAttest(seed, ch.Nonce, token, meas, ch.TS)
	if err := sendHandshake(c, secret, token, ch, &attestFields{pubHex, sigHex, meas}); err != nil {
		t.Fatalf("证明应答写入失败: %v", err)
	}
	ack, ok := registerAndAck(c, proto.RegisterPayload{Hostname: "lan-fields", OS: "linux", Token: token, AgentPubkey: pubHex})
	if !ok || !ack.OK {
		t.Fatalf("默认 LAN 下带证明字段副端被拒（应无害接受）: ok=%v ack=%+v", ok, ack)
	}
}
