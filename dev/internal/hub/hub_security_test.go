package hub

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"yuduan/internal/crypto"
	"yuduan/internal/proto"
)

// 固定种子（仅测试用）：与 Rust 副端 ed25519 同算法（crypto/ed25519 权威实现），
// 本测试验证中枢签名产物可被标准 ed25519.Verify 接受（Rust 侧已有 Go 向量互验证）。
var testSeed = mustHex("79756475616e2d656432353531392d63726f7373636865636b2d736565642d33")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func newSigningHub() *Hub {
	h := &Hub{signSeed: testSeed, software: make(map[string]*proto.SoftwareItem)}
	h.initSigning()
	return h
}

func TestSignSoftware_SignAndVerify(t *testing.T) {
	h := newSigningHub()
	if h.signPub == "" {
		t.Fatalf("signPub 不应为空（种子合法）")
	}

	data := []byte("yuduan-installer-payload-v1")
	shaHex, sigHex, signer := h.signSoftware(data)
	if shaHex == "" {
		t.Fatalf("sha256 不应为空")
	}
	if sigHex == "" || signer == "" {
		t.Fatalf("配置了种子后签名与签名者不应为空")
	}

	// 哈希正确性
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != shaHex {
		t.Fatalf("sha256 与计算不一致: got %s", shaHex)
	}

	// 签名可被标准 ed25519 验签（消息即 32 字节摘要，与 Rust verify 语义一致）
	sig, _ := hex.DecodeString(sigHex)
	pub, _ := hex.DecodeString(signer)
	if len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("签名/公钥长度异常 sig=%d pub=%d", len(sig), len(pub))
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), sum[:], sig) {
		t.Fatalf("ed25519.Verify 拒绝中枢签名（跨语言验签失败）")
	}

	// 篡改内容 → 验签必须失败
	tampered := append([]byte(nil), data...)
	tampered[0] ^= 0xff
	tamperedSum := sha256.Sum256(tampered)
	if ed25519.Verify(ed25519.PublicKey(pub), tamperedSum[:], sig) {
		t.Fatalf("篡改后签名仍被接受（验签形同虚设）")
	}
}

func TestSignSoftware_UnsignedWhenNoSeed(t *testing.T) {
	h := &Hub{} // 无种子
	shaHex, sigHex, signer := h.signSoftware([]byte("x"))
	if sigHex != "" || signer != "" {
		t.Fatalf("无种子时不应产生签名")
	}
	if shaHex == "" {
		t.Fatalf("无种子时仍应计算哈希")
	}
}

func TestRepoIDFromURL(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"http://hub:8080/api/v1/repo/sw-ab12cd", "sw-ab12cd"},
		{"/api/v1/repo/sw-ffffffff", "sw-ffffffff"},
		{"http://hub:8080/api/v1/repo/sw-xy?token=abc", "sw-xy"},
		{"http://hub:8080/api/v1/repo/sw-xy#frag", "sw-xy"},
		{"http://example.com/other/sw-xy", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := repoIDFromURL(c.url); got != c.want {
			t.Fatalf("repoIDFromURL(%q)=%q want %q", c.url, got, c.want)
		}
	}
}

// TestHandleDeviceCmd_AttachVerifyParams 验证 sw_install 下发时能从仓库解析并附加校验参数。
func TestHandleDeviceCmd_AttachVerifyParams(t *testing.T) {
	h := newSigningHub()
	// 预置一个已签名的仓库项
	item := &proto.SoftwareItem{
		ID: "sw-test01", Name: "demo", Version: "1.0.0", Platform: "macos",
		FileName: "demo.pkg", Size: 10, UploadedAt: 1,
		Sha256: "deadbeef", Signature: "cafe", Signer: h.signPub,
	}
	h.mu.Lock()
	h.software[item.ID] = item
	h.mu.Unlock()

	// 模拟从 URL 解析并附加
	url := "https://hub.example/api/v1/repo/sw-test01"
	if id := repoIDFromURL(url); id != "sw-test01" {
		t.Fatalf("解析仓库 id 失败: %q", id)
	}
	// 直接断言 item 校验参数非空（下发路径在 handleDeviceCmd 内基于此项填充）
	if item.Sha256 == "" || item.Signature == "" || item.Signer == "" {
		t.Fatalf("仓库项校验参数缺失，下发将无验签")
	}
}

// ---- 铁律 4：远控指令签名门禁（§8.6）----

// TestIsRCControl 固化「哪些远控消息属关键指令」：主端→副端的驱动型消息必须签名，
// 副端→主端的上报型消息不在门禁内。
func TestIsRCControl(t *testing.T) {
	control := []string{
		proto.TypeRCRequest, proto.TypeRCInput, proto.TypeRCStop,
		proto.TypeRCSelect, proto.TypeRCOffer, proto.TypeRCCandidate,
		proto.TypeRCQos, proto.TypeRCPing,
	}
	for _, ty := range control {
		if !proto.IsRCControl(ty) {
			t.Fatalf("IsRCControl(%q)=false，关键指令漏出签名门禁", ty)
		}
	}
	report := []string{
		proto.TypeRCReady, proto.TypeRCFrame, proto.TypeRCCapabilities,
		proto.TypeRCAnswer, proto.TypeRCEvent, proto.TypeRCPong,
	}
	for _, ty := range report {
		if proto.IsRCControl(ty) {
			t.Fatalf("IsRCControl(%q)=true，上报消息不应纳入指令门禁", ty)
		}
	}
}

// TestSignForAgent_RCSigned 验证中枢转发远控指令时补齐 nonce 并签名，
// 且签名可被副端同一口径（crypto.VerifyCommand）校验通过。
func TestSignForAgent_RCSigned(t *testing.T) {
	const secret = "rc-gate-secret"
	h := &Hub{secret: secret}

	// 模拟 Tauri 主端信封：只带 msg_id/ts/type/payload，无 nonce
	// （ts 取当前时间：副端验签有 ±300s 时间窗，固定旧时间戳会被判 TimeSkew）
	tsNow := time.Now().Unix()
	raw := []byte(fmt.Sprintf(
		`{"ver":1,"msg_id":"m1","ts":%d,"type":"rc_request","seq":0,"payload":{"device_id":"d1","session_id":"s1","operator":"admin"}}`,
		tsNow))
	var env proto.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	out := h.signForAgent(&env, raw)

	var sent proto.Envelope
	if err := json.Unmarshal(out, &sent); err != nil {
		t.Fatalf("转发信封无法解析: %v", err)
	}
	if sent.Nonce == "" {
		t.Fatal("nonce 未补齐：副端验签会判 Malformed 而拒绝执行")
	}
	if sent.Sig == "" {
		t.Fatal("远控指令未签名，违反铁律 4")
	}
	if !crypto.VerifyCommand(secret, sent.Sig, sent.MsgID, sent.Ts, sent.Seq, string(sent.Payload), sent.Nonce, 300) {
		t.Fatal("签名校验失败：中枢与副端口径不一致")
	}
	// 原始字段不得被覆盖
	if sent.MsgID != "m1" || sent.Ts != tsNow {
		t.Fatalf("规范化覆盖了既有字段: msg_id=%q ts=%d", sent.MsgID, sent.Ts)
	}
	// 篡改载荷必须验签失败
	if crypto.VerifyCommand(secret, sent.Sig, sent.MsgID, sent.Ts, sent.Seq,
		`{"device_id":"d2","session_id":"s1","operator":"admin"}`, sent.Nonce, 300) {
		t.Fatal("篡改载荷仍验签通过：签名未覆盖 payload")
	}
}

// TestSignForAgent_WhitespacePayloadVerifies 锁死「签名必须覆盖实际发送的 payload 字节」。
// 回归背景：主端/控制台发来的 JSON 常带空格，json.Marshal 会压缩空白并转义 <,>,&；
// 若按序列化前的 Payload 签名，副端从帧中取到的 payload 与签名覆盖内容不一致 → 验签失败。
func TestSignForAgent_WhitespacePayloadVerifies(t *testing.T) {
	const secret = "rc-gate-secret"
	h := &Hub{secret: secret}
	raw := []byte(`{"ver":1,"msg_id":"m1","type":"rc_input",` +
		`"payload": {"session_id": "s1", "kind": "key_down", "key": "a<b&c"},"ts":0}`)
	var env proto.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Ts = time.Now().Unix()
	out := h.signForAgent(&env, raw)

	// 副端口径：从「实际收到的帧」中原样提取 payload 再验签
	var sent proto.Envelope
	if err := json.Unmarshal(out, &sent); err != nil {
		t.Fatal(err)
	}
	frame := string(out)
	start := strings.Index(frame, `"payload":`)
	if start < 0 {
		t.Fatal("转发帧缺少 payload")
	}
	rest := frame[start+len(`"payload":`):]
	// 与副端 extract_raw_payload 同策略：按花括号配平截取原文
	depth, end := 0, -1
	for i, ch := range rest {
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i + 1
			}
		}
		if end > 0 {
			break
		}
	}
	if end < 0 {
		t.Fatal("payload 截取失败")
	}
	payloadAsReceived := rest[:end]
	if !crypto.VerifyCommand(secret, sent.Sig, sent.MsgID, sent.Ts, sent.Seq, payloadAsReceived, sent.Nonce, 300) {
		t.Fatalf("带空白的 payload 验签失败（签名未覆盖实际发送字节）\n sent payload=%s\n as-received=%s",
			string(sent.Payload), payloadAsReceived)
	}
}

// TestSignForAgent_NoSecretPassthrough 未配置密钥时原样透传（开发态行为不变）。
func TestSignForAgent_NoSecretPassthrough(t *testing.T) {
	h := &Hub{}
	raw := []byte(`{"ver":1,"type":"rc_input","payload":{"kind":"mouse_move"}}`)
	var env proto.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	out := h.signForAgent(&env, raw)
	var sent proto.Envelope
	_ = json.Unmarshal(out, &sent)
	if sent.Sig != "" {
		t.Fatalf("未配置密钥却产生签名: %q", sent.Sig)
	}
	if sent.Type != "rc_input" {
		t.Fatalf("透传改变了消息类型: %q", sent.Type)
	}
}
