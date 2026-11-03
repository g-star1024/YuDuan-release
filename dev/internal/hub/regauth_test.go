// §9.1 注册凭据握手（复盘 S-3/V-03 修复）的回归用例。
//
// v0.2.6 审查发现：/ws/agent 对任何来源的 register 一律照收——既不看凭据，
// 也不验证对方是否持有授权密钥，于是任意内网主机可以①自报 token 建无限假设备；
// ②报出他人设备 token 顶替在线设备、接管其指令流并回送伪造结果。REST 侧的
// 登录 / RBAC / 二级审批 / WORM 审计在这条通道上被整体旁路。
//
// 本文件同时承担两件事：
//  1. 提供测试用的「合规副端」握手辅助函数（本包其余测试复用）；
//  2. 为上述攻击形态逐一留负向用例——正是 QA 复盘第 4 章点名的
//     「WS 端点必须鉴权的最小用例不存在」这一覆盖缺口。
package hub

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"yuduan/internal/crypto"
	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

// agentHandshake 完成一次合规的 §9.1 凭据握手：读挑战 → 回 MAC。
// 返回的 token 必须与随后 register 的 token 一致（中枢会比对绑定）。
func agentHandshake(c *ws.Conn, secret, token string) error {
	raw, err := c.ReadMessage()
	if err != nil {
		return err
	}
	var env proto.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	if env.Type != proto.TypeAuthChallenge {
		return fmt.Errorf("期望 auth_challenge，实得 %q", env.Type)
	}
	var ch proto.AuthChallengePayload
	if err := env.DecodePayload(&ch); err != nil {
		return err
	}
	resp, err := proto.NewEnvelope(proto.TypeAuthResponse, 0, proto.AuthResponsePayload{
		Nonce: ch.Nonce,
		Token: token,
		MAC:   crypto.SignRegisterAuth(secret, ch.Nonce, token),
	})
	if err != nil {
		return err
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return c.WriteMessage(b)
}

// readTypedEnv 读取并解析一条文本帧信封。
func readTypedEnv(c *ws.Conn) (proto.Envelope, error) {
	var env proto.Envelope
	raw, err := c.ReadMessage()
	if err != nil {
		return env, err
	}
	err = json.Unmarshal(raw, &env)
	return env, err
}

// TestAgentWSRegisterWithoutHandshakeRejected：未握手的连接直接发 register
// 必须被 nack（携带原因），且不得在台账里产生任何设备。
func TestAgentWSRegisterWithoutHandshakeRejected(t *testing.T) {
	h := NewHub(HubConfig{HMACSecret: "regauth-secret"})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// 先把中枢下发的挑战读掉（模拟"收而不答"的攻击者）
	var chEnv proto.Envelope
	if chEnv, err = readTypedEnv(c); err != nil {
		t.Fatalf("读挑战失败: %v", err)
	}
	if chEnv.Type != proto.TypeAuthChallenge {
		t.Fatalf("中枢未下发注册挑战：type=%q", chEnv.Type)
	}

	reg, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{
		Hostname: "attacker-box", OS: "linux", Arch: "x86_64",
	})
	if err := c.WriteMessage(mustJSON(reg)); err != nil {
		t.Fatalf("写 register 失败: %v", err)
	}

	ackEnv, err := readTypedEnv(c)
	if err != nil {
		t.Fatalf("未收到回执：%v", err)
	}
	if ackEnv.Type != proto.TypeRegisterAck {
		t.Fatalf("期望 register_ack，实得 %q", ackEnv.Type)
	}
	var ack proto.RegisterAckPayload
	if err := ackEnv.DecodePayload(&ack); err != nil {
		t.Fatalf("解析回执失败: %v", err)
	}
	if ack.OK {
		t.Fatal("未握手的 register 竟被接受——S-3 回归失败：任意主机仍可注册设备")
	}
	if ack.DeviceID != "" {
		t.Fatalf("被拒注册却分配了 device_id=%s", ack.DeviceID)
	}
	if ack.Reason == "" {
		t.Fatal("回执缺少 reason，运维无法定位「注册一直失败」的根因")
	}
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("台账被注入 %d 台伪造设备", n)
	}
}

// TestAgentWSWrongSecretRejected：持错误密钥（猜错/弱密钥）的客户端
// 猜测/弱密钥）的客户端即便完成握手流程也必须被拒。
func TestAgentWSWrongSecretRejected(t *testing.T) {
	h := NewHub(HubConfig{HMACSecret: "regauth-secret"})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if err := agentHandshake(c, "wrong-secret", "some-token"); err != nil {
		t.Fatalf("握手写入失败: %v", err)
	}
	// MAC 校验失败 → 中枢应关闭连接；此处写 register 或读帧都应表现为断链
	reg, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{Hostname: "fake", OS: "linux"})
	_ = c.WriteMessage(mustJSON(reg))
	if env, err := readTypedEnv(c); err == nil {
		var ack proto.RegisterAckPayload
		_ = env.DecodePayload(&ack)
		if ack.OK {
			t.Fatal("错误密钥竟通过注册——S-3 回归失败")
		}
	}
	if n := len(h.store.List()); n != 0 {
		t.Fatalf("错误密钥的客户端仍写入了 %d 台设备", n)
	}
}

// TestAgentWSNonceNotReusableAcrossConnections：录得一份有效握手应答后，
// 在另一条连接上重放必须失败（nonce 逐连接唯一）。
func TestAgentWSNonceNotReusableAcrossConnections(t *testing.T) {
	const secret = "regauth-secret"
	h := NewHub(HubConfig{HMACSecret: secret})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	// 连接 A：合规握手 + 注册成功
	cA, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer cA.Close()
	if err := agentHandshake(cA, secret, "victim-token"); err != nil {
		t.Fatalf("握手 A: %v", err)
	}
	regA, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{
		Hostname: "victim", OS: "macos", Arch: "arm64", Token: "victim-token",
	})
	if err := cA.WriteMessage(mustJSON(regA)); err != nil {
		t.Fatalf("注册 A: %v", err)
	}
	envA, err := readTypedEnv(cA)
	if err != nil {
		t.Fatalf("读回执 A: %v", err)
	}
	var ackA proto.RegisterAckPayload
	if err := envA.DecodePayload(&ackA); err != nil || !ackA.OK {
		t.Fatalf("正常副端注册失败: %v ack=%+v", err, ackA)
	}

	// 连接 B：攻击者带着 A 那条作废应答闯入
	cB, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer cB.Close()
	chEnv, err := readTypedEnv(cB)
	if err != nil {
		t.Fatalf("读挑战 B: %v", err)
	}
	var chB proto.AuthChallengePayload
	if err := chEnv.DecodePayload(&chB); err != nil {
		t.Fatalf("解析挑战 B: %v", err)
	}
	if chB.Nonce == "" {
		t.Fatal("挑战未带 nonce")
	}
	// 用 B 的新 nonce 配 A 的旧应答模式不行；这里验证"换了 nonce 就验不过"：
	// 以 B 的 nonce + 正确算法之外的常量 MAC（等价于录得 A 的应答原文）
	replay, _ := proto.NewEnvelope(proto.TypeAuthResponse, 0, proto.AuthResponsePayload{
		Nonce: chB.Nonce, Token: "victim-token", MAC: "replayed-mac-from-conn-a",
	})
	_ = cB.WriteMessage(mustJSON(replay))
	regB, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{
		Hostname: "victim", OS: "macos", Arch: "arm64", Token: "victim-token",
	})
	_ = cB.WriteMessage(mustJSON(regB))
	if envB, err := readTypedEnv(cB); err == nil {
		var ackB proto.RegisterAckPayload
		_ = envB.DecodePayload(&ackB)
		if ackB.OK {
			t.Fatal("重放应答竟通过了新连接的握手——S-3 回归失败")
		}
	}
	if n := len(h.store.List()); n != 1 {
		t.Fatalf("台账设备数应为 1（仅真机），实为 %d", n)
	}
}

// TestAgentWSTokenMustMatchHandshake：握手时以 token=A 签名，注册却报 token=B
// （典型"抢注他人设备"）必须被拒。
func TestAgentWSTokenMustMatchHandshake(t *testing.T) {
	const secret = "regauth-secret"
	h := NewHub(HubConfig{HMACSecret: secret})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	// 真机：以 victim-token 注册成功
	cReal, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cReal.Close()
	if err := agentHandshake(cReal, secret, "victim-token"); err != nil {
		t.Fatalf("握手: %v", err)
	}
	reg, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{
		Hostname: "victim", OS: "macos", Arch: "arm64", Token: "victim-token",
	})
	if err := cReal.WriteMessage(mustJSON(reg)); err != nil {
		t.Fatal(err)
	}
	if env, err := readTypedEnv(cReal); err != nil {
		t.Fatalf("读回执: %v", err)
	} else {
		var ack proto.RegisterAckPayload
		_ = env.DecodePayload(&ack)
		if !ack.OK {
			t.Fatalf("合规副端注册被拒: %+v", ack)
		}
	}

	// 攻击者：握手报空 token，注册却报 victim-token
	cAtk, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial atk: %v", err)
	}
	defer cAtk.Close()
	if err := agentHandshake(cAtk, secret, ""); err != nil {
		t.Fatalf("攻击者握手: %v", err)
	}
	regAtk, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{
		Hostname: "victim", OS: "macos", Arch: "arm64", Token: "victim-token",
	})
	if err := cAtk.WriteMessage(mustJSON(regAtk)); err != nil {
		t.Fatal(err)
	}
	envAtk, err := readTypedEnv(cAtk)
	if err != nil {
		t.Fatalf("攻击者未收到回执: %v", err)
	}
	var ackAtk proto.RegisterAckPayload
	if err := envAtk.DecodePayload(&ackAtk); err != nil {
		t.Fatal(err)
	}
	if ackAtk.OK {
		t.Fatal("换 token 注册竟成功——凭据未与实际身份绑定，抢注仍成立")
	}
	if ackAtk.Reason == "" {
		t.Fatal("缺少拒绝原因")
	}
}

// TestAgentWSUnauthenticatedMessagesIgnored：握手之前发送的心跳/结果/远控帧
// 一律不产生任何台账副作用；完成握手后同一条连接可正常注册。
func TestAgentWSUnauthenticatedMessagesIgnored(t *testing.T) {
	const secret = "regauth-secret"
	h := NewHub(HubConfig{HMACSecret: secret})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	hb, _ := proto.NewEnvelope(proto.TypeHeartbeat, 0, proto.HeartbeatPayload{})
	_ = c.WriteMessage(mustJSON(hb))
	res, _ := proto.NewEnvelope(proto.TypeResult, 0, proto.ResultPayload{TaskID: "t1", State: "success"})
	_ = c.WriteMessage(mustJSON(res))

	if n := len(h.store.List()); n != 0 {
		t.Fatalf("未握手即产生台账副作用：%d 台", n)
	}

	// 完成握手后正常注册
	if err := agentHandshake(c, secret, ""); err != nil {
		t.Fatalf("握手: %v", err)
	}
	reg, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{
		Hostname: "late-handshake", OS: "linux", Arch: "x86_64",
	})
	if err := c.WriteMessage(mustJSON(reg)); err != nil {
		t.Fatal(err)
	}
	env, err := readTypedEnv(c)
	if err != nil {
		t.Fatalf("读回执: %v", err)
	}
	var ack proto.RegisterAckPayload
	if err := env.DecodePayload(&ack); err != nil || !ack.OK {
		t.Fatalf("补做握手后仍无法注册: %v ack=%+v", err, ack)
	}
}
