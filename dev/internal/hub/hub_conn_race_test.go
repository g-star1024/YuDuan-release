package hub

// 回归测试：同设备重复注册/旧连接断开不得误杀新连接的在线状态。
// 现场实锤（2026-10-27）：Windows 副端双实例/快速重连场景下，旧连接的读循环
// 退出时无条件 MarkOffline + delete(conns)，把仍存活的新连接标成离线，
// 主端台账显示「设备不在线」而副端自认已注册。同 StrictMode 双挂载竞态一族。

import (
	"encoding/json"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"yuduan/internal/proto"
	"yuduan/internal/store"
	"yuduan/internal/ws"
)

// TestStaleConnCloseDoesNotMarkNewConnOffline：
// 连接 A 以 token T 注册 → 连接 B 以同一 token T 注册（同设备身份，hub 挤掉 A）
// → 关闭 A → 设备必须仍在线，且 conns 里保留的是 B。
func TestStaleConnCloseDoesNotMarkNewConnOffline(t *testing.T) {
	st := store.NewMemStore()
	h := NewHub(HubConfig{Store: st})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	const token = "regression-token-fixed"
	dial := func(name string) (*ws.Conn, string) {
		c, err := ws.Dial(wsURL(srv, "/ws/agent"))
		if err != nil {
			t.Fatalf("dial 失败: %v", err)
		}
		if err := agentHandshake(c, "", token); err != nil {
			t.Fatalf("凭据握手失败: %v", err)
		}
		reg, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{
			Hostname: name, OS: "test", Arch: runtime.GOARCH, AgentVersion: "t", Token: token,
		})
		regB, _ := json.Marshal(reg)
		if err := c.WriteMessage(regB); err != nil {
			t.Fatalf("写 register 失败: %v", err)
		}
		raw, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("读 ack 失败: %v", err)
		}
		var env proto.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("解析 ack 失败: %v", err)
		}
		var ack proto.RegisterAckPayload
		if err := env.DecodePayload(&ack); err != nil || ack.DeviceID == "" {
			t.Fatalf("ack 异常: err=%v id=%q", err, ack.DeviceID)
		}
		return c, ack.DeviceID
	}

	connA, id := dial("conn-A")
	defer connA.Close()
	// hub 侧保存的连接指针（与客户端侧 ws.Conn 是不同对象，只能用 hub 侧值断言）
	h.mu.Lock()
	serverConnA := h.conns[id]
	h.mu.Unlock()
	if serverConnA == nil {
		t.Fatalf("A 注册后 conns 未登记")
	}

	connB, id2 := dial("conn-B")
	defer connB.Close()
	if id != id2 {
		t.Fatalf("同 token 应复用设备身份: %s != %s", id, id2)
	}
	h.mu.Lock()
	serverConnB := h.conns[id]
	h.mu.Unlock()
	if serverConnB != serverConnA {
		// 正确语义：B 注册后 conns 指向 B 的服务端连接（与 A 的不同）
		h.mu.Lock()
		ok := h.conns[id] != nil && h.conns[id] != serverConnA
		h.mu.Unlock()
		if !ok {
			t.Fatalf("重复注册后 conns 应指向新连接")
		}
	}

	// 旧连接 A 断开：不得把设备标离线，也不得清掉 B 的 conns 条目。
	connA.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		still := h.conns[id] == serverConnB
		h.mu.Unlock()
		got, _ := st.Get(id)
		if !got.Online {
			t.Fatalf("旧连接 A 断开后设备被误标离线（B 仍在线）")
		}
		if !still {
			t.Fatalf("旧连接 A 断开后 B 的 conns 条目被误删")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// B 心跳仍能维持在线（Touch 自愈路径）。
	hb, _ := proto.NewEnvelope(proto.TypeHeartbeat, 0, proto.HeartbeatPayload{})
	hbB, _ := json.Marshal(hb)
	if err := connB.WriteMessage(hbB); err != nil {
		t.Fatalf("B 心跳发送失败: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	got, _ := st.Get(id)
	if !got.Online {
		t.Fatalf("B 心跳后设备仍离线")
	}
}
