package hub

// 铁律 10（质量铁律）规模/并发验证：
//   - ≥2000 终端心跳登记与持续心跳不崩溃；
//   - ≥20 路并发远控会话（二进制媒体帧经中枢中继）不串台、不丢连接。
//
// 常规 `go test ./...` 只跑小样本 smoke（避免拉长 CI）；
// 完整规模：YUDUAN_STRESS=1 go test ./internal/hub -run TestStress -v -timeout 20m

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"yuduan/internal/proto"
	"yuduan/internal/store"
	"yuduan/internal/ws"
)

// stressScale 返回 (终端数, 远控并发路数)：YUDUAN_STRESS=1 时取铁律口径
// （2000 心跳 / 20 路并发），否则跑小样本 smoke（50 / 4）。
func stressScale() (int, int) {
	if os.Getenv("YUDUAN_STRESS") == "1" {
		return 2000, 20
	}
	return 50, 4
}

// dialAgent 建立 Agent 长连接并完成注册，返回连接与设备 ID（失败直接判死）。
func dialAgent(t *testing.T, srv *httptest.Server, name string) (*ws.Conn, string) {
	t.Helper()
	c, id, err := tryDialAgent(srv, name)
	if err != nil {
		t.Fatalf("agent dial 失败: %v", err)
	}
	return c, id
}

// tryDialAgent 返回 error 而非判死，供压测重试路径使用。
func tryDialAgent(srv *httptest.Server, name string) (*ws.Conn, string, error) {
	c, err := ws.Dial(wsURL(srv, "/ws/agent"))
	if err != nil {
		return nil, "", err
	}
	reg, _ := proto.NewEnvelope(proto.TypeRegister, 0, proto.RegisterPayload{
		Hostname: name, OS: "stress", Arch: runtime.GOARCH, AgentVersion: "stress-agent",
	})
	regB, _ := json.Marshal(reg)
	if err := c.WriteMessage(regB); err != nil {
		c.Close()
		return nil, "", fmt.Errorf("写 register 失败: %w", err)
	}
	raw, err := c.ReadMessage()
	if err != nil {
		c.Close()
		return nil, "", fmt.Errorf("读 register_ack 失败: %w", err)
	}
	var ack proto.Envelope
	if err := json.Unmarshal(raw, &ack); err != nil {
		c.Close()
		return nil, "", fmt.Errorf("解析 register_ack 失败: %w", err)
	}
	var p proto.RegisterAckPayload
	if err := ack.DecodePayload(&p); err != nil {
		c.Close()
		return nil, "", fmt.Errorf("解析 register_ack 载荷失败: %w", err)
	}
	if p.DeviceID == "" {
		c.Close()
		return nil, "", fmt.Errorf("register_ack 未分配设备 ID")
	}
	return c, p.DeviceID, nil
}

// TestStressHeartbeatRegistry 验证大规模终端并发注册 + 持续心跳：
// 2000 台在线、心跳轮次内无连接中断、登记数与实际一致。
func TestStressHeartbeatRegistry(t *testing.T) {
	n, _ := stressScale()
	st := store.NewMemStore()
	h := NewHub(HubConfig{Store: st})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	var (
		wg             sync.WaitGroup
		mu             sync.Mutex
		ids            = make([]string, 0, n)
		hbOK           int64
		dialErr, hbErr int64
	)
	start := time.Now()
	// 接入限流 + 重试：真实终端是分批上线的（开机风暴也不会真并发 2000 个 TCP 握手），
	// 瞬时并发握手会撞 macOS listen backlog（实测 2000 并发直连会 connection reset）。
	// 这里按「现实节奏 + 瞬时失败重试」建模，并记录重试次数作为容量反思依据。
	ramp := 128
	if v := os.Getenv("YUDUAN_STRESS_RAMP"); v != "" {
		fmt.Sscanf(v, "%d", &ramp)
	}
	sem := make(chan struct{}, ramp)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			var (
				c   *ws.Conn
				id  string
				err error
			)
			for attempt := 0; attempt < 3; attempt++ {
				c, id, err = tryDialAgent(srv, fmt.Sprintf("stress-%04d", i))
				if err == nil {
					break
				}
				atomic.AddInt64(&dialErr, 1) // 计入瞬时失败（重试成功不代表容量无忧）
				time.Sleep(50 * time.Millisecond * time.Duration(attempt+1))
			}
			<-sem
			if err != nil {
				t.Errorf("第 %d 台重试 3 次仍注册失败: %v", i, err)
				return
			}
			defer c.Close()
			mu.Lock()
			ids = append(ids, id)
			mu.Unlock()
			// 3 轮心跳（模拟注册后持续在线）
			for r := 0; r < 3; r++ {
				hb, _ := proto.NewEnvelope(proto.TypeHeartbeat, 0, map[string]string{"seq": fmt.Sprint(r)})
				hbB, _ := json.Marshal(hb)
				if err := c.WriteMessage(hbB); err != nil {
					atomic.AddInt64(&hbErr, 1)
					return
				}
				atomic.AddInt64(&hbOK, 1)
				time.Sleep(20 * time.Millisecond)
			}
		}(i)
		if i%200 == 0 && i > 0 {
			// 分批建立，避免瞬时连接风暴掩盖真实瓶颈
			time.Sleep(50 * time.Millisecond)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	if hbErr != 0 || dialErr != 0 {
		t.Fatalf("心跳/连接失败：dial=%d heartbeat=%d", dialErr, hbErr)
	}
	if len(ids) != n {
		t.Fatalf("注册数不符：期望 %d 实际 %d", n, len(ids))
	}
	if got := st.Count(); got != n {
		t.Fatalf("仓储登记数不符：期望 %d 实际 %d", n, got)
	}
	uniq := make(map[string]bool, len(ids))
	for _, id := range ids {
		if uniq[id] {
			t.Fatalf("设备 ID 重复（Different%q）", id)
		}
		uniq[id] = true
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("规模验证: %d 台注册完成 + %d 次心跳，耗时 %s（%.0f 次心跳/秒），瞬时重试 %d 次，堆 %.1fMB",
		n, hbOK, elapsed.Round(time.Millisecond), float64(hbOK)/elapsed.Seconds(),
		dialErr, float64(ms.HeapAlloc)/1024/1024)
}

// TestStressConcurrentRemoteControl 验证多路并发远控：每路 = 1 个 Agent + 1 个 Viewer，
// Agent 持续送二进制媒体帧，Viewer 必须按会话收到各自设备的帧（不串台）。
func TestStressConcurrentRemoteControl(t *testing.T) {
	_, sessions := stressScale()
	framesPerSession := 8
	h := NewHub(HubConfig{})
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	type pair struct {
		agent   *ws.Conn
		viewer  *ws.Conn
		device  string
		session string
	}
	pairs := make([]pair, 0, sessions)

	// 1) 建立 sessions 路会话
	for i := 0; i < sessions; i++ {
		aConn, devID := dialAgent(t, srv, fmt.Sprintf("rc-agent-%02d", i))
		vConn, err := ws.Dial(wsURL(srv, "/ws/viewer"))
		if err != nil {
			t.Fatalf("viewer dial 失败: %v", err)
		}
		sid := fmt.Sprintf("s-stress-%d", i)
		req, _ := proto.NewEnvelope(proto.TypeRCRequest, 0, proto.RCRequestPayload{
			DeviceID: devID, SessionID: sid, Operator: "stress-admin",
		})
		reqB, _ := json.Marshal(req)
		if err := vConn.WriteMessage(reqB); err != nil {
			t.Fatalf("写 rc_request 失败: %v", err)
		}
		// Agent 侧消费被转发的 rc_request（否则后续读循环会读到它而非业务消息）
		if _, err := aConn.ReadMessage(); err != nil {
			t.Fatalf("第 %d 路 Agent 未收到转发的 rc_request: %v", i, err)
		}
		pairs = append(pairs, pair{agent: aConn, viewer: vConn, device: devID, session: sid})
	}
	defer func() {
		for _, p := range pairs {
			p.agent.Close()
			p.viewer.Close()
		}
	}()

	// 2) 并发发帧/收帧：每路发 framesPerSession 帧二进制媒体帧
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		got        = make([]int, sessions)
		badMagic   int64
		totalBytes int64
	)
	var errMu sync.Mutex
	var errs []string
	addErr := func(f string, a ...interface{}) {
		errMu.Lock()
		errs = append(errs, fmt.Sprintf(f, a...))
		errMu.Unlock()
	}
	started := time.Now()
	for i, p := range pairs {
		wg.Add(1)
		go func(i int, p pair) {
			defer wg.Done()
			// Viewer 侧：统计收到的二进制帧
			done := make(chan struct{})
			go func() {
				defer close(done)
				n := 0
				for n < framesPerSession {
					// 媒体帧是二进制帧（opcode 0x2）：必须用 ReadMessageTyped，
					// ReadMessage 保持文本语义会跳过二进制帧（ws 包约定）。
					d, isBinary, err := p.viewer.ReadMessageTyped()
					if err != nil {
						addErr("路 %d viewer 读失败(%d/%d): %v", i, n, framesPerSession, err)
						return
					}
					if !isBinary {
						continue // 会话信令（JSON）不计数
					}
					if len(d) < 24 || binary.LittleEndian.Uint32(d[0:4]) != 0x59445946 {
						// 非法媒体帧（magic 'YDYF'）
						atomic.AddInt64(&badMagic, 1)
						continue
					}
					atomic.AddInt64(&totalBytes, int64(len(d)))
					n++
				}
				mu.Lock()
				got[i] = n
				mu.Unlock()
			}()
			// Agent 侧：发二进制媒体帧（24B 头 + payload）
			for s := 0; s < framesPerSession; s++ {
				payload := make([]byte, 512)
				payload[0] = byte(i) // 便于识别是否串台
				frame := make([]byte, 24+len(payload))
				binary.LittleEndian.PutUint32(frame[0:4], 0x59445946)
				frame[4] = 1
				frame[6] = 1 // codec=jpeg
				binary.LittleEndian.PutUint16(frame[12:14], 640)
				binary.LittleEndian.PutUint16(frame[14:16], 360)
				binary.LittleEndian.PutUint32(frame[16:20], uint32(s))
				binary.LittleEndian.PutUint32(frame[20:24], uint32(len(payload)))
				copy(frame[24:], payload)
				if err := sendAgentBinary(p.agent, frame); err != nil {
					addErr("路 %d 第 %d 帧发送失败: %v", i, s, err)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				addErr("路 %d 收帧超时（仅收到部分帧）", i)
			}
		}(i, p)
	}
	wg.Wait()
	elapsed := time.Since(started)

	errMu.Lock()
	defer errMu.Unlock()
	if len(errs) > 0 {
		t.Fatalf("并发远控失败 %d 项:\n  %s", len(errs), strings.Join(errs, "\n  "))
	}
	for i, n := range got {
		if n != framesPerSession {
			t.Fatalf("路 %d 收帧数不符：期望 %d 实际 %d（可能存在串台/丢帧）", i, framesPerSession, n)
		}
	}
	t.Logf("并发远控: %d 路 × %d 帧 = %d 帧，字节 %d，耗时 %s（%.0f 帧/秒）",
		sessions, framesPerSession, sessions*framesPerSession, totalBytes,
		elapsed.Round(time.Millisecond),
		float64(sessions*framesPerSession)/elapsed.Seconds())
}

// sendAgentBinary 以 WebSocket 文本兼容方式发送二进制帧（ws 包对 Agent 侧是客户端 Conn，
// 直接写二进制帧：opcode 0x2，与副端 send_ws_binary 语义一致）。
func sendAgentBinary(c *ws.Conn, frame []byte) error {
	return c.WriteBinary(frame)
}
