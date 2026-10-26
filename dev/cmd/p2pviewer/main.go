// Command p2pviewer 是 P2P 二进制媒体环（protocol.md §8.3）的端到端验证 viewer（参考实现）。
//
// 以主端身份经中枢建立远控会话、接收能力宣告并发送 rc_select 协商，随后按 transport
// 收取二进制媒体帧：
//   - p2p：监听媒体端口，接收被控端 dial_direct 直连帧（4B 长度前缀分帧）；
//   - relay：经中枢 viewer 长连接收取二进制帧中继（P2P 不可达时的兜底路径）。
//
// 校验帧格式（magic/version/头字段）与 JPEG SOI，落盘样例帧并输出统计。
// 用途：CI/联调验证远控媒体运行时，不面向终端用户。
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"yuduan/internal/annexb"
	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

const (
	frameMagic     = 0x59445946 // 'YDYF' 小端（与 Rust rc_media.FRAME_MAGIC 一致）
	frameVersion   = 1
	frameHeaderLen = 24
	codecJPEG      = 1
	codecRawRGBA   = 0
	codecH264      = 2
	codecH265      = 3
)

var codecNames = []string{"raw_rgba", "jpeg", "h264", "h265", "vp8", "vp9", "av1"}

func main() {
	hub := flag.String("hub", "ws://127.0.0.1:18080", "中枢 viewer WS 地址（不含路径）")
	device := flag.String("device", "", "被控设备 ID（必填）")
	transport := flag.String("transport", "p2p", "p2p 直连 / relay 中继")
	codec := flag.Int("codec", codecJPEG, "协商编解码器 ID（1=jpeg）")
	media := flag.String("media", "127.0.0.1:19500", "p2p 媒体监听地址（被控端 dial 此地址）")
	selectAddr := flag.String("selectaddr", "", "rc_select 携带的媒体地址（默认同 -media；设为不可达地址可验证 P2P 失败后的中继回退）")
	frames := flag.Int("frames", 5, "收集满 N 帧即结束")
	out := flag.String("out", "/tmp/p2pviewer-out", "样例帧输出目录")
	timeout := flag.Duration("timeout", 25*time.Second, "总体超时")
	candidates := flag.Bool("candidates", true, "p2p 时广播本机候选地址（ICE-lite：被控端逐个尝试直连）")
	qos := flag.Int("qos", 0, "协商后每 2s 向被控端发送 rc_qos 目标帧率（0=关闭；验证 §8.3.9 带宽自适应闭环）")
	probe := flag.Bool("probe", false, "每 1s 发 rc_ping 探测 RTT（§8.3.11），并按 RTT 档位向被控端反馈帧率上限")
	loss := flag.Int("loss", -1, "rc_qos 携带的丢包率 %（§8.3.15；-1=使用真实帧序号缺口测量；≥0 注入固定值，供 e2e 验证丢包档位策略）")
	kbps := flag.Int64("kbps", 0, "rc_qos 携带的实测接收码率 kbps（§8.3.15；0=使用真实接收字节测量；>0 注入固定值，供 e2e 验证码率重参数化）")
	flag.Parse()
	if *device == "" {
		fatal("需指定 -device（被控设备 ID）")
	}
	if *transport != "p2p" && *transport != "relay" {
		fatal("-transport 仅支持 p2p / relay")
	}

	sessionID := fmt.Sprintf("s-%d", time.Now().UnixNano())

	// p2p：先监听（被控端收到 rc_select 才会 dial，监听必须先就绪）。
	var ln net.Listener
	if *transport == "p2p" {
		var err error
		ln, err = net.Listen("tcp", *media)
		if err != nil {
			fatal("P2P 媒体监听失败: %v", err)
		}
		defer ln.Close()
		logf("P2P 媒体监听 %s（等待被控端直连）", ln.Addr())
	}

	conn, err := ws.Dial(*hub + "/ws/viewer")
	if err != nil {
		fatal("viewer WS 连接失败: %v", err)
	}
	defer conn.Close()

	// 1) rc_request 建立会话（中枢据此登记 Viewer 并转发给被控端）
	req, err := proto.NewEnvelope(proto.TypeRCRequest, 0, proto.RCRequestPayload{
		DeviceID: *device, SessionID: sessionID, Operator: "p2pviewer",
	})
	if err != nil {
		fatal("构造 rc_request 失败: %v", err)
	}
	reqB, _ := json.Marshal(req)
	if err := conn.WriteMessage(reqB); err != nil {
		fatal("发送 rc_request 失败: %v", err)
	}
	logf("已发送 rc_request device=%s session=%s transport=%s codec=%d", *device, sessionID, *transport, *codec)

	// 2) 读循环：文本信封 → evCh；二进制帧 → frameCh
	type envelope = proto.Envelope
	evCh := make(chan envelope, 32)
	frameCh := make(chan []byte, 64)
	go func() {
		for {
			d, isBinary, err := conn.ReadMessageTyped()
			if err != nil {
				close(evCh)
				close(frameCh)
				return
			}
			if isBinary {
				frameCh <- d
				continue
			}
			var env envelope
			if json.Unmarshal(d, &env) == nil {
				evCh <- env
			}
		}
	}()

	// p2p：accept 被控端直连后按 4B 长度前缀读帧
	if ln != nil {
		go func() {
			c, err := ln.Accept()
			if err != nil {
				logf("P2P accept 失败: %v", err)
				return
			}
			defer c.Close()
			logf("P2P 直连建立: %s", c.RemoteAddr())
			for {
				var lenBuf [4]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					logf("P2P 连接读取结束: %v", err)
					return
				}
				n := binary.LittleEndian.Uint32(lenBuf[:])
				buf := make([]byte, n)
				if _, err := io.ReadFull(c, buf); err != nil {
					logf("P2P 帧体读取失败: %v", err)
					return
				}
				frameCh <- buf
			}
		}()
	}

	// 3) 主循环：等能力宣告→发协商；收帧→校验+落盘；收满即止
	deadline := time.Now().Add(*timeout)
	started := time.Time{}
	got, totalBytes := 0, 0
	selectSent := false
	codecAdopted := false
	lastQosByRtt := time.Time{} // §8.3.11：上次按 RTT 反馈的时刻（节流 2s）
	meas := mediaMeas{}         // §8.3.15：媒体实测（帧序号缺口 → 丢包率；窗口字节 → 接收码率）

	for got < *frames {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			fatal("超时：仅收到 %d/%d 帧（transport=%s）", got, *frames, *transport)
		}
		select {
		case env, ok := <-evCh:
			if !ok {
				fatal("viewer 连接关闭（仅 %d/%d 帧）", got, *frames)
			}
			switch env.Type {
			case proto.TypeRCReady:
				logf("rc_ready ok=%v", payloadOK(env))
			case proto.TypeRCCapabilities:
				var p proto.RCCapabilitiesPayload
				_ = env.DecodePayload(&p)
				logf("能力宣告: codecs=%v %dx%d@%dfps", p.Codecs, p.MaxW, p.MaxH, p.Fps)
				if !selectSent {
					addr := *media
					if *selectAddr != "" {
						addr = *selectAddr
					}
					// 协商：p2p 带上媒体监听地址；relay 无需地址
					sel, err := proto.NewEnvelope(proto.TypeRCSelect, 0, proto.RCSelectPayload{
						SessionID: sessionID, Codec: *codec, Transport: *transport, MediaAddr: addr,
					})
					if err != nil {
						fatal("构造 rc_select 失败: %v", err)
					}
					selB, _ := json.Marshal(sel)
					if err := conn.WriteMessage(selB); err != nil {
						fatal("发送 rc_select 失败: %v", err)
					}
					selectSent = true
					logf("已发送 rc_select（transport=%s codec=%d media=%s）", *transport, *codec, addr)
					// ICE-lite：广播本机候选地址（被控端首跳失败时逐个尝试直连升级）。
					if *transport == "p2p" && *candidates {
						sendCandidates(conn, sessionID, ln)
					}
					// §8.3.9/§8.3.15 带宽自适应闭环：周期反馈帧率 + 媒体实测（丢包率/接收码率）。
					// 首条立即发送（等 2s 的话低速用例收满前反馈根本到不了），此后每 2s 一次。
					// 触发条件：-qos 开启，或 -loss/-kbps 注入（e2e 验证 §8.3.15 策略）。
					if *qos > 0 || *loss >= 0 || *kbps > 0 {
						go func() {
							for i := 0; ; i++ {
								if i > 0 {
									time.Sleep(2 * time.Second)
								}
								lossPct, kbpsGot := meas.snapshot()
								if *loss >= 0 {
									lossPct = *loss
								}
								if *kbps > 0 {
									kbpsGot = *kbps
								}
								q, err := proto.NewEnvelope(proto.TypeRCQos, 0, proto.RCQosPayload{
									SessionID: sessionID, FPS: *qos, Reason: "p2pviewer-feedback",
									LossPct: lossPct, Kbps: kbpsGot,
								})
								if err != nil {
									return
								}
								qB, _ := json.Marshal(q)
								if err := conn.WriteMessage(qB); err != nil {
									return
								}
								logf("已发送 rc_qos fps=%d loss=%d%% kbps=%d", *qos, lossPct, kbpsGot)
							}
						}()
					}
					// §8.3.11 传输级自适应：周期 RTT 探测；RTT>80ms 时按档位反馈帧率上限，
					// 让被控端在不依赖渲染统计的情况下感知网络拥塞。
					if *probe {
						go func() {
							for {
								time.Sleep(1 * time.Second)
								p, err := proto.NewEnvelope(proto.TypeRCPing, 0, proto.RCPingPayload{
									SessionID: sessionID, T0: time.Now().UnixMilli(),
								})
								if err != nil {
									return
								}
								pB, _ := json.Marshal(p)
								if err := conn.WriteMessage(pB); err != nil {
									return
								}
							}
						}()
					}
				}
			case proto.TypeRCPong:
				var p proto.RCPingPayload
				_ = env.DecodePayload(&p)
				rtt := time.Now().UnixMilli() - p.T0
				logf("RTT 探测: %d ms", rtt)
				// RTT 越过档位（>80ms）→ 立即反馈一次上限（副端 min(目标, 档位) 生效）
				if *probe && rtt > 80 && time.Since(lastQosByRtt) > 2*time.Second {
					cap := 15
					if rtt > 400 {
						cap = 4
					} else if rtt > 200 {
						cap = 8
					}
					q, err := proto.NewEnvelope(proto.TypeRCQos, 0, proto.RCQosPayload{
						SessionID: sessionID, FPS: cap, Reason: "rtt_probe", RTTMs: rtt,
					})
					if err == nil {
						qB, _ := json.Marshal(q)
						if err := conn.WriteMessage(qB); err == nil {
							logf("已发送 rc_qos（RTT %dms → 上限 %dfps）", rtt, cap)
							lastQosByRtt = time.Now()
						}
					}
				}
			case proto.TypeRCEvent:
				var p proto.RCEventPayload
				_ = env.DecodePayload(&p)
				logf("事件[%s]: %s", p.Kind, p.Message)
				if p.Kind == "error" {
					fatal("被控端报错: %s", p.Message)
				}
				// 被控端可能诚实回退编解码器（如选 h265 但无原生库 → jpeg）：
				// 从 media_selected 事件末尾的 codec 名采纳实际值，避免误判有效帧。
				if p.Kind == "media_selected" && !codecAdopted {
					if name := lastToken(p.Message); name != "" {
						for i, n := range codecNames {
							if n == name {
								*codec = i
								codecAdopted = true
								logf("采纳被控端实际编解码器: %s", name)
								break
							}
						}
					}
				}
			case proto.TypeRCStop:
				fatal("会话被结束（仅 %d/%d 帧）", got, *frames)
			}
		case frame, ok := <-frameCh:
			if !ok {
				fatal("帧通道关闭（仅 %d/%d 帧）", got, *frames)
			}
			codecGot, fw, fh, payload, err := checkFrame(frame, *codec)
			if err != nil {
				logf("丢弃无效帧: %v", err)
				continue
			}
			if got == 0 {
				started = time.Now()
				logf("首帧头 8 字节: % x（%s 帧用于校验编码器输出特征）", payload[:min(8, len(payload))], codecName(codecGot))
				// 首帧 = 关键帧：H.264 首段应为 SPS(7)，HEVC 应为 VPS(32)
				if int(codecGot) == codecH264 || int(codecGot) == codecH265 {
					if err := checkAnnexB(payload, codecGot); err != nil {
						fatal("首帧 Annex-B/参数集校验失败: %v", err)
					}
					logf("首帧 Annex-B 校验通过（起始码 + 参数集在位）")
				}
			}
			got++
			totalBytes += len(payload)
			meas.record(frame[8:12], len(payload)) // 24B 头 seq 域（§8.3.15 实测）
			saved := saveFrame(*out, got, codecGot, payload)
			logf("帧 #%d ok: codec=%s %dx%d %d 字节载荷 → %s", got, codecName(codecGot), fw, fh, len(payload), saved)
		}
	}

	elapsed := time.Since(started)
	// 4) 结束会话（rc_stop 载荷仅携带 session_id，中枢/被控端均不强制解析）
	stop, err := proto.NewEnvelope(proto.TypeRCStop, 0, map[string]string{"session_id": sessionID})
	if err != nil {
		fatal("构造 rc_stop 失败: %v", err)
	}
	stopB, _ := json.Marshal(stop)
	_ = conn.WriteMessage(stopB)

	fmt.Printf("P2PVIEWER_OK frames=%d transport=%s codec=%s bytes=%d elapsed=%s avg_fps=%.1f\n",
		got, *transport, codecName(byte(*codec)), totalBytes,
		elapsed.Round(time.Millisecond), float64(got)/elapsed.Seconds())
}

// checkFrame 校验二进制媒体帧格式；wantCodec>0 时还要求编解码器与协商值一致。
// 返回（编解码器, 宽, 高, payload）。RAW_RGBA 帧额外校验载荷长度 == 宽*高*4。
func checkFrame(b []byte, wantCodec int) (byte, int, int, []byte, error) {
	if len(b) < frameHeaderLen {
		return 0, 0, 0, nil, fmt.Errorf("帧过短 %d < %d", len(b), frameHeaderLen)
	}
	if binary.LittleEndian.Uint32(b[0:4]) != frameMagic {
		return 0, 0, 0, nil, errors.New("magic 不匹配")
	}
	if b[4] != frameVersion {
		return 0, 0, 0, nil, fmt.Errorf("帧版本 %d 不支持", b[4])
	}
	codec := b[6]
	w := int(binary.LittleEndian.Uint16(b[12:14]))
	h := int(binary.LittleEndian.Uint16(b[14:16]))
	ln := int(binary.LittleEndian.Uint32(b[20:24]))
	if len(b) < frameHeaderLen+ln {
		return 0, 0, 0, nil, fmt.Errorf("载荷截断: 声明 %d 实际 %d", ln, len(b)-frameHeaderLen)
	}
	payload := b[frameHeaderLen : frameHeaderLen+ln]
	if wantCodec > 0 && int(codec) != wantCodec {
		return 0, 0, 0, nil, fmt.Errorf("编解码器 %d 非协商值 %d", codec, wantCodec)
	}
	if codec == codecJPEG && (len(payload) < 2 || payload[0] != 0xFF || payload[1] != 0xD8) {
		return 0, 0, 0, nil, errors.New("JPEG 载荷缺 SOI 标记")
	}
	if int(codec) == codecH264 || int(codec) == codecH265 {
		if err := checkAnnexB(payload, 0); err != nil {
			return 0, 0, 0, nil, fmt.Errorf("%s 载荷非合法 Annex-B: %v", codecNames[codec], err)
		}
	}
	if codec == codecRawRGBA {
		if w == 0 || h == 0 {
			return 0, 0, 0, nil, errors.New("RAW 帧宽高为 0")
		}
		if len(payload) != w*h*4 {
			return 0, 0, 0, nil, fmt.Errorf("RAW 载荷长度 %d != %dx%dx4", len(payload), w, h)
		}
	}
	return codec, w, h, payload, nil
}

// sendCandidates 广播 ICE-lite 候选：
//   - 监听绑定具体 IP（如 127.0.0.1）→ 唯一候选即该地址（拨别的地址必然被拒）；
//   - 监听绑定通配地址（0.0.0.0 / ::）→ 枚举本机非回送网卡 IPv4 + 监听端口。
//
// 先发 rc_offer（批量），再逐个 rc_candidate（增量，与协议 §8.3 一致）。
func sendCandidates(conn *ws.Conn, sessionID string, ln net.Listener) {
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		logf("候选收集失败（监听地址解析）: %v", err)
		return
	}
	var cands []string
	if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
		cands = []string{net.JoinHostPort(ip.String(), port)}
	} else {
		ifaces, err := net.Interfaces()
		if err != nil {
			logf("候选收集失败（枚举网卡）: %v", err)
			return
		}
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() || ip.To4() == nil {
					continue // 仅 IPv4（媒体环当前按 IPv4 拨号）
				}
				cands = append(cands, net.JoinHostPort(ip.String(), port))
			}
		}
	}
	if len(cands) == 0 {
		return
	}
	offer, err := proto.NewEnvelope(proto.TypeRCOffer, 0, proto.RCOfferPayload{SessionID: sessionID, Candidates: cands})
	if err == nil {
		if b, err := json.Marshal(offer); err == nil {
			_ = conn.WriteMessage(b)
		}
	}
	for _, c := range cands {
		cm, err := proto.NewEnvelope(proto.TypeRCCandidate, 0, proto.RCCandidatePayload{SessionID: sessionID, Candidate: c})
		if err != nil {
			continue
		}
		if b, err := json.Marshal(cm); err == nil {
			_ = conn.WriteMessage(b)
		}
	}
	logf("已广播 %d 个 ICE-lite 候选: %v", len(cands), cands)
}

func saveFrame(dir string, n int, codec byte, payload []byte) string {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logf("建目录失败: %v", err)
		return "(未落盘)"
	}
	ext := ".bin"
	if int(codec) < len(codecNames) {
		ext = "." + codecNames[codec]
	}
	path := filepath.Join(dir, fmt.Sprintf("frame-%03d%s", n, ext))
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		logf("落盘失败: %v", err)
		return "(未落盘)"
	}
	return path
}

// lastToken 取消息末尾以空白分隔的最后一个词（media_selected 消息以 codec 名结尾）。
func lastToken(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// mediaMeas 媒体实测（§8.3.15）：主端侧丢包率与接收码率测量。
//   - 丢包率：二进制媒体帧 24B 头携带单调递增 seq（uint32），按序号缺口累计丢帧数；
//     TCP 传输下正常无缺口（机制对齐未来 UDP 媒体路径与真实弱网），e2e 用注入值验证策略。
//   - 接收码率：滑动窗口累计载荷字节，取样时按窗口时长折算 kbps（取样即清零窗口）。
type mediaMeas struct {
	mu          sync.Mutex
	lastSeq     uint32
	seqSeen     bool
	lossFrames  int
	totalFrames int
	winBytes    int
	winStart    time.Time
}

// record 记录一帧：seq 取自 24B 头 seq 域（b[8:12]），n 为载荷字节数。
func (m *mediaMeas) record(seqB []byte, n int) {
	if len(seqB) < 4 {
		return
	}
	seq := binary.LittleEndian.Uint32(seqB)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seqSeen {
		gap := int64(int32(seq - m.lastSeq)) // 回绕安全差值；正常为 1
		if gap > 1 {
			m.lossFrames += int(gap - 1)
		}
	}
	m.seqSeen = true
	m.lastSeq = seq
	m.totalFrames++
	m.winBytes += n
	if m.winStart.IsZero() {
		m.winStart = time.Now()
	}
}

// snapshot 取样：返回 (丢包率 %, 接收码率 kbps)；码率窗口取样后清零。
func (m *mediaMeas) snapshot() (int, int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var lossPct int
	if m.lossFrames > 0 {
		lossPct = m.lossFrames * 100 / (m.totalFrames + m.lossFrames)
	}
	var kbps int64
	if !m.winStart.IsZero() {
		if dt := time.Since(m.winStart).Seconds(); dt > 0.2 {
			kbps = int64(float64(m.winBytes) * 8 / dt / 1000)
		}
		m.winBytes = 0
		m.winStart = time.Now()
	}
	return lossPct, kbps
}

// checkAnnexB 校验 H.264/H.265 裸流：Annex-B 起始码切分 NAL，逐段非空，
// 且首帧内参数集在位（H.264 需含 SPS(7)+PPS(8)；HEVC 需含 VPS(32)+SPS(33)+PPS(34)）。
//
// 切分与校验逻辑已收口到 internal/annexb（权威实现）——本函数只是兼容包装。
// ⚠️ 双实现防漂移：Python 侧镜像实现见 dev/encoder-vt/annexb_stat.py
// （`--selftest` 共享同一组黄金向量）；改动任何一侧都必须同步另一侧。
// 判据是「参数集在位」而非「首 NAL 必须 SPS」——不同编码器的首帧形态不同：
// macOS VideoToolbox 首帧以 SPS 开头，而 Windows Media Foundation 会先输出
// AUD(9) / SEI(6) 再到 SPS/PPS（见 dev/encoder-mf 实测与 internal/annexb 文档）。
func checkAnnexB(p []byte, codec byte) error {
	return annexb.Validate(p, codec == codecH264)
}

func payloadOK(env proto.Envelope) any {
	var p proto.RCReadyPayload
	if err := env.DecodePayload(&p); err != nil {
		return "?"
	}
	return p.OK
}

func codecName(c byte) string {
	if int(c) < len(codecNames) {
		return codecNames[c]
	}
	return fmt.Sprintf("codec:%d", c)
}

func logf(format string, args ...any) {
	fmt.Printf("[p2pviewer %s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "P2PVIEWER_FAIL: "+format+"\n", args...)
	os.Exit(1)
}
