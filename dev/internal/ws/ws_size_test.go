package ws

// 复盘 S-4/QA P0-2 回归：帧长度上限与短读错误传播。
// 此前 ReadMessageTyped 对 ln==127 直接 make([]byte, uint64)，
// 8 字节帧头声明 2^64 长度即可打爆内存；且 io.ReadFull 错误被静默忽略。

import (
	"bufio"
	"errors"
	"net"
	"testing"
)

// TestReadFrameSizeCap：声明超限长度的帧必须立即报错，而非分配巨额内存。
func TestReadFrameSizeCap(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// 服务端视角：isClient=false。对端写一个 ln==127、扩展长度 2^40 的帧头。
	serverConn := &Conn{conn: c1, buf: bufio.NewReader(c1), isClient: false}
	go func() {
		// b0=0x81(text) b1=0xFF(掩码位|127)，8 字节扩展长度 = 1<<40
		hdr := []byte{0x81, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
		_, _ = c2.Write(hdr)
		// 若实现错误地按 2^40 分配，这里会先 OOM/挂死；正确实现立刻报错。
	}()

	_, _, err := serverConn.ReadMessageTyped()
	if err == nil {
		t.Fatal("超限帧未被拒绝（S-4 回归失败）")
	}
	if !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("应返回 errFrameTooLarge，got: %v", err)
	}
}

// TestReadFrameShortReadError：帧头声明长度与实际载荷不符时必须返回错误，
// 不得静默把残包当完整消息（io.ReadFull 错误传播回归）。
func TestReadFrameShortReadError(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()

	serverConn := &Conn{conn: c1, buf: bufio.NewReader(c1), isClient: false}
	go func() {
		// 声明 126 长度但只写 3 字节就关闭——ReadFull 必须报错
		_, _ = c2.Write([]byte{0x81, 126, 0x00, 0x10, 0xAA, 0xBB, 0xCC})
		c2.Close()
	}()

	_, _, err := serverConn.ReadMessageTyped()
	if err == nil {
		t.Fatal("短读未报错——ReadFull 错误仍被忽略（S-4 回归失败）")
	}
}

// TestDialTokenAppendsParam：DialToken 应把 token 附加为查询参数（S-1 客户端配套）。
func TestDialTokenAppendsParam(t *testing.T) {
	// 不发起真实连接：仅验证 URL 拼接逻辑（通过不合法 scheme 快速失败前的行为不可见，
	// 故直接测拼接函数语义——以无 token 的 URL 构造校验）。
	got := appendToken("/ws/viewer", "abc")
	if got != "/ws/viewer?token=abc" {
		t.Fatalf("appendToken 无查询串: %q", got)
	}
	got = appendToken("/ws/viewer?x=1", "abc")
	if got != "/ws/viewer?x=1&token=abc" {
		t.Fatalf("appendToken 已有查询串: %q", got)
	}
}
