package ws

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// echoTypedHandler 升级后回显每条消息：二进制→二进制，文本→文本（验证类型不串味）。
func echoTypedHandler(w http.ResponseWriter, r *http.Request) {
	c, err := Upgrade(w, r)
	if err != nil {
		return
	}
	defer c.Close()
	for {
		data, isBinary, err := c.ReadMessageTyped()
		if err != nil {
			return
		}
		if isBinary {
			if err := c.WriteBinary(data); err != nil {
				return
			}
			continue
		}
		if err := c.WriteMessage(data); err != nil {
			return
		}
	}
}

func wsURL(srv *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + path
}

// TestBinaryFrameRoundTrip 验证二进制帧双向收发：客户端发二进制→服务端读到 isBinary=true，
// 服务端回二进制→客户端同样读到；载荷逐字节一致（含掩码解扰正确）。
func TestBinaryFrameRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echoTypedHandler))
	defer srv.Close()

	c, err := Dial(wsURL(srv, "/echo"))
	if err != nil {
		t.Fatalf("dial 失败: %v", err)
	}
	defer c.Close()

	// 构造一个 §8.3 二进制媒体帧样式的载荷：magic + 版本 + 少量字节
	payload := []byte{0x46, 0x59, 0x44, 0x59, 0x01, 0x00, 0x01, 0x00, 0x2A, 0x00, 0x00, 0x00}
	if err := c.WriteBinary(payload); err != nil {
		t.Fatalf("WriteBinary 失败: %v", err)
	}
	got, isBinary, err := c.ReadMessageTyped()
	if err != nil {
		t.Fatalf("ReadMessageTyped 失败: %v", err)
	}
	if !isBinary {
		t.Fatalf("回显应为二进制帧，实际 isBinary=false")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("二进制载荷不一致: got=%v want=%v", got, payload)
	}

	// 文本帧仍然按文本语义往返（不串味）
	if err := c.WriteMessage([]byte("hello")); err != nil {
		t.Fatalf("WriteMessage 失败: %v", err)
	}
	txt, isBinary, err := c.ReadMessageTyped()
	if err != nil {
		t.Fatalf("读文本失败: %v", err)
	}
	if isBinary || string(txt) != "hello" {
		t.Fatalf("文本帧语义错误: isBinary=%v txt=%q", isBinary, txt)
	}
}

// TestReadMessageSkipsBinary 验证 ReadMessage 的既有语义：跳过二进制帧只返回文本。
func TestReadMessageSkipsBinary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echoTypedHandler))
	defer srv.Close()

	c, err := Dial(wsURL(srv, "/echo"))
	if err != nil {
		t.Fatalf("dial 失败: %v", err)
	}
	defer c.Close()

	// 先发一帧二进制（服务端回显二进制），再发文本；ReadMessage 应只拿到文本。
	if err := c.WriteBinary([]byte("binary-should-be-skipped")); err != nil {
		t.Fatalf("WriteBinary 失败: %v", err)
	}
	if err := c.WriteMessage([]byte("text-only")); err != nil {
		t.Fatalf("WriteMessage 失败: %v", err)
	}
	got, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage 失败: %v", err)
	}
	if string(got) != "text-only" {
		t.Fatalf("ReadMessage 应跳过二进制只返回文本, got=%q", got)
	}
}

// TestLargeBinaryFrame 验证大帧（>64KiB，走 16 位扩展长度）二进制往返。
func TestLargeBinaryFrame(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(echoTypedHandler))
	defer srv.Close()

	c, err := Dial(wsURL(srv, "/echo"))
	if err != nil {
		t.Fatalf("dial 失败: %v", err)
	}
	defer c.Close()

	payload := make([]byte, 300*1024) // 300KB，超出 16 位上限前先覆盖 126 分支
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := c.WriteBinary(payload); err != nil {
		t.Fatalf("WriteBinary 失败: %v", err)
	}
	got, isBinary, err := c.ReadMessageTyped()
	if err != nil {
		t.Fatalf("ReadMessageTyped 失败: %v", err)
	}
	if !isBinary || !bytes.Equal(got, payload) {
		t.Fatalf("大二进制帧往返失败: isBinary=%v len=%d want=%d", isBinary, len(got), len(payload))
	}
}
