package annexb

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// 黄金向量（与 dev/encoder-vt/annexb_stat.py --selftest 共享，防双实现漂移）。
// 每条向量：原始码流 hex + 期望切分（每 NAL 的 [起始码长度, 载荷hex]）。
var goldenVectors = []struct {
	name string
	in   string
	want [][2]any // []{startCodeLen, payloadHex}
}{
	{
		name: "全 4 字节起始码",
		in:   "0000000167abcd0000000168beef0000000165deadbeef",
		want: [][2]any{{4, "67abcd"}, {4, "68beef"}, {4, "65deadbeef"}},
	},
	{
		name: "全 3 字节起始码",
		in:   "00000167abcd00000168beef00000165dead",
		want: [][2]any{{3, "67abcd"}, {3, "68beef"}, {3, "65dead"}},
	},
	{
		name: "首 4 字节后续 3 字节混用",
		in:   "0000000167010203000001680506000001650708",
		want: [][2]any{{4, "67010203"}, {3, "680506"}, {3, "650708"}},
	},
	{
		name: "NAL 载荷尾部 0 紧邻下一起始码（易触发 off-by-one 的形态）",
		// NAL1 = 65 01 02，其后的 00 属于 4 字节起始码 00 00 00 01；
		// 旧实现 prev=i+startLen 在此多跳 1 字节，把下一 NAL 头 68 误读为 88。
		in:   "0000000165010200000001680304000000016709",
		want: [][2]any{{4, "650102"}, {4, "680304"}, {4, "6709"}},
	},
	{
		name: "H.264 关键帧 AU（AUD/SPS/PPS/SEI/IDR，Windows MF 实测形态）",
		in:   "00000001090000000167420000000168ce00000001062a0000000165abcd",
		want: [][2]any{{4, "09"}, {4, "6742"}, {4, "68ce"}, {4, "062a"}, {4, "65abcd"}},
	},
	{
		name: "末 NAL 无后继起始码",
		in:   "00000167aa5500000168bb",
		want: [][2]any{{3, "67aa55"}, {3, "68bb"}},
	},
}

func TestSplitGoldenVectors(t *testing.T) {
	for _, v := range goldenVectors {
		raw, err := hex.DecodeString(v.in)
		if err != nil {
			t.Fatalf("%s: 向量 hex 非法: %v", v.name, err)
		}
		got := Split(raw)
		if len(got) != len(v.want) {
			t.Fatalf("%s: 切分数量 got=%d want=%d", v.name, len(got), len(v.want))
		}
		for i, w := range v.want {
			wantLen := w[0].(int)
			wantHex := w[1].(string)
			if got[i].StartCodeLen != wantLen {
				t.Errorf("%s: NAL#%d 起始码长度 got=%d want=%d", v.name, i+1, got[i].StartCodeLen, wantLen)
			}
			wantPayload, _ := hex.DecodeString(wantHex)
			if !bytes.Equal(got[i].Payload, wantPayload) {
				t.Errorf("%s: NAL#%d 载荷 got=%x want=%x（NAL 首字节错位即 off-by-one 回归）", v.name, i+1, got[i].Payload, wantPayload)
			}
		}
	}
}

func TestValidate(t *testing.T) {
	// H.264 参数集在位（AUD/SPS/PPS/SEI/IDR 形态）
	ok264, _ := hex.DecodeString("0000000109000000016742000000000168ce00000001062a0000000165abcd")
	if err := Validate(ok264, true); err != nil {
		t.Fatalf("合法 H.264 关键帧不应报错: %v", err)
	}
	// H.264 缺 PPS
	noPPS, _ := hex.DecodeString("0000000167420000000165abcd")
	if err := Validate(noPPS, true); err == nil {
		t.Fatal("缺 PPS 应报错")
	}
	// HEVC 参数集在位（VPS/SPS/PPS/IDR：类型 32/33/34/19 → 头字节 = 类型<<1 = 0x40/0x42/0x44/0x26）
	ok265, _ := hex.DecodeString("00000001400000000142420000000144440000000126abcd")
	if err := Validate(ok265, false); err != nil {
		t.Fatalf("合法 HEVC 关键帧不应报错: %v", err)
	}
	// 空载荷 NAL
	empty, _ := hex.DecodeString("0000000167ab000000010000000165cd") // 第 2 个起始码后直接跟下一个起始码
	if err := Validate(empty, true); err == nil {
		t.Fatal("空 NAL 应报错")
	}
	// 缺起始码开头
	bad, _ := hex.DecodeString("67abcd68beef")
	if err := Validate(bad, true); err == nil {
		t.Fatal("缺起始码应报错")
	}
}
