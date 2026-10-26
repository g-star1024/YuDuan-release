// Package annexb —— H.264/H.265 Annex-B 裸流切分与参数集校验（Go 侧权威实现）。
//
// ⚠️ 双实现防漂移：本包与 dev/encoder-vt/annexb_stat.py（Python 侧 split_annexb）
// 是同一逻辑的两份实现——历史上 Go 侧曾出现 4 字节起始码 off-by-one（prev 多推进
// 1 字节导致 NAL 首字节被跳过，IDR 0x65 被误判 PPS），而 Python 侧一直正确
// （Windows 实机验证发现，见 dev/verify-windows-report-20261024.md）。
// 防漂移机制：两侧共享同一组黄金向量——Go 见 annexb_test.go，Python 跑
// `python3 annexb_stat.py --selftest`。改动任何一侧都必须同步向量并在另一侧复跑。
//
// 已知行为差异（有意保留）：Python 侧会 rstrip NAL 尾部对齐零（cabac_zero_words，
// 影响统计显示）；本包保留原始字节（校验口径，不多不少）。参数集判据两侧一致：
// H.264 需 SPS(7)+PPS(8)；HEVC 需 VPS(32)+SPS(33)+PPS(34)——判「参数集在位」而非
// 「首 NAL 必须 SPS」（Windows MF 首帧先出 AUD/SEI，见 §8.3.14 实测）。
package annexb

import (
	"errors"
	"fmt"
)

// Segment 单个 NAL：起始码长度（3 或 4 字节）与 NAL 体（不含起始码）。
type Segment struct {
	StartCodeLen int
	Payload      []byte
}

// NAL 类型（H.264 头字节 & 0x1F；HEVC (头字节>>1) & 0x3F）。
const (
	NalSPS = 7
	NalPPS = 8
)

// Split 按 Annex-B 起始码切分裸流。返回 NAL 段列表（可能为空）。
//
// 正确性要点（即历史上的 off-by-one 修复）：扫描命中 00 00 01 窗口时，若前一字节
// 也是 0，则真实起始码是 4 字节形态 00 00 00 01，其起点在 i-1；NAL 载荷起点 =
// 起始码起点 + 起始码长度，必须按此推算，否则每个 NAL 的首字节会被跳过。
func Split(p []byte) []Segment {
	var segs []Segment
	type sc struct{ pos, length int }
	var starts []sc
	n := len(p)
	for i := 0; i+2 < n; i++ {
		if p[i] == 0 && p[i+1] == 0 && p[i+2] == 1 {
			length := 3
			pos := i
			if i > 0 && p[i-1] == 0 {
				length = 4
				pos = i - 1
			}
			starts = append(starts, sc{pos, length})
			i += 2 // 跳过本窗口（含可能的后续 0 由下一轮判定）
		}
	}
	for k, s := range starts {
		end := n
		if k+1 < len(starts) {
			end = starts[k+1].pos
		}
		if s.pos+s.length <= end {
			segs = append(segs, Segment{StartCodeLen: s.length, Payload: p[s.pos+s.length : end]})
		}
	}
	return segs
}

// Validate 校验裸流合法性：非空、以起始码开头、无空 NAL、参数集在位。
// codec 取 p2pviewer 的 codecH264(2)/codecH265(3) 语义（h264=true 表示 H.264）。
func Validate(p []byte, h264 bool) error {
	if len(p) < 5 {
		return errors.New("载荷过短")
	}
	if !(p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1) &&
		!(p[0] == 0 && p[1] == 0 && p[2] == 1) {
		return errors.New("缺起始码 00 00 00 01")
	}
	segs := Split(p)
	if len(segs) == 0 {
		return errors.New("无 NAL")
	}
	for i, s := range segs {
		if len(s.Payload) == 0 {
			return fmt.Errorf("第 %d 个 NAL 为空（起始码后无载荷）", i+1)
		}
	}
	// 参数集在位：H.264 需 SPS(7)+PPS(8)；HEVC 需 VPS(32)+SPS(33)+PPS(34)
	var seenSPS, seenPPS, seenVPS bool
	for _, s := range segs {
		head := s.Payload[0]
		if h264 {
			switch head & 0x1F {
			case 7:
				seenSPS = true
			case 8:
				seenPPS = true
			}
		} else {
			switch (head >> 1) & 0x3F {
			case 32:
				seenVPS = true
			case 33:
				seenSPS = true
			case 34:
				seenPPS = true
			}
		}
	}
	switch {
	case h264 && !(seenSPS && seenPPS):
		return fmt.Errorf("首帧缺参数集（SPS=%v PPS=%v，H.264 关键帧应携带 SPS(7)+PPS(8)）", seenSPS, seenPPS)
	case !h264 && !(seenVPS && seenSPS && seenPPS):
		return fmt.Errorf("首帧缺参数集（VPS=%v SPS=%v PPS=%v，HEVC 关键帧应携带 VPS(32)+SPS(33)+PPS(34)）", seenVPS, seenSPS, seenPPS)
	}
	return nil
}
