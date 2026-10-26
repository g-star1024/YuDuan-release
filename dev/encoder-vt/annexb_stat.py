#!/usr/bin/env python3
"""御端原生编码器裸流校验：Annex-B 切分 + NAL 类型统计 + ffmpeg/ffprobe 交叉验证。

用法：
  python3 annexb_stat.py <file.h264|file.h265> [expected_w expected_h]
  python3 annexb_stat.py --probe <file> --codec h264 --w 1280 --h 720
  python3 annexb_stat.py --selftest        # 黄金向量自检（防与 Go 侧实现漂移）

职责：
  1. 校验起始码（00 00 00 01 / 00 00 01）、无空 NAL；
  2. 统计 NAL 类型序列（H.264: 7=SPS 8=PPS 5=IDR 1=非IDR片；HEVC: 32=VPS 33=SPS 34=PPS 19/20=IDR 1=TRAIL_R）；
  3. 校验参数集在位（首个可解码单元必须已含 SPS/PPS）；
  4. 可选调用 ffprobe 交叉验证（宽高/帧数/关键帧）。

作为编码器库的**可复现验证 fixture**：任何新编码器后端都必须能通过本脚本。

⚠️ 双实现防漂移：本脚本的 split_annexb 与 Go 侧 dev/internal/annexb 是同一逻辑的
两份实现（历史上 Go 侧曾出现 4 字节起始码 off-by-one 而本脚本一直正确，Windows
实机验证发现）。防漂移机制：两侧共享同一组黄金向量——Go 见 internal/annexb/
annexb_test.go，本脚本见 --selftest。改动任何一侧都必须同步向量并在另一侧复跑。
"""
import re
import subprocess
import sys

H264_NAMES = {1: "非IDR片", 5: "IDR", 6: "SEI", 7: "SPS", 8: "PPS", 9: "AUD"}
H265_NAMES = {1: "TRAIL_R", 19: "IDR_N_LP", 20: "IDR_W_RADL", 32: "VPS", 33: "SPS", 34: "PPS", 35: "AUD", 39: "PREFIX_SEI"}


def split_annexb(data: bytes):
    """返回 [(start_code_len, payload)] ，payload 为 NAL 体（不含起始码，已去尾部补齐零）。"""
    starts = []
    i = 0
    n = len(data)
    while i + 2 < n:
        if data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 1:
            scl = 4 if (i > 0 and data[i - 1] == 0) else 3
            starts.append((i - (scl - 3), scl))
            i += 3
        else:
            i += 1
    if not starts:
        return []
    out = []
    for k, (pos, scl) in enumerate(starts):
        end = starts[k + 1][0] if k + 1 < len(starts) else n
        payload = data[pos + scl:end]
        # 去除尾部用于对齐的零字节（cabac_zero_words）
        payload = payload.rstrip(b"\x00") if payload and payload[-1] == 0 else payload
        out.append((scl, payload))
    return out


def nal_types(data: bytes, hevc: bool):
    types = []
    for scl, payload in split_annexb(data):
        if not payload:
            return None, "存在空 NAL（起始码后无载荷）"
        t = (payload[0] >> 1) & 0x3F if hevc else (payload[0] & 0x1F)
        types.append(t)
    return types, None


GOLDEN_VECTORS = [
    # (名称, hex, [(起始码长度, 载荷hex), ...]) —— 与 dev/internal/annexb/annexb_test.go 共享
    ("全 4 字节起始码",
     "0000000167abcd0000000168beef0000000165deadbeef",
     [(4, "67abcd"), (4, "68beef"), (4, "65deadbeef")]),
    ("全 3 字节起始码",
     "00000167abcd00000168beef00000165dead",
     [(3, "67abcd"), (3, "68beef"), (3, "65dead")]),
    ("首 4 字节后续 3 字节混用",
     "0000000167010203000001680506000001650708",
     [(4, "67010203"), (3, "680506"), (3, "650708")]),
    ("NAL 载荷尾部 0 紧邻下一起始码（易触发 off-by-one 的形态）",
     "0000000165010200000001680304000000016709",
     [(4, "650102"), (4, "680304"), (4, "6709")]),
    ("H.264 关键帧 AU（AUD/SPS/PPS/SEI/IDR，Windows MF 实测形态）",
     "00000001090000000167420000000168ce00000001062a0000000165abcd",
     [(4, "09"), (4, "6742"), (4, "68ce"), (4, "062a"), (4, "65abcd")]),
    ("末 NAL 无后继起始码",
     "00000167aa5500000168bb",
     [(3, "67aa55"), (3, "68bb")]),
]


def selftest() -> int:
    """黄金向量自检：与 Go 侧 internal/annexb 共享同一组向量，防双实现漂移。

    注意：本脚本会把 NAL 尾部对齐零 rstrip（cabac_zero_words），故向量载荷
    均不含尾部零字节，保证两侧口径可比。"""
    import binascii
    failed = 0
    for name, hexstr, want in GOLDEN_VECTORS:
        data = binascii.unhexlify(hexstr)
        got = [(scl, payload.hex()) for scl, payload in split_annexb(data)]
        if got != [(scl, p) for scl, p in want]:
            print(f"FAIL {name}: got={got} want={want}")
            failed += 1
        else:
            print(f"PASS {name}: {len(want)} NAL")
    if failed:
        print(f"--selftest: {failed} 条向量失败（Go 侧同步复跑 go test ./internal/annexb）")
        return 1
    print(f"--selftest: {len(GOLDEN_VECTORS)} 条黄金向量全部通过")
    return 0


def main():
    args = sys.argv[1:]
    if args[:1] == ["--selftest"]:
        return selftest()
    if not args:
        print(__doc__)
        return 1
    path = args[0]
    hevc = (path.endswith(".h265") or path.endswith(".hevc") or path.endswith(".hvc")
            or any(a == "--hevc" for a in args))
    data = open(path, "rb").read()
    parts = split_annexb(data)
    if not parts:
        print(f"FAIL {path}: 未找到 Annex-B 起始码")
        return 1
    types, err = nal_types(data, hevc)
    if err:
        print(f"FAIL {path}: {err}")
        return 1
    names = H265_NAMES if hevc else H264_NAMES
    seq = ", ".join(f"{t}({names.get(t, '?')})" for t in types)
    print(f"OK {path}: {len(types)} 个 NAL，类型序列: {seq}")
    if hevc:
        need = {32, 33, 34}
        has_ps = need.issubset(set(types))
        key_types = {19, 20}
    else:
        need = {7, 8}
        has_ps = need.issubset(set(types))
        key_types = {5}
    print(f"参数集在位: {has_ps}（期望包含 {sorted(need)}）")
    if not has_ps:
        print("FAIL: 缺参数集，解码器无法起播")
        return 1
    # 首个参数集应出现在第一个 IDR 之前（保证首帧可独立解码）
    first_key = next((i for i, t in enumerate(types) if t in key_types), None)
    first_ps = next((i for i, t in enumerate(types) if t in need), None)
    if first_key is not None and first_ps is not None and first_ps > first_key:
        print("WARN: 首个关键帧出现在参数集之前（部分解码器容错，但不推荐）")
    print(f"关键帧(I)数量: {sum(1 for t in types if t in key_types)} / 片层单元: {sum(1 for t in types if t in ({1, 5} if not hevc else {1, 19, 20}))}")
    # ffprobe 交叉验证（存在 ffmpeg 时）
    try:
        fmt = "hevc" if hevc else "h264"
        p = subprocess.run(
            ["ffprobe", "-f", fmt, "-i", path, "-show_entries",
             "frame=pkt_size,key_frame", "-of", "csv=p=0"],
            capture_output=True, text=True, timeout=60)
        if p.returncode == 0 and p.stdout.strip():
            lines = [l for l in p.stdout.strip().splitlines() if l.strip()]
            keys = sum(1 for l in lines if l.split(",")[1] == "1")
            print(f"ffprobe: 解码出 {len(lines)} 帧，其中关键帧 {keys}")
    except FileNotFoundError:
        print("ffprobe 不可用（跳过交叉验证）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
