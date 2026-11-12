# 御端 · 原生编码器（macOS VideoToolbox 后端）

按 `dev/proto/protocol.md` §8.3.4 C-ABI 契约实现的**真实**H.264/HEVC 编码器动态库，
供副端（Rust / 后续 Go 版）经 `YUDUAN_ENCODER_LIB` 运行时 `dlopen` 加载。

## 1. 构建

```bash
bash build.sh [输出路径]      # 默认 /tmp/libyuduan_enc_vt.dylib
```

依赖：Xcode Command Line Tools（`clang` + VideoToolbox / CoreMedia / CoreVideo 框架），无第三方依赖。

## 2. 契约

```c
void*    yuduan_enc_create (const char* codec, uint32_t w, uint32_t h);   // "h264"/"h265"，其余返回 NULL
uint32_t yuduan_enc_encode(void* h, const uint8_t* rgba, uint32_t len, uint8_t* out, uint32_t cap);
void     yuduan_enc_destroy(void* h);
```

- 输入：紧凑 RGBA8（`w*h*4` 字节，与会话尺寸一致，否则返回 0 交由上层回退）。
- 输出：Annex-B 裸流（`00 00 00 01` 起始码）；参数集随关键帧前置。
- 返回写入字节数；`out` 容量不足返回 0 并把该帧留在 `pending`，扩张后重试交付**同一帧**。

## 3. 出帧模型（踩坑结论，写新后端前必读）

VideoToolbox 会话有**固定的 1 帧管线延迟**，并且 `CompleteFrames` 会把被推出的帧**强制成 IDR**。
详见 `protocol.md` §8.3.8。本库因此采用「两帧黑帧预置 + 输出队列 + 仅饥饿时兜底 flush」：
稳态出 P 帧（KB 级），首帧 IDR，绝不因每帧 flush 退化成"全 I 帧"（20~40KB/帧）。

| 环境变量 | 作用 |
|---|---|
| `YUDUAN_ENC_DEBUG=1` | 打印会话创建 / 出帧 / 饥饿兜底的 OSStatus 与时序（排障用，生产关闭） |
| `YUDUAN_ENC_HW=0` / `1` | 强制软件 / 强制硬件编码器；未设置 = 系统启发式（默认）。实测本机软编 H.264 不回调，**不要默认强制软件** |

## 4. 验证（可复现 fixture）

```bash
# 4.1 直测库：合成渐变+运动方块 → 裸流
clang -O2 harness.c -o harness
./harness ./libyuduan_enc_vt.dylib h264 1280 720 10 /tmp/out.h264

# 4.2 裸流结构（起始码 / NAL 类型 / 参数集 / ffprobe 交叉验证）
python3 annexb_stat.py /tmp/out.h264

# 4.3 全帧解码零错误
ffmpeg -v error -f h264 -i /tmp/out.h264 -f null -

# 4.4 全链路（中枢 + Rust 副端 + 参考 viewer + 码流级校验）
cd .. && python3 e2e_vt_encoder.py
```

判据：起始码 `00 00 00 01` 或无空 NAL；参数集在位（H.264 SPS7/PPS8；HEVC VPS32/SPS33/PPS34）；
关键帧仅首帧（稳态为 P 帧）；ffmpeg 解码无 stderr 输出。

## 5. 其他平台

Linux（VAAPI / x264+x265 封装）、Windows（Media Foundation）按同一 C-ABI 供库即可；
交付前必须能通过本目录的 `harness.c` + `annexb_stat.py`（把分辨率/内容换成对应平台可跑的值）。
