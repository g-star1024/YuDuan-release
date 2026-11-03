# encoder-mf — Windows Media Foundation 原生编码器（§8.3.14）

与 `encoder-vt`（macOS）/ `encoder-vaapi`（Linux）同构的 §8.3.3 C-ABI 动态库，
供副端 `YUDUAN_ENCODER_LIB` 运行时加载。仅支持 h264（微软系统自带 H.264 编码
MFT，Windows 8+ 无需额外安装；其余 codec `create` 返回 NULL，副端诚实回退）。

## 验证状态（诚实标注）

| 环节 | 状态 |
|---|---|
| 语法/类型（mfstub.h 声明子集 `-fsyntax-only`） | ✅ macOS 开发机可跑（`bash check.sh`） |
| 运行时编码验证 | ✅ **Windows 11 实机通过**（2026-10-24）：harness 直测 60 帧 + 系统 MS H264 解码 MFT 独立实解零错误 + 远控 relay 全链路 60 帧 15.3fps（报告 `dev/verify-windows-report-20261024.md`） |

实机结论要点：MS H264 编码 MFT 固有 12 帧管线延迟（无低延迟旋钮），本库以
「预置 13 帧黑帧 + 输出队列」吸收；一次性塞多帧会丢帧，须逐帧提交+逐帧拉取；
扩展导出 `yuduan_enc_flush`（DRAIN 冲刷）。详细出帧模型见 `yuduan_enc_mf.c` 头注释。

实机验证步骤（"x64 Native Tools Command Prompt"）：

```cmd
build-windows.cmd
build-harness.cmd
:: 直测（与 encoder-vt/harness.c 同构的 Windows 版，LoadLibraryA 加载）：
enc_harness.exe %TEMP%\yuduan_enc_mf.dll h264 1280 720 60 out.h264
:: out.h264 用 ffprobe/ffplay 交叉验证；通过后再接入副端走全链路（见 dev/verify-windows.md）
set YUDUAN_ENCODER_LIB=%TEMP%\yuduan_enc_mf.dll
:: 启动副端，能力宣告应含 h264
```

直测工具 `harness-win.c` 与 `encoder-vt/harness.c` 逐行同构（仅 dlopen→LoadLibraryA
差异），保证三平台编码器验证口径一致。

## 实现要点

- 枚举：`MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, SYNCMFT, out=H264)`，无编码器
  → `create` 返回 NULL（探测诚实失败）。异步 MFT（SYNCMFT 枚举不到的）不覆盖，
  可在实机按需加 `MFT_ENUM_FLAG_ASYNCMFT` + 事件驱动改造。
- 类型协商：先 SetOutputType（GetOutputAvailableType 找 H264 子型 + 设码率/Profile），
  再 SetInputType（NV12 渐进，30fps）——编码器 MFT 要求先输出后输入。
- 码控：CBR（`YUDUAN_ENC_KBPS` 默认 4000kbps）；GOP `YUDUAN_ENC_GOP` 默认 120，
  关键帧经 `ICodecAPI CODECAPI_AVEncVideoForceKeyFrame` 强推（首帧必推）。
- SPS/PPS：MS H264 MFT 在关键帧 in-band 自带（Annex-B），无需手工前置。
- 出帧：ProcessInput 后 ProcessOutput 拉取；首帧前 `NEED_MORE_INPUT` 属正常
  （MFT 管线缓存），该轮 encode 返回 0 且无 pending，副端按丢弃重采处理。
- COM：create 中 `CoInitializeEx(MULTITHREADED)` + `MFStartup`；destroy 对称释放。
  注意契约要求 create/encode/destroy 同线程调用（COM 单元约束）。

## 实机排障入口

- `YUDUAN_ENC_DEBUG=1` 打印各阶段 HRESULT。
- 常见失败：N 版 Windows 缺媒体特性包（无 H.264 编码 MFT）；
  远程会话/无 GPU 时 MS 软编码器仍可用（MFT 是系统组件）。
- mfstub.h 仅离线自检用（GUID 值据 MSDN）；目标机以 SDK 真头为准。
