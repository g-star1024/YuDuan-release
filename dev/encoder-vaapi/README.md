# encoder-vaapi — Linux VAAPI 原生编码器（§8.3.14）

与 `encoder-vt`（macOS VideoToolbox）同构的 §8.3.3 C-ABI 动态库，供副端
`YUDUAN_ENCODER_LIB` 运行时加载。仅支持 h264（其余 codec `create` 返回 NULL，
能力探测不虚标，副端诚实回退 RAW_RGBA）。

## 验证状态（诚实标注）

| 环节 | 状态 |
|---|---|
| 语法/类型（真实 libva 头 `-fsyntax-only`） | ✅ macOS 开发机可跑（`bash check.sh`） |
| 运行时编码验证 | ⏳ 待 Linux + Intel/AMD GPU 实机 |

实机验证步骤：

```bash
bash build-linux.sh /tmp/libyuduan_enc_va.so
# 上面冒烟会打印 create 是否可用；可用则接副端全链：
YUDUAN_ENCODER_LIB=/tmp/libyuduan_enc_va.so ./agent
# 或跑仓库内 e2e：YUDUAN_ENCODER_LIB=... python3 e2e_vt_encoder.py（同脚本复用）
```

## 实现要点

- 显示：`vaGetDisplayDRM`（headless，`YUDUAN_VA_DRM_DEVICE` 默认
  `/dev/dri/renderD128`）；无 GPU/驱动 → `create` 返回 NULL（探测诚实失败）。
- 上传：`vaCreateImage(NV12)` + `vaMapBuffer` 直填 + `vaPutImage`；
  RGBA→NV12 为 BT.601 限幅整数运算（见 `rgba_to_nv12`）。
- 配置：CQP（`YUDUAN_ENC_QP` 默认 26）；profile 探测顺序
  Constrained Baseline → Main → High，首个建配置成功者胜出。
- 参数集：SPS/PPS 由本库构建 RBSP（含防仿真字节），经 packed header
  （param=25/data=26 双缓冲）随 IDR 帧下发；GOP `YUDUAN_ENC_GOP` 默认 120。
- 出帧：每帧 `vaSyncSurface` 同步取 `VAEncCodedBufferType` 段链（无 VT 的
  1 帧管线延迟）；`out` 不足返回 0，输出缓存句柄内待重投（契约语义同 VT）。
- 参考管理：双 surface ping-pong（Curr/Ref 分离），单参考帧，CAVLC Baseline。

## 实机排障入口

- `YUDUAN_ENC_DEBUG=1` 打印每个 VA 调用的 VAStatus 与 profile 探测过程。
- `vainfo`（libva-utils）确认驱动/入口可用性：关注
  `VAProfileH264ConstrainedBaseline: VAEntrypointEncSlice`。
- 常见失败：无权限访问 render 节点（用户需在 `video` 组）、混合显卡选错
  节点（`YUDUAN_VA_DRM_DEVICE` 指定 dGPU 的 renderD129 等）。
