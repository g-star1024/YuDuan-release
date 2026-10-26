# 御端 · 跨平台接口契约（M1 冻结基线 v1）

> 副端 Agent 以 Rust 实现，下方为跨平台抽象 trait（伪代码），三平台各自提供实现。
> 对应 TDD 第 7/8/9 章。未覆盖三平台实现的功能不得宣告完成（铁律 2）。

## 1. 服务管理（常驻）

```rust
trait ServiceManager {
    fn install() -> Result<()>;        // 安装为系统服务并开机自启
    fn start() -> Result<()>;
    fn stop() -> Result<()>;
    fn uninstall() -> Result<()>;     // 需授权码/控制台授权（防卸载）
    fn self_check() -> Result<()>;    // 启动自校验哈希/签名（防篡改）
}
```
- Windows：`sc` / 原生服务；macOS：`launchd` plist；Linux：`systemd` unit。

## 2. 资产采集

```rust
trait AssetCollector {
    fn collect_hardware() -> HardwareInfo;   // CPU/内存/磁盘/序列号/MAC/IP/显示器
    fn collect_software() -> Vec<SoftwareInfo>; // 已装软件/版本/来源
}
```
| 项 | Windows | macOS | Linux |
|---|---|---|---|
| 硬件 | WMI / PowerShell | `system_profiler` / `ioreg` | `/proc` + `lshw` / `dmidecode` |
| 软件 | 注册表 / WMI | `/Applications` + `pkgutil` | `dpkg` / `rpm` |

- 差异上报：仅回传变更项；首次全量。

## 3. 屏幕捕获（远控）

```rust
trait ScreenCapturer {
    fn start(&mut self) -> Result<()>;
    fn capture_frame(&mut self) -> Result<Frame>;   // 编码后帧（H.264/H.265/VP8-9）
    fn set_quality(&mut self, q: Quality);          // LAN 高画质 / 弱网降码率
    fn stop(&mut self) -> Result<()>;
}
```
- Windows：DXGI Desktop Duplication
- macOS：ScreenCaptureKit
- Linux：PipeWire（Wayland）/ X11 XShm（Xorg）

## 4. 输入注入（远控）

```rust
trait InputInjector {
    fn inject_mouse(&self, e: MouseEvent) -> Result<()>;
    fn inject_keyboard(&self, e: KeyEvent) -> Result<()>;
    fn send_sas(&self) -> Result<()>;   // Windows Ctrl+Alt+Del（安全桌面）
}
```
- Windows：`SendInput`；macOS：`CGEvent`；Linux：`uinput` / `xdotool`。

## 5. 安装执行（软件分发）

```rust
trait InstallExecutor {
    fn install(&self, pkg: &Package, args: &str) -> Result<InstallOutcome>; // 静默
    fn uninstall(&self, pkg: &Package) -> Result<InstallOutcome>;
}
```
| 平台 | 静默命令 |
|---|---|
| Windows | `msiexec /quiet`、`NSIS /S`、`InnoSetup /VERYSILENT` |
| macOS | `installer -pkg -target /`；拖拽型 `cp` + 授权 |
| Linux | `dpkg -i` / `rpm -i`（静默 `-y`） |

- 退出码映射为标准 `exit_code`；失败自动重试（由中枢任务编排控制）。

## 6. 合规与自我保护

- 屏幕/录像默认关闭；远端弹提示由中枢指令触发。
- `ServiceManager::uninstall` / `self_check` 落实铁律 4（防卸载/防篡改）。
- 采集最小必要（铁律 5）。

## 7. 平台适配清单（须专项验证）

- [ ] Windows：服务权限、DXGI、SendInput、SAS 驱动
- [ ] macOS：开发者签名、PPPC 授权、ScreenCaptureKit 权限
- [ ] Linux：systemd 权限、PipeWire（Wayland）权限、uinput 权限
