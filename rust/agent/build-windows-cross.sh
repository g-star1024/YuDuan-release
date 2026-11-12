#!/bin/bash
# 御端 Rust 生产副端 macOS→Windows 交叉编译（固化版 v2）
#
# ⚠️ 根因修正（2026-10-25 22:40，Windows 侧二次实机核实）：
#   上一版把栈溢出归因于「rustc 1.98.1 旧工具链」，该结论**已被证伪**。
#   证据：升级到 1.99.1（58cf8f9c）后重新交叉编译的产物，
#   内嵌 rustc commit 与本机原生构建**完全一致**，在 Windows 上**依然**
#   启动即 STATUS_STACK_OVERFLOW(0xC00000FD)，且零输出。
#
#   真正的根因是**交叉编译链本身**（rust-lld + mingw-w64 CRT + libgcc unwinder），
#   而非 rustc 版本。崩溃产物与正常产物的结构差异是决定性的：
#
#     产物            section  .tls  TLS回调  __mingw  _Unwind_  addr2line/gimli
#     交叉编译(崩)      6       有      2       17       17        有
#     原生 MSVC(正常)    5       无      0        0        0        无
#
#   结论：**不要用本脚本产出 Windows 发布包**。
#   正确做法 = 在真实 Windows 主机用 MSVC 工具链原生构建：
#     rustc -O src/main.rs -o yuduan-agent.exe
#   若必须交叉编译，产物交付前**必须**在真实 Windows 上冒烟通过（本脚本末尾
#   已加入结构校验闸门，可提前拦截已知坏产物结构）。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CARGO="$HOME/.cargo/bin/cargo"
MWROOT="$HOME/mingw-brew/mingw-w64/14.0.0_3"   # 清华镜像 bottle 解包（见脚本尾部注释）
TARGET="x86_64-pc-windows-gnu"

# —— 断言 1：必须用 rustup 的 cargo/rustc（Homebrew rustc 无 windows-gnu std）——
[ -x "$CARGO" ] || { echo "FATAL: $CARGO 不存在（需要 rustup）" >&2; exit 1; }
RUSTC="$HOME/.cargo/bin/rustc"

# —— 断言 2：rustc minor ≥ 99（保持向好；但注意：版本断言**不能**防住栈溢出，
#    1.99.1 交叉产物同样崩溃。真正的闸门在文件末尾的结构校验）——
REL="$("$RUSTC" -vV | awk '/^release:/ {print $2}')"
MINOR="${REL#*.}"; MINOR="${MINOR%%.*}"
[ "$MINOR" -ge 99 ] || { echo "FATAL: rustc $REL 过旧，请 rustup update stable" >&2; exit 1; }
HASH="$("$RUSTC" -vV | awk '/^commit-hash:/ {print $2}')"

# —— 断言 3：mingw bottle 就位 ——
[ -d "$MWROOT/toolchain-x86_64/x86_64-w64-mingw32/lib" ] || {
  echo "FATAL: 缺 mingw-w64 bottle。获取方式：" >&2
  echo "  curl -sL -o /tmp/mingw.bottle.tar.gz https://mirrors.tuna.tsinghua.edu.cn/homebrew-bottles/mingw-w64-14.0.0_3.sonoma.bottle.tar.gz" >&2
  echo "  mkdir -p ~/mingw-brew && tar -xzf /tmp/mingw.bottle.tar.gz -C ~/mingw-brew" >&2
  exit 1
}
CRT="$HOME/.rustup/toolchains/stable-x86_64-apple-darwin/lib/rustlib/$TARGET/lib/self-contained/crt2.o"

echo "==> rustc $REL ($HASH)"
PATH="$HOME/.cargo/bin:$PATH" RUSTC="$RUSTC" \
RUSTFLAGS="-L native=$MWROOT/toolchain-x86_64/x86_64-w64-mingw32/lib \
 -L native=$MWROOT/toolchain-x86_64/lib/gcc/x86_64-w64-mingw32/16.2.0 \
 -C link-arg=$CRT" \
"$CARGO" build --release --manifest-path "$REPO_ROOT/rust/agent/Cargo.toml" \
  --target "$TARGET" --config "target.$TARGET.linker=\"rust-lld\""

EXE="$REPO_ROOT/rust/agent/target/$TARGET/release/yuduan-agent.exe"

# —— 校验 A：内嵌 rustc commit 必须与当前工具链一致（防止缓存里混入旧工具链产物）——
if ! python3 - "$EXE" "$HASH" << 'EOF'
import re, sys
data = open(sys.argv[1], "rb").read()
m = sorted(set(re.findall(rb"/rustc/([0-9a-f]{40})", data)))
sys.exit(0 if m == [sys.argv[2].encode()] else 1)
EOF
then
  echo "FATAL: 产物内嵌 rustc commit 与当前工具链不一致（cargo 增量缓存混入了旧产物），请 cargo clean 后重跑" >&2
  exit 1
fi

# —— 校验 B（关键闸门）：产物结构特征校验，识别已知会在 Windows 启动即崩的产物 ——
# 已知坏产物的判据（全部同时成立）：
#   1) 含 .tls 段且有 TLS 回调（mingw CRT 注入）
#   2) 含 __mingw / _Unwind_ 符号（mingw CRT + libgcc 展开器）
#   3) 含 addr2line / gimli / catch_unwind（gimli 展开器被编入）
# 正常（原生 MSVC）产物：无 .tls 段、无 TLS 回调、无上述符号。
if ! python3 - "$EXE" << 'EOF'
import re, struct, sys
path = sys.argv[1]
data = open(path, "rb").read()

def has(p): return len(re.findall(re.escape(p), data)) > 0

# 解析 PE 找 .tls 段与 TLS 回调数
e = struct.unpack_from("<I", data, 0x3c)[0]
nsec = struct.unpack_from("<H", data, e + 6)[0]
optsz = struct.unpack_from("<H", data, e + 20)[0]
opt = e + 24
magic = struct.unpack_from("<H", data, opt)[0]
pe32p = (magic == 0x20b)
ddoff = opt + (112 if pe32p else 96)
imagebase = struct.unpack_from("<Q", data, opt + 24)[0] if pe32p else struct.unpack_from("<I", data, opt + 28)[0]
sec_off = e + 24 + optsz
secs = []
for i in range(nsec):
    o = sec_off + i * 40
    nm = data[o:o + 8].rstrip(b"\x00").decode(errors="replace")
    vsz, va, rsz, ptr = struct.unpack_from("<IIII", data, o + 8)
    secs.append((nm, va, vsz, ptr, rsz))

def r2o(rva):
    for nm, va, vsz, ptr, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ptr + (rva - va)
    return None

has_tls_sec = any(nm == ".tls" for nm, *_ in secs)
ncb = 0
tls_rva, _ = struct.unpack_from("<II", data, ddoff + 72)
if tls_rva:
    o = r2o(tls_rva)
    if o is not None:
        cb = struct.unpack_from("<QQQQII", data, o)[3]
        if cb > imagebase:
            co = r2o(cb - imagebase)
            if co is not None:
                while struct.unpack_from("<Q", data, co + ncb * 8)[0]:
                    ncb += 1

mingw = has(b"__mingw") or has(b"_tls_init")
unwind = has(b"_Unwind_")
gimli = has(b"addr2line") or has(b"gimli") or has(b"catch_unwind")

if has_tls_sec and ncb > 0 and mingw and (unwind or gimli):
    print("STRUCT: FAIL —— 产物命中已知 Windows 启动崩溃特征：", file=sys.stderr)
    print(f"  .tls 段={has_tls_sec}  TLS回调={ncb}  mingw符号={mingw}  "
          f"_Unwind_={unwind}  gimli={gimli}", file=sys.stderr)
    sys.exit(1)

print(f"STRUCT: PASS —— .tls段={has_tls_sec} TLS回调={ncb} mingw符号={mingw} "
      f"_Unwind_={unwind} gimli={gimli}", file=sys.stderr)
EOF
then
  cat >&2 << 'MSG'
FATAL: 产物结构命中「Windows 启动即 STATUS_STACK_OVERFLOW」已知特征。
  根因：rust-lld + mingw-w64 CRT + libgcc/gimli 展开器的交叉编译链
        （与 rustc 版本无关 —— 1.98.1 与 1.99.1 交叉产物均崩）。
  处置：不要交付该产物。改用真实 Windows 主机原生构建：
        rustc -O src/main.rs -o yuduan-agent.exe
  详见 dev/verify-windows-report-20261025.md（根因修正版）。
MSG
  exit 1
fi

echo "==> OK $EXE"
echo "    sha256  $(shasum -a 256 "$EXE" | awk '{print $1}')"
echo "    工具链  rustc $REL ($HASH)"
echo "    ⚠️  结构校验通过**不等于**运行正常。本机无法冒烟 Windows PE："
echo "       交付前必须在真实 Windows 上运行一次，确认能打印"
echo "       「[agent] 御端 Rust 副端启动」再交付（发布纪律，见报告）。"
