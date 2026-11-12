#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T-3 端到端验收：主端 Tauri core 的 P2P 直连媒体路径（§8.3）。

覆盖链路：
  真实 Go 中枢 + Rust 副端（真实屏幕采集 + VideoToolbox 编码）
    → 主端 p2pcheck（TCP 监听 + ICE-lite 候选广播）
    → 副端 dial 直连 → 4B 长度前缀 + 24B 帧头
    → 主端 VideoToolbox 解码 → RGBA（尺寸/非纯色校验）

同时回归 T-2 relay 路径（mediacheck），确认 P2P 改动未破坏既有中继链路。

用法：python3 dev/e2e_tauri_p2p.py
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
RUST = "/Users/huluobo/WorkBuddy/jiankong/rust/agent"
MAIN = "/Users/huluobo/WorkBuddy/jiankong/main/src-tauri"
HUB = os.path.join(DEV, "bin", "hub")
AGENT = os.path.join(RUST, "target", "agent")
ENC_LIB = "/Users/huluobo/WorkBuddy/jiankong/dev/encoder-vt/libyuduan_enc_vt.dylib"
DEC_LIB = "/tmp/libyuduan_dec_vt.dylib"
SECRET = "e2e-secret-tauri-p2p"
NEW_PW = "YuDuan@Tauri#2026"

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (("  " + detail) if detail else ""))
    return bool(cond)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


PORT = str(free_port())
BASE = f"http://127.0.0.1:{PORT}"


def http_json(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode()
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or "{}"
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def build_agent():
    if not os.path.exists(AGENT):
        print("[build] rustc 构建 Rust 副端…")
        subprocess.run(["rustc", "-O", "src/main.rs", "-o", "target/agent"], cwd=RUST, check=True)


def build_main():
    print("[build] cargo 构建主端验收二进制…")
    subprocess.run(["cargo", "build", "--bins"], cwd=MAIN, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def build_decoder():
    if not os.path.exists(DEC_LIB):
        print("[build] clang 构建 VT 解码器…")
        subprocess.run(["bash", "build.sh", DEC_LIB],
                       cwd="/Users/huluobo/WorkBuddy/jiankong/main/decoder-vt", check=True)


def wait_device(token, timeout=30):
    for _ in range(timeout * 2):
        st, body = http_json("GET", "/api/v1/devices", token=token)
        if st == 200:
            for d in body.get("devices", []):
                if d.get("online") and "rust" in (d.get("agent_version") or ""):
                    return d
        time.sleep(0.5)
    return None


def main():
    build_agent()
    build_main()
    build_decoder()

    hub = subprocess.Popen(
        [HUB], cwd=DEV,
        env=dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_HUB_ADDR=":" + PORT,
                 YUDUAN_REPO="/tmp/yuduan-tauri-p2p-repo"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)

    st, body = http_json("POST", "/api/v1/login", {"username": "admin", "password": "admin123"})
    token = body.get("token")
    check("admin 登录", st == 200 and body.get("role") == "admin", f"role={body.get('role')}")
    st, body = http_json("POST", "/api/v1/password",
                         {"old_password": "admin123", "new_password": NEW_PW}, token=token)
    token = body.get("token") or token
    check("admin 改密换令牌", st == 200 and bool(body.get("token")))

    agent = subprocess.Popen(
        [AGENT], env=dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent",
                          YUDUAN_HMAC_SECRET=SECRET, YUDUAN_ENCODER_LIB=ENC_LIB,
                          YUDUAN_STATE_FILE="/tmp/yuduan-tauri-p2p-state.json"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    dev = wait_device(token)
    check("Rust 副端注册（带 VT 编码器）", dev is not None, f"device={dev['id'] if dev else None}")
    if not dev:
        agent.terminate(); hub.terminate()
        return 1
    devid = dev["id"]

    # —— 1) P2P 直连 + 原生码流解码 ——
    print("\n=== p2pcheck（P2P 直连 + VT 解码）===")
    env = dict(os.environ, YUDUAN_DECODER_LIB=DEC_LIB, YUDUAN_P2P_BIND="0.0.0.0:0")
    p = subprocess.run(["cargo", "run", "-q", "--bin", "p2pcheck", "--", BASE, devid, "10", "p2p"],
                       cwd=MAIN, env=env, capture_output=True, text=True, timeout=300)
    out = (p.stdout or "") + (p.stderr or "")
    print(out[-4000:])
    check("p2pcheck 退出码 0", p.returncode == 0, f"rc={p.returncode}")
    check("P2P 直连建立", "被控端已直连" in out)
    check("P2P 首帧到达", "P2P 首帧" in out)
    check("原生解码器就绪", "原生解码器就绪" in out)
    check("原生码流解码成功（真实出图）", "原生解码成功=" in out and
          int((out.split("原生解码成功=")[1].split()[0] or "0")) >= 1)

    # —— 2) relay 回归（T-2 不被破坏）——
    print("\n=== mediacheck（relay 回归）===")
    p2 = subprocess.run(["cargo", "run", "-q", "--bin", "mediacheck", "--", BASE, devid, "6"],
                        cwd=MAIN, capture_output=True, text=True, timeout=300)
    out2 = (p2.stdout or "") + (p2.stderr or "")
    print(out2[-2500:])
    check("mediacheck relay 回归通过", p2.returncode == 0, f"rc={p2.returncode}")

    agent.terminate(); agent.wait(timeout=10)
    hub.terminate(); hub.wait(timeout=10)

    ok = sum(1 for _, c, _ in results if c)
    print(f"\n==== {ok}/{len(results)} PASS ====")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
