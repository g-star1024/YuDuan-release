#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T-4 安全段端到端验收：主端全链路 TLS（铁律 4）+ 私有 CA / SPKI pin / mTLS。

场景（全部对真实 Go 中枢跑）：
  A. 私有 CA 校验：YUDUAN_TLS_CAFILE=ca.pem → hubcheck over https 全通过
  B. SPKI pin：YUDUAN_TLS_PIN=<pin>（不给 CA）→ 全通过（RFC 7469 固定）
  C. 错 pin：YUDUAN_TLS_PIN=<wrong> → 必须拒绝连接（防内网伪造中枢）
  D. mTLS：带客户端证书访问 mTLS 端口 → 握手成功
  E. mTLS：不带客户端证书访问 mTLS 端口 → 被要求证书而失败
  F. 远控信令走 wss：p2pcheck over https base（P2P 直连 + 原生解码）全通过

用法：python3 dev/e2e_tauri_tls.py
"""
import os
import re
import socket
import subprocess
import sys
import time

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
MAIN = "/Users/huluobo/WorkBuddy/jiankong/main/src-tauri"
RUST = "/Users/huluobo/WorkBuddy/jiankong/rust/agent"
HUB = os.path.join(DEV, "bin", "hub")
CA = os.path.join(DEV, "bin", "ca")
AGENT = os.path.join(RUST, "target", "agent")
ENC_LIB = "/Users/huluobo/WorkBuddy/jiankong/dev/encoder-vt/libyuduan_enc_vt.dylib"
DEC_LIB = "/tmp/libyuduan_dec_vt.dylib"
CERTS = "/tmp/yd-tls-certs"
SECRET = "e2e-secret-tauri-tls"
NEW_PW = "YuDuan@TLS#2026"

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


def main():
    # 0) 构建
    subprocess.run(["go", "build", "-o", "bin/ca", "./cmd/ca"], cwd=DEV, check=True)
    if not os.path.exists(DEC_LIB):
        subprocess.run(["bash", "build.sh", DEC_LIB],
                       cwd="/Users/huluobo/WorkBuddy/jiankong/main/decoder-vt", check=True)
    subprocess.run(["cargo", "build", "--bins"], cwd=MAIN, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if not os.path.exists(AGENT):
        subprocess.run(["rustc", "-O", "src/main.rs", "-o", "target/agent"], cwd=RUST, check=True)

    # 1) 私有 CA
    if os.path.exists(CERTS):
        subprocess.run(["rm", "-rf", CERTS], check=True)
    out = subprocess.run([CA, "init", "-dir", CERTS, "-ip", "127.0.0.1"],
                         capture_output=True, text=True, check=True).stdout
    m = re.search(r"YUDUAN_TLS_PIN=([0-9a-fA-F]{64})", out)
    pin = m.group(1) if m else ""
    check("私有 CA 建立并输出 SPKI pin", bool(pin), f"pin={pin[:16]}…")
    if not pin:
        return 1
    # 主端 mTLS 客户端证书（CN = 主端标识，供中枢审计对账）
    # -rsa：macOS 原生 TLS 栈（Security.framework / native-tls）无法导入 SEC1 的 EC 私钥，
    #       主端客户端证书用 RSA（PKCS#8）；副端走 openssl 不受影响，仍用默认 EC。
    subprocess.run([CA, "issue-client", "-dir", CERTS, "-cn", "main-console", "-rsa",
                    "-out", os.path.join(CERTS, "client")], check=True, capture_output=True)
    client_cert = os.path.join(CERTS, "client.pem")
    client_key = os.path.join(CERTS, "client.key")
    check("主端 mTLS 客户端证书签发", os.path.exists(client_cert) and os.path.exists(client_key))

    plain_port, tls_port, mtls_port = free_port(), free_port(), free_port()
    hub = subprocess.Popen(
        [HUB], cwd=DEV,
        env=dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_HUB_ADDR=":" + str(plain_port),
                 YUDUAN_TLS_ADDR=":" + str(tls_port),
                 YUDUAN_TLS_CERT=os.path.join(CERTS, "cert.pem"),
                 YUDUAN_TLS_KEY=os.path.join(CERTS, "key.pem"),
                 YUDUAN_CA_CERT=os.path.join(CERTS, "ca.pem"),
                 YUDUAN_CA_KEY=os.path.join(CERTS, "ca.key"),
                 YUDUAN_CLIENT_CA=os.path.join(CERTS, "ca.pem"),
                 YUDUAN_MTLS_ADDR=":" + str(mtls_port),
                 YUDUAN_REPO="/tmp/yuduan-tauri-tls-repo"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(2.0)

    def run_main(bin_name, args, env_extra=None):
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        p = subprocess.run(["cargo", "run", "-q", "--bin", bin_name, "--"] + args,
                           cwd=MAIN, env=env, capture_output=True, text=True, timeout=300)
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    # A. 私有 CA 校验
    rc, out = run_main("hubcheck", [f"https://127.0.0.1:{tls_port}", "admin", "admin123", NEW_PW],
                       {"YUDUAN_TLS_CAFILE": os.path.join(CERTS, "ca.pem")})
    print(out[-1200:])
    check("A 私有 CA 校验：https 登录/改密/设备列表", rc == 0, f"rc={rc}")

    # B. SPKI pin（不给 CA）
    rc, out = run_main("hubcheck", [f"https://127.0.0.1:{tls_port}", "admin", NEW_PW],
                       {"YUDUAN_TLS_PIN": pin})
    print(out[-900:])
    check("B SPKI pin 固定：https 全通过（无 CA）", rc == 0, f"rc={rc}")

    # C. 错 pin 必须拒绝
    bad = ("0" if pin[0] != "0" else "1") + pin[1:]
    rc, out = run_main("hubcheck", [f"https://127.0.0.1:{tls_port}", "admin", NEW_PW],
                       {"YUDUAN_TLS_PIN": bad})
    check("C 错误 pin 拒绝连接", rc != 0, f"rc={rc}")
    check("C 错误信息为证书固定校验失败", "SPKI 固定校验失败" in out, (out.strip()[-160:]))

    # D/E. mTLS 端口
    rc, out = run_main("tlscheck", [f"https://127.0.0.1:{mtls_port}/api/v1/devices"],
                       {"YUDUAN_TLS_CAFILE": os.path.join(CERTS, "ca.pem"),
                        "YUDUAN_CLIENT_CERT": client_cert,
                        "YUDUAN_CLIENT_KEY": client_key})
    # mTLS 端口仅放行 /ws/agent：有响应即握手成功（业务码非 2xx 属预期）
    check("D mTLS 带客户端证书握手成功", rc == 0 and "TLS 握手成功" in out, (out.strip()[-160:]))

    rc, out = run_main("tlscheck", [f"https://127.0.0.1:{mtls_port}/api/v1/devices"],
                       {"YUDUAN_TLS_CAFILE": os.path.join(CERTS, "ca.pem")})
    check("E mTLS 无客户端证书被拒", rc != 0, f"rc={rc} {(out.strip()[-120:])}")

    # F. 远控信令走 wss（P2P 直连 + 原生解码）
    agent = subprocess.Popen(
        [AGENT], env=dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{plain_port}/ws/agent",
                          YUDUAN_HMAC_SECRET=SECRET, YUDUAN_ENCODER_LIB=ENC_LIB,
                          YUDUAN_STATE_FILE="/tmp/yuduan-tauri-tls-state.json"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    devid = None
    import json as _json
    import urllib.request as _ur
    try:
        req = _ur.Request(f"http://127.0.0.1:{plain_port}/api/v1/login", method="POST",
                          data=_json.dumps({"username": "admin", "password": NEW_PW}).encode(),
                          headers={"Content-Type": "application/json"})
        with _ur.urlopen(req, timeout=10) as r:
            token = _json.loads(r.read().decode()).get("token")
        for _ in range(60):
            req = _ur.Request(f"http://127.0.0.1:{plain_port}/api/v1/devices",
                              headers={"Authorization": "Bearer " + token})
            with _ur.urlopen(req, timeout=10) as r:
                body = _json.loads(r.read().decode())
            for d in body.get("devices", []):
                if d.get("online") and "rust" in (d.get("agent_version") or ""):
                    devid = d["id"]
                    break
            if devid:
                break
            time.sleep(0.5)
    except Exception as e:
        print("[warn] 设备等待异常:", e)

    check("F 前置：Rust 副端注册", devid is not None, f"device={devid}")
    if devid:
        rc, out = run_main("p2pcheck", [f"https://127.0.0.1:{tls_port}", devid, "8", "p2p"],
                           {"YUDUAN_DECODER_LIB": DEC_LIB,
                            "YUDUAN_TLS_CAFILE": os.path.join(CERTS, "ca.pem"),
                            "YUDUAN_P2P_BIND": "0.0.0.0:0"})
        print(out[-1600:])
        check("F 远控信令走 wss：P2P 直连 + 原生解码", rc == 0 and "ALL PASS" in out, f"rc={rc}")

    agent.terminate()
    hub.terminate()

    ok = sum(1 for _, c, _ in results if c)
    print(f"\n==== {ok}/{len(results)} PASS ====")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
