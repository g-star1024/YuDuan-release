#!/usr/bin/env python3
# 御端 e2e —— 设备引导（档位 A）：UDP 广播携带一次性注册令牌 + /api/agent/claim
# 换取 HMAC 密钥 +（CA 就绪时）mTLS 客户端证书。模拟副端零手动部署全流程。
# v0.4.8 勘误：v0.2.7 安全止血起 claim 明文端口一律拒绝（4033 claim_requires_tls），
# 本脚本改走 https://127.0.0.1:8443（自签/私有 CA 证书均用不校验上下文——e2e 只验
# 业务载荷，证书链校验由副端真实链路覆盖）。
import json, os, shutil, socket, ssl, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl._create_unverified_context())))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-claim-e2e"
SECRET = "claim-e2e-secret-0123456789abcdef"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18090")
BASE = "http://127.0.0.1:" + PORT
TLS_BASE = "https://127.0.0.1:8443"
try:
    DISCOVERY_PORT = int(os.environ.get("YUDUAN_DISCOVERY_PORT", "18242"))
except (TypeError, ValueError):
    DISCOVERY_PORT = 18242
os.makedirs(BIN, exist_ok=True)

PASS = FAIL = 0
def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print(f"  ✓ {name}")
    else:
        FAIL += 1; print(f"  ✗ {name}  {detail}")

def build():
    for name, pkg in [("hub", "./cmd/hub"), ("ca", "./cmd/ca")]:
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), pkg], cwd=DEV, check=True)
    print("[build] hub + ca 编译完成")

def start_hub(cwd, extra_env=None):
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO=os.path.join(cwd, "repo"),
               YUDUAN_HUB_ADDR=":" + PORT)
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen([os.path.join(BIN, "hub")], cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def discovery_probe(timeout=3.0):
    """UDP 广播探测（模拟副端 discover_hub）：返回解析后的回复行。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"YUDUAN_DISCOVER", ("127.0.0.1", DISCOVERY_PORT))
        data, _ = s.recvfrom(512)
        return data.decode(errors="replace")
    finally:
        s.close()

def parse_field(line, key):
    for tok in line.split():
        if tok.startswith(key + "="):
            return tok[len(key) + 1:]
    return None

def req(path, tls=True):
    # v0.4.8：claim 必须走 TLS 端口（v0.2.7 起 4033 明文拒绝）；tls=False 仅用于
    # 验证「明文端口确实被拒绝」这一安全行为本身。
    base = TLS_BASE if tls else BASE
    r = urllib.request.Request(base + path)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, {"_raw": e.read().decode()[:200]}
    except Exception as e:
        return -1, {"error": str(e)}

def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

def main():
    build()
    print("\n== 场景 1：无 CA（开发态）——广播带令牌 + claim 换密钥 ==")
    s1 = os.path.join(BIN, "scene1")
    shutil.rmtree(s1, ignore_errors=True)
    os.makedirs(s1)
    hub = start_hub(s1); time.sleep(1.5)
    try:
        line = discovery_probe()
        check("广播响应含 ws= 地址", (parse_field(line, "ws") or "").startswith("ws://"))
        check("广播响应含 hostname=", parse_field(line, "hostname") is not None)
        tok = parse_field(line, "token")
        check("广播响应携带一次性注册令牌 token=", bool(tok))
        check("广播不携带 HMAC 密钥（铁律 4）", "hmacSecret=" not in line and "secret" not in line.lower())

        st, b = req(f"/api/agent/claim?token={tok}&device=e2e-dev&hostname=scene1")
        check("claim 有效令牌返回 hmacSecret", st == 200 and b.get("hmacSecret") == SECRET,
              f"got {b}")
        check("claim 返回 hubId", bool(b.get("hubId")))

        st, b2 = req("/api/agent/claim?token=bogus-token")
        check("claim 伪令牌被拒（4003）", b2.get("code") == 4003, f"got {b2}")

        st, b3 = req("/api/agent/claim")
        check("claim 缺令牌被拒（4001）", b3.get("code") == 4001, f"got {b3}")

        # v0.2.7 安全行为回归：明文端口请求 claim 必须 4033 拒绝。
        # 令牌一次性消费（v0.2.7），上一条 claim 已消耗 tok —— 重新广播取新令牌。
        line2 = discovery_probe()
        tok2 = parse_field(line2, "token")
        st, b5 = req(f"/api/agent/claim?token={tok2}&device=e2e-dev&hostname=scene1", tls=False)
        check("明文端口 claim 被拒（4033 claim_requires_tls）", b5.get("code") == 4033, f"got {b5}")

        st, b4 = req(f"/api/agent/claim?token={tok}&device=e2e-dev")
        check("无 CA 时 claim 不含客户端证书", "clientCert" not in b4)
    finally:
        stop(hub)

    print("\n== 场景 2：私有 CA 就绪——claim 额外签发 mTLS 客户端证书 ==")
    s2 = os.path.join(BIN, "scene2")
    shutil.rmtree(s2, ignore_errors=True)
    os.makedirs(s2)
    ca = subprocess.run([os.path.join(BIN, "ca"), "init", "-dir", os.path.join(s2, "certs")],
                        cwd=s2, capture_output=True, text=True)
    check("ca init 成功（根 CA + 服务器证书）",
          ca.returncode == 0 and os.path.exists(os.path.join(s2, "certs", "ca.pem")),
          ca.stderr[-200:] if ca.returncode != 0 else "")
    hub = start_hub(s2); time.sleep(1.5)
    try:
        line = discovery_probe()
        tok = parse_field(line, "token")
        st, b = req(f"/api/agent/claim?token={tok}&device=e2e-mtls&hostname=scene2")
        check("CA 就绪时 claim 返回 caPem", "-----BEGIN CERTIFICATE-----" in b.get("caPem", ""))
        check("CA 就绪时 claim 签发客户端证书", "-----BEGIN CERTIFICATE-----" in b.get("clientCert", ""))
        check("CA 就绪时 claim 签发客户端私钥", "PRIVATE KEY" in b.get("clientKey", ""))
        check("claim 仍返回一致的 hmacSecret", b.get("hmacSecret") == SECRET)
        check("claim 返回 TLS 监听提示地址", bool(b.get("tlsAddr")))
    finally:
        stop(hub)

    print(f"\n结果：PASS={PASS} FAIL={FAIL}")
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
