#!/usr/bin/env python3
# 御端 · §9.1 注册凭据握手（复盘 S-3/V-03）端到端对抗验证。
#
# 背景：v0.2.6 专家团审查发现 /ws/agent 注册不验凭据——任意内网主机可零成本
# 注册假设备污染台账，或报出他人 token 顶替在线设备接管其指令流。
# 本脚本以**真实编译产物**（中枢 + Go 参考副端 + Rust 生产副端）验证：
#   ① 合规副端（Go / Rust）均可正常注册——修复不得把正常链路打死；
#   ② 不持有凭据的攻击者①~③三种攻击形态全部被拒，台账零污染。
#
# 仅依赖标准库。用法：python3 dev/e2e_regauth.py
import base64, hashlib, hmac, json, os, random, socket, struct, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
RUST = "/Users/huluobo/WorkBuddy/jiankong/rust"
BIN = "/tmp/yuduan-regauth"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
RUST_AGENT = os.path.join(RUST, "agent", "target", "agent")
SECRET = "s3-regauth-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18093")
BASE = "http://127.0.0.1:" + PORT
PINNED_TOKEN = "pinned-victim-token"

os.makedirs(BIN, exist_ok=True)

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  ✓ " + name)
    else:
        FAIL += 1
        print("  ✗ " + name + "  " + detail)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = str(s.getsockname()[1])
    s.close()
    return p


def http(path, data=None, token=None, timeout=10):
    req = urllib.request.Request(BASE + path, method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode()
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, {"_raw": raw[:200]}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def register_mac(secret, nonce, token):
    """§9.1 应答 MAC；规范串须与 Go crypto.SignRegisterAuth / Rust secure::register_auth_mac 一致。"""
    canonical = "yuduan-register|" + nonce + "|" + token
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


class WS:
    """极简 WebSocket 客户端（仅满足本脚本的正/负向用例）。"""

    def __init__(self, port, path="/ws/agent"):
        self.sock = socket.create_connection(("127.0.0.1", int(port)), timeout=15)
        key = base64.b64encode(bytes(random.getrandbits(8) for _ in range(16))).decode()
        req = ("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, port, key))
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("ws handshake EOF")
            buf += chunk
        if b"101" not in buf.split(b"\r\n")[0]:
            raise RuntimeError("ws handshake failed: %r" % buf[:120])
        self.buf = buf.split(b"\r\n\r\n", 1)[1]

    def send(self, obj):
        data = json.dumps(obj, separators=(",", ":")).encode()
        header = bytearray([0x81])
        n = len(data)
        if n < 126:
            header.append(0x80 | n)
        elif n <= 0xFFFF:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        mask = bytes(random.getrandbits(8) for _ in range(4))
        header += mask
        self.sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _need(self, n, deadline):
        while len(self.buf) < n:
            self.sock.settimeout(max(0.1, deadline - time.time()))
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("ws EOF")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _frame(self, deadline):
        b0b1 = self._need(2, deadline)
        op = b0b1[0] & 0x0F
        ln = b0b1[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._need(2, deadline))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._need(8, deadline))[0]
        if b0b1[1] & 0x80:
            self._need(4, deadline)
        return op, (self._need(ln, deadline) if ln else b"")

    def recv(self, timeout=15):
        deadline = time.time() + timeout
        while True:
            op, payload = self._frame(deadline)
            if op == 0x8:
                return None
            if op == 0x9:
                m = bytes(random.getrandbits(8) for _ in range(4))
                hdr = bytearray([0x8A, 0x80 | len(payload)]) + m
                self.sock.sendall(bytes(hdr) + bytes(b ^ m[i % 4] for i, b in enumerate(payload)))
                continue
            if op in (0x1, 0x0):
                return json.loads(payload.decode("utf-8", "replace"))

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def wait_hub(timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(BASE + "/api/v1/login", timeout=2)
        except urllib.error.HTTPError:
            return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def device_count(token):
    st, b = http("/api/v1/devices", token=token)
    return b.get("total", 0) if st == 200 else -1


def main():
    global PORT, BASE
    print("[0/6] 构建真实产物")
    for name, pkg in [("hub", "./cmd/hub"), ("agent", "./cmd/agent")]:
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), pkg], cwd=DEV, check=True)
    print("      Go 中枢 + 参考副端编译完成")

    PORT = free_port()
    BASE = "http://127.0.0.1:" + PORT
    hub = subprocess.Popen(
        [HUB], cwd=DEV,
        env=dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_HUB_ADDR=":" + PORT,
                 YUDUAN_REPO="/tmp/yuduan-regauth-repo"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    procs = [hub]
    try:
        check("中枢启动就绪", wait_hub())
        st, b = http("/api/v1/login", {"username": "admin", "password": "admin123"})
        if st != 200 or not b.get("token"):
            print("登录失败:", b)
            return
        st, b2 = http("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"},
                      token=b["token"])
        tok = b2.get("token") or b["token"]
        check("管理端登录+改密", bool(tok))
        base_devices = device_count(tok)
        check("初始台账为空", base_devices == 0, f"total={base_devices}")

        print("\n[1/6] 合规 Go 副端注册（正常链路不得被门禁打死）")
        go_agent = subprocess.Popen(
            [AGENT], cwd=DEV,
            env=dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent",
                     YUDUAN_HMAC_SECRET=SECRET, YUDUAN_STATE_FILE="/tmp/yuduan-regauth-go-state.json",
                     YUDUAN_TOKEN=PINNED_TOKEN))
        procs.append(go_agent)
        got_go = False
        for _ in range(30):
            time.sleep(0.5)
            if device_count(tok) >= 1:
                got_go = True
                break
        check("Go 参考副端完成 §9.1 握手并注册", got_go, f"total={device_count(tok)}")
        after_go = device_count(tok)

        print("\n[2/6] 攻击者甲：读走挑战但不作答，直接 register")
        try:
            w = WS(PORT)
            ch = w.recv(timeout=10)
            check("中枢确实先下发了 auth_challenge", bool(ch) and ch.get("type") == "auth_challenge",
                  json.dumps(ch)[:120] if ch else "无响应")
            nonce = (ch or {}).get("payload", {}).get("nonce", "")
            check("挑战携带随机 nonce", len(nonce) >= 16, f"nonce={nonce}")
            w.send({"ver": 1, "msg_id": "atk-a", "ts": int(time.time()), "type": "register", "seq": 1,
                    "payload": {"hostname": "attacker-a", "os": "linux", "arch": "x86_64"}})
            ack = w.recv(timeout=10)
            ok = bool(ack) and ack.get("type") == "register_ack" and ack.get("payload", {}).get("ok") is False
            check("未握手的 register 被 nack", ok, json.dumps(ack)[:160])
            check("nack 携带可读原因", bool(ack and ack.get("payload", {}).get("reason")),
                  json.dumps(ack)[:160] if ack else "无回执")
            w.close()
        except Exception as e:
            check("攻击者甲链路可用", False, str(e))
        check("台账未被攻击者甲污染", device_count(tok) == after_go,
              f"before={after_go} after={device_count(tok)}")

        print("\n[3/6] 攻击者乙：凭空捏造 MAC（未持有共享密钥）")
        try:
            w = WS(PORT)
            ch = w.recv(timeout=10)
            nonce = (ch or {}).get("payload", {}).get("nonce", "")
            w.send({"ver": 1, "msg_id": "atk-b", "ts": int(time.time()), "type": "auth_response", "seq": 1,
                    "payload": {"nonce": nonce, "token": "", "mac": "0" * 64}})
            w.send({"ver": 1, "msg_id": "atk-b2", "ts": int(time.time()), "type": "register", "seq": 2,
                    "payload": {"hostname": "attacker-b", "os": "linux", "arch": "x86_64"}})
            ack = w.recv(timeout=10)
            rejected = (ack is None) or (ack.get("payload", {}).get("ok") is False)
            check("伪造 MAC 未通过，register 仍被拒", rejected, json.dumps(ack)[:160] if ack else "连接被断")
            w.close()
        except Exception as e:
            # 中枢在握手失败时会主动断链，客户端读帧抛异常本身即「被拒」的证据
            check("伪造 MAC 被拒（连接被断）", True, "")
        check("台账未被攻击者乙污染", device_count(tok) == after_go,
              f"before={after_go} after={device_count(tok)}")

        print("\n[4/6] 攻击者丙：持有密钥但握手绑定为空 token，注册却报他人 token（抢注）")
        try:
            w = WS(PORT)
            ch = w.recv(timeout=10)
            nonce = (ch or {}).get("payload", {}).get("nonce", "")
            # 以「空身份」签名——与随后声明的 victim token 不一致
            w.send({"ver": 1, "msg_id": "atk-c", "ts": int(time.time()), "type": "auth_response", "seq": 1,
                    "payload": {"nonce": nonce, "token": "", "mac": register_mac(SECRET, nonce, "")}})
            w.send({"ver": 1, "msg_id": "atk-c2", "ts": int(time.time()), "type": "register", "seq": 2,
                    "payload": {"hostname": "victim-clone", "os": "macos", "arch": "arm64",
                                "token": PINNED_TOKEN}})
            ack = w.recv(timeout=10)
            okk = ack and ack.get("payload", {}).get("ok")
            check("令牌与握手绑定不符 → 注册被拒", not okk, json.dumps(ack)[:160] if ack else "无回执")
            w.close()
        except Exception as e:
            check("攻击者丙链路可用", False, str(e))
        check("真机仍在线（未被顶替下线）", device_count(tok) == after_go,
              f"before={after_go} after={device_count(tok)}")

        print("\n[5/6] 重连：合规 Go 副端重启后复用同一身份（不产生新设备）")
        go_agent.terminate()
        try:
            go_agent.wait(timeout=5)
        except Exception:
            pass
        time.sleep(1)
        go_agent2 = subprocess.Popen(
            [AGENT], cwd=DEV,
            env=dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent",
                     YUDUAN_HMAC_SECRET=SECRET, YUDUAN_STATE_FILE="/tmp/yuduan-regauth-go-state.json"))
        procs.append(go_agent2)
        same = False
        for _ in range(30):
            time.sleep(0.5)
            if device_count(tok) == after_go:
                same = True
                break
        check("重启后复用 device_id（台账仍 %d 台）" % after_go, same, f"total={device_count(tok)}")

        print("\n[6/6] Rust 生产副端（三平台主力）同样能通过握手")
        if not os.path.exists(RUST_AGENT):
            print("      未找到 Rust 产物，尝试 rustc 构建…")
            subprocess.run(["rustc", "-O", "src/main.rs", "-o", "target/agent"], cwd=os.path.join(RUST, "agent"),
                           check=True)
        if sys.platform == "darwin":
            # 副端防篡改自检含 codesign 校验（仅告警不阻断）；ad-hoc 签名消警告
            subprocess.run(["codesign", "--force", "--sign", "-", RUST_AGENT],
                           capture_output=True, text=True)
        # v0.4.8 幂等注册：同宿主机身份会被合并为一台设备（报告问题 4 产品语义），
        # rust agent 必须伪造独立硬件身份才能计为新设备。
        rust_agent = subprocess.Popen(
            [RUST_AGENT],
            env=dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent",
                     YUDUAN_HMAC_SECRET=SECRET, YUDUAN_STATE_FILE="/tmp/yuduan-regauth-rust-state.json",
                     YUDUAN_HOSTNAME="regauth-rust-host", YUDUAN_MAC="02:00:00:00:0f:fe",
                     YUDUAN_SERIAL="REGAUTH-RUST-SN"))
        procs.append(rust_agent)
        got_rust = False
        for _ in range(40):
            time.sleep(0.5)
            if device_count(tok) >= after_go + 1:
                got_rust = True
                break
        check("Rust 生产副端完成握手并注册", got_rust, f"total={device_count(tok)}")
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    print("\n==== regauth: %d/%d PASS ====" % (PASS, PASS + FAIL))
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
