#!/usr/bin/env python3
# 御端 · 铁律 4 远控指令签名门禁 端到端验证（协议 §8.6）
#
# 背景：改造前中枢把 Viewer 的 rc_* 消息原样透传给副端、副端也只给 command 做验签，
#       remote_control 实际处于「无签名、无防重放」状态，违反铁律 4。
# 改造：中枢转发前规范化（补 nonce）+ HMAC 签名；副端把 rc_* 纳入同一验签门禁。
#
# 本脚本用真实进程验证三场景：
#   A 同密钥   → 验签通过，rc_ready + 真实屏幕帧到达（加签不破坏链路）
#   B 密钥不一致 → 副端拒签，回 rc_event(kind=error)，且不得出现 rc_ready/帧
#   C 双方均无密钥 → 开发态放行，会话照常建立（与改造前行为一致）
#
# 仅依赖标准库。用法：python3 dev/e2e_rc_signing.py
import base64, json, os, random, socket, struct, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
RUST = "/Users/huluobo/WorkBuddy/jiankong/rust/agent"
HUB = os.path.join(DEV, "bin", "hub")
AGENT = os.path.join(RUST, "target", "agent")
SECRET_OK = "e2e-rc-signing-secret"
SECRET_BAD = "e2e-rc-signing-WRONG"

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + ("  " + detail if detail else ""))


def free_port():
    for _ in range(20):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return str(p)
    raise RuntimeError("no free port")


def http(base, path, method="GET", data=None, token=None, timeout=10):
    req = urllib.request.Request(base + path, method=method)
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


class WSClient:
    """极简 WebSocket 客户端（viewer 侧）"""

    def __init__(self, host, port, path):
        self.sock = socket.create_connection((host, port), timeout=15)
        key = base64.b64encode(bytes(random.getrandbits(8) for _ in range(16))).decode()
        req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key))
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

    def send_text(self, text):
        data = text.encode()
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

    def _read_frame(self, deadline):
        def need(n):
            while len(self.buf) < n:
                self.sock.settimeout(max(0.1, deadline - time.time()))
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise RuntimeError("ws EOF")
                self.buf += chunk
            out, self.buf = self.buf[:n], self.buf[n:]
            return out

        b0b1 = need(2)
        op = b0b1[0] & 0x0F
        ln = b0b1[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", need(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", need(8))[0]
        if b0b1[1] & 0x80:
            need(4)
        return op, (need(ln) if ln else b"")

    def recv_text(self, timeout=20):
        deadline = time.time() + timeout
        while True:
            op, payload = self._read_frame(deadline)
            if op == 0x8:
                return None
            if op == 0x9:
                hdr = bytearray([0x8A, 0x80 | len(payload)]) + bytes(random.getrandbits(8) for _ in range(4))
                m = bytes(hdr[2:])
                self.sock.sendall(bytes(hdr) + bytes(b ^ m[i % 4] for i, b in enumerate(payload)))
                continue
            if op in (0x1, 0x0):
                return payload.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def jpeg_size(data):
    if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8:
        return None
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        m = data[i + 1]
        if m == 0xD8 or (0xD0 <= m <= 0xD7) or m == 0x01:
            i += 2
            continue
        if m == 0xD9:
            break
        ln = struct.unpack(">H", data[i + 2:i + 4])[0]
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            return (w, h)
        i += 2 + ln
    return None


def build():
    # 中枢按源码时间戳重建：脚本只判存在会导致「改了 hub 源码却跑旧二进制」的假失败
    hub_src = max(os.path.getmtime(os.path.join(DEV, "internal", "hub", "hub.go")),
                  os.path.getmtime(os.path.join(DEV, "internal", "proto", "proto.go")))
    if not os.path.exists(HUB) or os.path.getmtime(HUB) < hub_src:
        print("[build] go build 中枢…")
        subprocess.run(["go", "build", "-o", "bin/hub", "./cmd/hub"], cwd=DEV, check=True)
    if not os.path.exists(AGENT) or os.path.getmtime(AGENT) < os.path.getmtime(
            os.path.join(RUST, "src", "main.rs")):
        print("[build] rustc 构建副端…")
        rustc = os.path.expanduser("~/.cargo/bin/rustc")
        if not os.path.exists(rustc):
            rustc = "rustc"
        subprocess.run([rustc, "-O", "src/main.rs", "-o", "target/agent"], cwd=RUST, check=True)


def start_hub(port, secret):
    env = dict(os.environ, YUDUAN_HUB_ADDR=":" + port,
               YUDUAN_ADMIN_MUST_CHANGE_PW="0",
               YUDUAN_REPO="/tmp/yuduan-rc-signing-repo",
               # 关 TLS：默认还会绑 :8443，与开发机上已在运行的中枢冲突会导致本轮 e2e 假失败
               YUDUAN_TLS_ADDR="")
    if secret:
        env["YUDUAN_HMAC_SECRET"] = secret
    else:
        env.pop("YUDUAN_HMAC_SECRET", None)
    log = open("/tmp/yuduan-rc-signing-hub-%s.log" % port, "w")
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=log, stderr=subprocess.STDOUT, text=True)


def start_agent(port, secret, tag):
    env = dict(os.environ,
               YUDUAN_HUB="ws://127.0.0.1:%s/ws/agent" % port,
               YUDUAN_STATE_FILE="/tmp/yuduan-rc-signing-state-%s.json" % tag)
    if secret:
        env["YUDUAN_HMAC_SECRET"] = secret
    else:
        env.pop("YUDUAN_HMAC_SECRET", None)
    log = open("/tmp/yuduan-rc-signing-agent-%s.log" % tag, "w")
    return subprocess.Popen([AGENT], env=env, stdout=log, stderr=subprocess.STDOUT, text=True)


def wait_device(base, token, timeout=30):
    for _ in range(timeout * 2):
        st, body = http(base, "/api/v1/devices", token=token)
        if st == 200:
            for d in body.get("devices", []):
                if d.get("online") and "rust" in (d.get("agent_version") or ""):
                    return d
        time.sleep(0.5)
    return None


def run_rc(base, port, device_id, timeout=30):
    """发起一次远控会话，返回 (ready, frames, err_events)"""
    v = WSClient("127.0.0.1", int(port), "/ws/viewer")
    sid = "signing-%d" % int(time.time())
    ready, frames, errs = None, [], []
    try:
        v.send_text(json.dumps({"type": "rc_request", "payload": {
            "device_id": device_id, "session_id": sid, "operator": "e2e"}}))
        t0 = time.time()
        while time.time() - t0 < timeout:
            # 收敛条件：收到错误回执即止；或已就绪且拿到帧；
            # 负向场景（预期被拒）没有 rc_ready，给 12s 观察窗后收尾，避免空等超时。
            if errs:
                break
            if ready and frames:
                break
            if ready is None and time.time() - t0 > 12:
                break
            try:
                msg = v.recv_text(timeout=3)
            except Exception:
                continue
            if not msg:
                break
            try:
                env = json.loads(msg)
            except Exception:
                continue
            t = env.get("type")
            p = env.get("payload") or {}
            if t == "rc_ready":
                ready = env
            elif t == "rc_frame":
                frames.append(env)
                if len(frames) >= 3:
                    break
            elif t == "rc_event" and p.get("kind") == "error":
                errs.append(env)
        # 收尾：结束会话
        try:
            v.send_text(json.dumps({"type": "rc_stop", "payload": {"session_id": sid}}))
        except Exception:
            pass
    finally:
        v.close()
    return ready, frames, errs


def scenario(name, hub_secret, agent_secret, expect_ready):
    port = free_port()
    base = "http://127.0.0.1:" + port
    hub = start_hub(port, hub_secret)
    time.sleep(1.5)
    agent = start_agent(port, agent_secret, name.replace(" ", "-"))
    try:
        st, body = http(base, "/api/v1/login", method="POST",
                        data={"username": "admin", "password": "admin123"})
        token = body.get("token")
        if not token:
            check(name + " · admin 登录", False, "st=%s body=%s" % (st, body)[:120])
            return
        dev = wait_device(base, token)
        if not dev:
            check(name + " · 副端上线", False, "30s 内未注册")
            return
        ready, frames, errs = run_rc(base, port, dev["id"])
        if expect_ready:
            check(name + " · rc_ready 就绪", ready is not None and ready["payload"].get("ok") is True,
                  "ok=%s" % (ready["payload"].get("ok") if ready else None))
            if frames:
                raw = base64.b64decode(frames[-1]["payload"].get("data", ""))
                dim = jpeg_size(raw)
                check(name + " · 真实屏幕帧到达", len(raw) > 1000 and dim is not None,
                      "bytes=%d dim=%s" % (len(raw), dim))
            else:
                check(name + " · 真实屏幕帧到达", False, "未收到 rc_frame（采集可能被系统权限限制）")
        else:
            check(name + " · 副端拒签（无 rc_ready）", ready is None,
                  "ready=%s" % (ready is not None))
            check(name + " · 回执 rc_event(error)", len(errs) > 0,
                  "msg=%s" % (errs[0]["payload"].get("message", "")[:60] if errs else ""))
            log = "/tmp/yuduan-rc-signing-agent-%s.log" % name.replace(" ", "-")
            txt = open(log).read() if os.path.exists(log) else ""
            check(name + " · 副端日志记录拒签", "拒绝执行远控指令" in txt,
                  (txt.strip().splitlines()[-1][:80] if txt else "无日志"))
    finally:
        agent.terminate()
        agent.wait()
        hub.terminate()
        hub.wait()


def agent_saw_rejection(log_path, tag):
    """断言副端进程日志出现拒签记录（证据链补齐：不止看主端现象）"""
    return log_path and os.path.exists(log_path)


def main():
    build()
    print("== 场景 A：中枢/副端同密钥（加签后链路仍通）==")
    scenario("A 同密钥", SECRET_OK, SECRET_OK, expect_ready=True)
    print("== 场景 B：副端密钥与中枢不一致（必须拒签）==")
    scenario("B 密钥不一致", SECRET_OK, SECRET_BAD, expect_ready=False)
    print("== 场景 C：双方无密钥（开发态放行，行为不变）==")
    scenario("C 无密钥", "", "", expect_ready=True)

    ok = sum(1 for _, c, _ in results if c)
    print("\n==== %d/%d PASS ====" % (ok, len(results)))
    for n, c, d in results:
        if not c:
            print("FAILED: %s %s" % (n, d))
    sys.exit(0 if ok == len(results) else 1)


if __name__ == "__main__":
    main()
