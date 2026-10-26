#!/usr/bin/env python3
# 御端 Rust 生产副端 端到端验证脚本（仅依赖标准库）。
# 覆盖：ws 注册 / HMAC 签名指令互通 / 错误密钥拒签 / sw_install 下载+解包 / wss(TLS) / M4 远控(rc_ready→rc_frame→rc_stop)。
# 前置：dev 侧 Go 中枢已构建（go build -o bin/hub ./cmd/hub）；Rust 副端二进制缺失时自动 rustc 构建。
import base64, json, os, random, socket, ssl, struct, subprocess, sys, time, urllib.request, urllib.error, zipfile

# 本机 HTTP_PROXY 指向 127.0.0.1 代理，urllib 会把 127.0.0.1 也走代理导致 502；端到端测试必须直连。
urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
RUST = "/Users/huluobo/WorkBuddy/jiankong/rust/agent"
HUB = os.path.join(DEV, "bin", "hub")
AGENT = os.path.join(RUST, "target", "agent")
SECRET = "e2e-secret"
# 端口可通过环境变量绕开（本机 8080 常被 Docker Desktop 占用，硬编码会让整轮 e2e 假失败）。
PORT = os.environ.get("YUDUAN_E2E_PORT", "8080")
BASE = "http://127.0.0.1:" + PORT
NEW_PW = "Admin@2026x"

os.makedirs(os.path.join(DEV, "certs"), exist_ok=True)

def http_get(path, token=None, base=BASE):
    req = urllib.request.Request(base + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            raw = r.read().decode()
            try: return r.status, json.loads(raw)
            except Exception: return r.status, {"_raw": raw[:200]}
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}

def http_post(path, data, token=None, base=BASE):
    req = urllib.request.Request(base + path, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=130) as r:
            raw = r.read().decode()
            try: return r.status, json.loads(raw)
            except Exception: return r.status, {"_raw": raw[:200]}
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}

def http_upload(path, file_path, fields, token):
    """multipart 上传（urllib 手写 boundary）"""
    boundary = "----yuduan-e2e-%d" % random.getrandbits(48)
    body = b""
    for k, v in fields.items():
        body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (boundary, k, v)).encode()
    fname = os.path.basename(file_path)
    with open(file_path, "rb") as f:
        body += ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                 "Content-Type: application/octet-stream\r\n\r\n" % (boundary, fname)).encode()
        body += f.read()
    body += ("\r\n--%s--\r\n" % boundary).encode()
    req = urllib.request.Request(BASE + path, data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary,
                                          "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {}

# ===================== 极简 WebSocket 客户端（viewer 用） =====================

class WSClient:
    def __init__(self, host, port, path, tls=False):
        self.sock = socket.create_connection((host, port), timeout=15)
        if tls:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname=host)
        key = base64.b64encode(bytes(random.getrandbits(8) for _ in range(16))).decode()
        req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key))
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk: raise RuntimeError("ws handshake EOF")
            buf += chunk
        if b"101" not in buf.split(b"\r\n")[0]:
            raise RuntimeError("ws handshake failed: %r" % buf[:120])
        self.buf = buf.split(b"\r\n\r\n", 1)[1]

    def send_text(self, text):
        data = text.encode()
        header = bytearray([0x81])
        n = len(data)
        if n < 126: header.append(0x80 | n)
        elif n <= 0xffff: header.append(0x80 | 126); header += struct.pack(">H", n)
        else: header.append(0x80 | 127); header += struct.pack(">Q", n)
        mask = bytes(random.getrandbits(8) for _ in range(4))
        header += mask
        self.sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv_text(self, timeout=20):
        """读一个文本帧（处理 ping/close；不处理分片，控制面消息均单帧）"""
        deadline = time.time() + timeout
        while True:
            frame = self._read_frame(deadline)
            if frame is None: return None
            op, payload = frame
            if op == 0x8: return None
            if op == 0x9:
                # pong
                hdr = bytearray([0x8A, 0x80 | len(payload)]) + bytes(random.getrandbits(8) for _ in range(4))
                m = bytes(hdr[2:])
                self.sock.sendall(bytes(hdr) + bytes(b ^ m[i % 4] for i, b in enumerate(payload)))
                continue
            if op in (0x1, 0x0): return payload.decode("utf-8", "replace")

    def _read_frame(self, deadline):
        def need(n):
            while len(self.buf) < n:
                self.sock.settimeout(max(0.1, deadline - time.time()))
                chunk = self.sock.recv(65536)
                if not chunk: raise RuntimeError("ws EOF")
                self.buf += chunk
            out, self.buf = self.buf[:n], self.buf[n:]
            return out
        b0b1 = need(2)
        op = b0b1[0] & 0x0F
        ln = b0b1[1] & 0x7F
        if ln == 126: ln = struct.unpack(">H", need(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", need(8))[0]
        if b0b1[1] & 0x80: need(4)  # 服务端不应掩码，防御性丢弃
        return op, need(ln) if ln else b""

    def close(self):
        try: self.sock.close()
        except Exception: pass

def jpeg_size(data):
    """解析 JPEG SOF 尺寸（与 Rust 副端 jpeg_size 同逻辑）"""
    if len(data) < 4 or data[0] != 0xFF or data[1] != 0xD8: return None
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF: i += 1; continue
        m = data[i+1]
        if m == 0xD8 or (0xD0 <= m <= 0xD7) or m == 0x01: i += 2; continue
        if m == 0xD9: break
        ln = struct.unpack(">H", data[i+2:i+4])[0]
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", data[i+5:i+9])
            return (w, h)
        i += 2 + ln
    return None

results = []
def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(("PASS " if cond else "FAIL ") + name + ("  " + detail if detail else ""))

def build_rust():
    if not os.path.exists(AGENT):
        print("[build] rustc 构建副端…")
        subprocess.run(["rustc", "-O", "src/main.rs", "-o", "target/agent"], cwd=RUST, check=True)

def start_hub():
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-rust-e2e-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent(hub_url, secret=SECRET):
    env = dict(os.environ, YUDUAN_HUB=hub_url, YUDUAN_HMAC_SECRET=secret)
    return subprocess.Popen([AGENT], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def wait_rust_device(token, timeout=25):
    """等待 agent_version 含 rust 的设备上线"""
    for _ in range(timeout * 2):
        st, body = http_get("/api/v1/devices", token=token)
        if st == 200:
            for d in body.get("devices", []):
                if d.get("online") and "rust" in (d.get("agent_version") or ""):
                    return d
        time.sleep(0.5)
    return None

# ===================== 主流程 =====================
build_rust()
hub = start_hub()
time.sleep(1.5)

# 1) admin 登录 + 强制改密（与 e2e_m6 同一流程，拿到干净令牌）
st, body = http_post("/api/v1/login", {"username": "admin", "password": "admin123"})
TOKEN = body.get("token")
check("admin 登录", st == 200 and body.get("role") == "admin", f"role={body.get('role')}")
st, body = http_post("/api/v1/password", {"old_password": "admin123", "new_password": NEW_PW}, token=TOKEN)
TOKEN = body.get("token") or TOKEN
check("admin 改密换令牌", st == 200 and bool(body.get("token")))

# 2) ws 明文 + HMAC 互通：注册 → shell 指令
agent = start_agent(f"ws://127.0.0.1:{PORT}/ws/agent")
dev = wait_rust_device(TOKEN)
check("Rust 副端(ws)注册成功", dev is not None, f"device={dev['id'] if dev else None}")
DEVID = dev["id"] if dev else None

if DEVID:
    st, b = http_post(f"/api/v1/devices/{DEVID}",
                      {"action": "shell", "command": "echo rust_ws_hmac_ok"}, token=TOKEN)
    out = b.get("output_log", "") if isinstance(b, dict) else ""
    check("Rust 副端 HMAC 签名指令执行", isinstance(b, dict) and b.get("state") == "success"
          and "rust_ws_hmac_ok" in out, f"state={b.get('state')} out={out[:60]}")

    # 3) sw_install：上传一个不含 .app 的 zip（验证下载+解包全链路，不落 /Applications）
    zp = "/tmp/yuduan-sw-e2e.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("readme.txt", "yuduan sw_install e2e package")
        z.writestr("bin/tool.sh", "#!/bin/sh\necho installed\n")
    st, b = http_upload("/api/v1/software", zp,
                        {"name": "e2e-tool", "version": "9.9.9", "platform": "macos"}, token=TOKEN)
    sw_id = b.get("item", {}).get("id") if isinstance(b, dict) else None
    check("软件仓库上传成功", st == 200 and bool(sw_id), f"id={sw_id}")
    if sw_id:
        st, b = http_post(f"/api/v1/devices/{DEVID}",
                          {"action": "sw_install", "software_url": f"{BASE}/api/v1/repo/{sw_id}",
                           "platform": "macos", "pkg_name": "e2e-tool"}, token=TOKEN)
        check("Rust 副端 sw_install 下载+解包", isinstance(b, dict) and b.get("state") == "success",
              f"state={b.get('state')} out={b.get('output_log','')[:80]}")

# 4) HMAC 拒签：错误密钥 → 指令被拒（回执 failed，不执行）
agent.terminate(); agent.wait()
time.sleep(0.5)
agent_bad = start_agent(f"ws://127.0.0.1:{PORT}/ws/agent", secret="WRONG-SECRET")
dev2 = wait_rust_device(TOKEN)
if dev2:
    st, b = http_post(f"/api/v1/devices/{dev2['id']}",
                      {"action": "shell", "command": "echo should_be_rejected"}, token=TOKEN)
    check("错误密钥指令被拒(不执行)", isinstance(b, dict) and b.get("state") == "failed"
          and "指令被拒" in b.get("output_log", ""), f"state={b.get('state')} out={b.get('output_log','')[:60]}")
agent_bad.terminate(); agent_bad.wait()
time.sleep(0.5)

# 5) wss（TLS）互通：openssl 管道代理 + 自签证书
agent_tls = start_agent("wss://127.0.0.1:8443/ws/agent")
dev3 = wait_rust_device(TOKEN)
check("Rust 副端(wss/TLS)注册成功", dev3 is not None, f"device={dev3['id'] if dev3 else None}")
if dev3:
    st, b = http_post(f"/api/v1/devices/{dev3['id']}",
                      {"action": "shell", "command": "echo rust_wss_ok"}, token=TOKEN)
    out = b.get("output_log", "") if isinstance(b, dict) else ""
    check("Rust 副端 wss 通道指令执行", isinstance(b, dict) and b.get("state") == "success"
          and "rust_wss_ok" in out, f"state={b.get('state')} out={out[:60]}")

# 6) M4 远控：viewer → rc_request → rc_ready（+rc_frame 若沙箱允许采集）→ rc_input → rc_stop
if dev3:
    try:
        v = WSClient("127.0.0.1", int(PORT), "/ws/viewer")
        v.send_text(json.dumps({"type": "rc_request", "payload": {
            "device_id": dev3["id"], "session_id": "e2e-rc-1", "operator": "admin"}}))
        ready = frame = event = None
        t0 = time.time()
        while time.time() - t0 < 25 and not (ready and (frame or event)):
            msg = v.recv_text(timeout=25)
            if not msg: break
            try: env = json.loads(msg)
            except Exception: continue
            t = env.get("type")
            if t == "rc_ready": ready = env
            elif t == "rc_frame": frame = env
            elif t == "rc_event":
                # consent_required 是合规提示（先于帧到达），只有 notice 才代表采集不可用
                if env["payload"].get("kind") == "notice":
                    event = env
        check("远控 rc_ready 就绪", ready is not None and ready["payload"].get("ok") is True,
              f"ok={ready['payload'].get('ok') if ready else None}")
        if frame:
            p = frame["payload"]
            raw = base64.b64decode(p.get("data", ""))
            dim = jpeg_size(raw)
            check("远控 rc_frame JPEG 帧有效", len(raw) > 1000 and dim is not None,
                  f"bytes={len(raw)} dim={dim} fmt={p.get('format')}")
        elif event:
            check("远控采集不可用时如实上报(沙箱限制)", event["payload"].get("kind") == "notice",
                  f"kind={event['payload'].get('kind')} msg={event['payload'].get('message','')[:50]}")
        else:
            check("远控 rc 帧/事件到达", False, "25s 内未收到 rc_frame/rc_event")
        # 输入注入 + 结束会话
        v.send_text(json.dumps({"type": "rc_input", "payload": {
            "session_id": "e2e-rc-1", "kind": "mouse_move", "x": 100, "y": 100}}))
        v.send_text(json.dumps({"type": "rc_stop", "payload": {"session_id": "e2e-rc-1"}}))
        stop_seen = False
        t0 = time.time()
        while time.time() - t0 < 8:
            msg = v.recv_text(timeout=8)
            if not msg: break
            try: env = json.loads(msg)
            except Exception: continue
            if env.get("type") == "rc_stop": stop_seen = True; break
            if env.get("type") == "rc_event" and env["payload"].get("kind") == "input_received": pass
        check("远控 rc_stop 会话结束", stop_seen)
        v.close()
    except Exception as e:
        check("M4 远控 viewer 链路", False, f"exception: {e}")

agent_tls.terminate(); agent_tls.wait()

# 收尾
hub.terminate()
print("\n==== 汇总 ====")
passed = sum(1 for _, c, _ in results if c)
print(f"{passed}/{len(results)} 通过")
fails = [n for n, c, _ in results if not c]
if fails:
    print("失败项: " + ", ".join(fails))
    sys.exit(1)
print("ALL PASS")
