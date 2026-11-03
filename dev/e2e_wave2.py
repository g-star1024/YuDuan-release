#!/usr/bin/env python3
# 御端 Wave 2（远控会话内协作）端到端验证脚本（仅标准库）。
#
# 覆盖：
#   W2-1 会话内文件传输（push 主端→终端，含 SHA-256 校验；pull 默认关闭的合规拒绝）
#   W2-2 会话内消息（主端→被控端提示 + 送达回告）
#   W2-3 画面控制（黑屏 / 水印状态回告）
#   W2-4 敏感设备二级审批（工单创建 → admin 放行 → 会话建立；驳回路径）
#   W2-5 会话视图 + 强制结束 + 空闲超时自动结束
#   W2-6 Ctrl+Alt+Del（非 Windows 平台诚实回告不支持）
#
# 说明：本脚本用 Go 参考副端（dev/cmd/agent）验证协议与中枢行为；
#       Rust 生产副端（rust/agent）的同构实现由 cargo test 覆盖（rc_wave2 单测）。
import base64, hashlib, json, os, random, socket, ssl, struct, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave2"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave2-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18082")
BASE = "http://127.0.0.1:" + PORT
PULL_ROOT = "/tmp/yuduan-wave2-pull"
os.makedirs(BIN, exist_ok=True)
os.makedirs(PULL_ROOT, exist_ok=True)

PASS = FAIL = 0
def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print(f"  ✓ {name}")
    else:
        FAIL += 1; print(f"  ✗ {name}  {detail}")

def api(method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if token: req.add_header("Authorization", "Bearer " + token)
    if data: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, raw

# ===================== 极简 WebSocket 客户端（viewer / 复用 e2e_rust 实现） =====================

class WSClient:
    def __init__(self, host, port, path):
        self.sock = socket.create_connection((host, port), timeout=15)
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
        deadline = time.time() + timeout
        while True:
            frame = self._read_frame(deadline)
            if frame is None: return None
            op, payload = frame
            if op == 0x8: return None
            if op == 0x9:
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
        if b0b1[1] & 0x80: need(4)
        return op, need(ln) if ln else b""

    def close(self):
        try: self.sock.close()
        except Exception: pass

def recv_event(ws, kinds, timeout=20):
    """读 rc_event 直到 kind 命中（kinds 可为字符串或集合）；其余事件丢弃。"""
    if isinstance(kinds, str): kinds = {kinds}
    deadline = time.time() + timeout
    while time.time() < deadline:
        t = ws.recv_text(timeout=max(1, deadline - time.time()))
        if t is None: return None
        try: env = json.loads(t)
        except Exception: continue
        if env.get("type") == "rc_event" and env.get("payload", {}).get("kind") in kinds:
            return env
    return None

def send_env(ws, typ, payload):
    ws.send_text(json.dumps({
        "ver": 1, "msg_id": "m%d" % int(time.time() * 1000), "ts": int(time.time()),
        "type": typ, "seq": 1, "payload": payload,
    }))

def recv_until(ws, typ, timeout=25, keep=None):
    """读到指定 type 的消息为止；其余消息按需沉淀到 keep 列表。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        t = ws.recv_text(timeout=max(1, deadline - time.time()))
        if t is None: return None
        try: env = json.loads(t)
        except Exception: continue
        if keep is not None: keep.append(env)
        if env.get("type") == typ: return env
    return None

# ===================== 主流程 =====================

def build():
    for name, pkg in [("hub", "./cmd/hub"), ("agent", "./cmd/agent")]:
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), pkg], cwd=DEV, check=True)
    print("[build] hub + agent 编译完成")

def start_hub(idle_sec, max_sec):
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-wave2-repo",
               YUDUAN_HUB_ADDR=":" + PORT,
               YUDUAN_RC_MAX_SEC=str(max_sec), YUDUAN_RC_IDLE_SEC=str(idle_sec))
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent(pull_root=""):
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET)
    if pull_root: env["YUDUAN_RC_PULL_ROOT"] = pull_root
    return subprocess.Popen([AGENT], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def wait_devices(token, n=1, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        _, r = api("GET", "/api/v1/devices", token)
        if isinstance(r, dict) and r.get("total", 0) >= n:
            return r["devices"]
        time.sleep(1)
    return []

def main():
    build()
    hub = start_hub(idle_sec=0, max_sec=0)   # 先关超时，避免干扰功能验证
    agent = start_agent(pull_root=PULL_ROOT)
    time.sleep(3)
    print(f"[hub] 启动 :{PORT}（本轮关闭超时，超时项单独复跑）")
    try:
        # ---- 登录 + 强制改密 ----
        _, r = api("POST", "/api/v1/login", body={"username": "admin", "password": "admin123"})
        token = r.get("token", "")
        check("admin 登录", bool(token), str(r)[:120])
        if r.get("must_change_password"):
            _, r2 = api("POST", "/api/v1/password", token, {"old_password": "admin123", "new_password": "Yuduan@2026x"})
            token = r2.get("token", token)
            check("首登强制改密", bool(token), str(r2)[:120])

        devs = wait_devices(token)
        check("副端注册上线", len(devs) >= 1, f"devices={len(devs)}")
        if not devs: return
        dev = devs[0]
        dev_id = dev["id"]

        # ---- W2-4：标记敏感 → rc_request 触发二级审批 ----
        _, r = api("POST", f"/api/v1/devices/meta/{dev_id}", token, {"sensitive": True})
        check("W2-4 标记设备为敏感", isinstance(r, dict) and r.get("sensitive") is True, str(r)[:160])

        ws = WSClient("127.0.0.1", int(PORT), "/ws/viewer?token=" + token)
        sid = "s-wave2-1"
        send_env(ws, "rc_request", {"device_id": dev_id, "session_id": sid, "operator": "admin"})
        ev = recv_until(ws, "rc_event", timeout=15)
        ok_approval = ev is not None and (ev.get("payload", {}).get("kind") == "approval_required")
        check("W2-4 敏感设备远控进入待审批", ok_approval, str(ev)[:200] if ev else "未收到 rc_event")

        _, r = api("GET", "/api/v1/rc/approvals?status=pending", token)
        pending = r.get("approvals", []) if isinstance(r, dict) else []
        check("W2-4 审批工单列表可见", len(pending) >= 1, str(r)[:200])
        if not pending: return
        apr_id = pending[0]["id"]

        # 驳回再放行（覆盖两条分支）：先建第二个工单用于驳回
        ws2 = WSClient("127.0.0.1", int(PORT), "/ws/viewer?token=" + token)
        send_env(ws2, "rc_request", {"device_id": dev_id, "session_id": "s-wave2-reject", "operator": "admin"})
        recv_until(ws2, "rc_event", timeout=10)
        _, r = api("GET", "/api/v1/rc/approvals?status=pending", token)
        pend2 = [a for a in (r.get("approvals", []) if isinstance(r, dict) else []) if a["id"] != apr_id]
        if pend2:
            _, rj = api("POST", f"/api/v1/rc/approvals/{pend2[0]['id']}", token, {"approve": False, "reason": "e2e"})
            check("W2-4 驳回工单", isinstance(rj, dict) and rj.get("ok") is True, str(rj)[:160])
            ev = recv_until(ws2, "rc_event", timeout=10)
            check("W2-4 驳回回告发起方",
                  ev is not None and ev.get("payload", {}).get("kind") == "approval_rejected", str(ev)[:160])
        ws2.close()

        # 放行第一个工单 → 会话建立
        _, r = api("POST", f"/api/v1/rc/approvals/{apr_id}", token, {"approve": True})
        check("W2-4 admin 放行进会话", isinstance(r, dict) and r.get("ok") is True, str(r)[:160])
        ready = recv_until(ws, "rc_ready", timeout=20)
        check("W2-4 放行后被控端就绪（rc_ready）", ready is not None, "未收到 rc_ready")

        time.sleep(1)
        _, r = api("GET", "/api/v1/rc/sessions", token)
        sessions = r.get("sessions", []) if isinstance(r, dict) else []
        check("W2-5 会话视图含该会话", any(s.get("session_id") == sid for s in sessions), str(r)[:200])
        if sessions:
            s0 = [s for s in sessions if s.get("session_id") == sid]
            if s0:
                check("W2-5 会话记录审批人", s0[0].get("approved") is True and s0[0].get("approved_by") == "admin",
                      str(s0[0])[:200])

        # ---- W2-2 会话内消息 ----
        send_env(ws, "rc_chat", {"session_id": sid, "from": "operator", "text": "e2e 测试消息", "ts": int(time.time())})
        ev = recv_event(ws, "chat_delivered", timeout=20)
        ok_chat = ev is not None
        check("W2-2 会话消息送达回告", ok_chat, str(ev)[:200] if ev else "未收到回告")

        # ---- W2-3 画面控制 ----
        send_env(ws, "rc_display", {"session_id": sid, "blank": True, "watermark": False, "text": ""})
        ev = recv_event(ws, "display_state", timeout=20)
        ok_disp = ev is not None
        check("W2-3 画面控制状态回告", ok_disp, str(ev)[:200] if ev else "未收到 display_state")
        send_env(ws, "rc_display", {"session_id": sid, "blank": False, "watermark": True, "text": "ADMIN E2E"})
        ev = recv_event(ws, "display_state", timeout=20)
        check("W2-3 水印可切换", ev is not None, str(ev)[:160])
        # 复位（避免影响后续帧校验）
        send_env(ws, "rc_display", {"session_id": sid, "blank": False, "watermark": False, "text": ""})
        recv_event(ws, "display_state", timeout=10)

        # ---- W2-1 文件传输（push） ----
        payload = bytes(random.getrandbits(8) for _ in range(300000))  # 300KB → 多分片
        sha = hashlib.sha256(payload).hexdigest()
        tid = "tf-e2e-1"
        send_env(ws, "rc_file_offer", {
            "session_id": sid, "transfer_id": tid, "direction": "push",
            "name": "e2e-test.bin", "size": len(payload), "sha256": sha,
        })
        acc = recv_until(ws, "rc_file_accept", timeout=20)
        ok_acc = acc is not None and acc.get("payload", {}).get("accept") is True
        check("W2-1 被控端同意接收", ok_acc, str(acc)[:200] if acc else "未收到 rc_file_accept")
        if ok_acc:
            cs = int(acc.get("payload", {}).get("chunk_size") or 65536)
            seq = 0
            for off in range(0, len(payload), cs):
                send_env(ws, "rc_file_chunk", {
                    "session_id": sid, "transfer_id": tid, "seq": seq,
                    "data": base64.b64encode(payload[off:off + cs]).decode(),
                })
                seq += 1
            done = recv_until(ws, "rc_file_done", timeout=30)
            ok_done = done is not None and done.get("payload", {}).get("ok") is True
            check("W2-1 文件传输完成且校验通过", ok_done, str(done)[:240] if done else "未收到 rc_file_done")
            if done:
                got = done.get("payload", {}).get("sha256", "")
                check("W2-1 SHA-256 一致", got.lower() == sha.lower(), f"{got} != {sha}")

        # ---- W2-1 pull：未配置允许根时应被拒绝（合规默认关闭） ----
        keep = []
        send_env(ws, "rc_file_offer", {
            "session_id": sid, "transfer_id": "tf-e2e-pull-out", "direction": "pull",
            "name": "x.txt", "size": 0, "path": "/etc/hosts",
        })
        done2 = recv_until(ws, "rc_file_done", timeout=20, keep=keep)
        # 本 agent 启动时带 PULL_ROOT=/tmp/yuduan-wave2-pull，/etc/hosts 不在其内 → 应拒绝
        ok_reject = done2 is not None and done2.get("payload", {}).get("ok") is False
        check("W2-1 越界拉取被拒（合规默认受控）", ok_reject, str(done2)[:240] if done2 else "未收到 rc_file_done")

        # ---- W2-6 Ctrl+Alt+Del ----
        send_env(ws, "rc_input", {"session_id": sid, "kind": "cad"})
        ev = recv_event(ws, {"cad", "cad_unsupported"}, timeout=20)
        check("W2-6 CAD 指令有明确回告（不静默）", ev is not None,
              "未收到 cad/cad_unsupported 回告")

        # ---- W2-5 强制结束 ----
        _, r = api("POST", f"/api/v1/rc/sessions/{dev_id}/kill", token, {})
        check("W2-5 强制结束会话", isinstance(r, dict) and r.get("ok") is True, str(r)[:160])
        time.sleep(1)
        _, r = api("GET", "/api/v1/rc/sessions", token)
        left = r.get("sessions", []) if isinstance(r, dict) else []
        check("W2-5 会话已从活动表移除", not any(s.get("session_id") == sid for s in left), str(r)[:200])
        stop_ev = recv_until(ws, "rc_stop", timeout=10)
        check("W2-5 主端收到 rc_stop 代发", stop_ev is not None, "未收到 rc_stop")
        ws.close()
    finally:
        agent.terminate(); hub.terminate()
        try: agent.wait(timeout=5)
        except Exception: agent.kill()
        try: hub.wait(timeout=5)
        except Exception: hub.kill()

    # ---- W2-5 空闲超时自动结束（独立复跑，短阈值） ----
    print("[hub] 复跑：空闲超时（IDLE=3s / MAX=0）")
    hub2 = start_hub(idle_sec=3, max_sec=0)
    agent2 = start_agent()
    time.sleep(3)
    try:
        # 复跑用的是全新中枢进程 → 走一次首登强制改密
        _, r = api("POST", "/api/v1/login", body={"username": "admin", "password": "admin123"})
        token2 = r.get("token", "")
        if r.get("must_change_password"):
            _, r = api("POST", "/api/v1/password", token2,
                       {"old_password": "admin123", "new_password": "Yuduan@2026x"})
            token2 = r.get("token", token2)
        check("W2-5 超时复跑：登录就绪", bool(token2), str(r)[:160])
        devs = wait_devices(token2)
        if not devs:
            check("W2-5 超时复跑：副端上线", False, "无设备")
            return
        dev_id = devs[0]["id"]
        ws3 = WSClient("127.0.0.1", int(PORT), "/ws/viewer?token=" + token2)
        send_env(ws3, "rc_request", {"device_id": dev_id, "session_id": "s-timeout", "operator": "admin"})
        recv_until(ws3, "rc_ready", timeout=20)
        _, r = api("GET", "/api/v1/rc/sessions", token2)
        check("W2-5 超时复跑：会话已建立",
              any(s.get("session_id") == "s-timeout" for s in (r.get("sessions", []) if isinstance(r, dict) else [])),
              str(r)[:200])
        # 不发送任何指令 → 空闲超时（扫描周期 30s，最多等 45s）
        ev = recv_event(ws3, "session_timeout", timeout=70)
        check("W2-5 空闲超时自动结束并回告", ev is not None, "未收到 session_timeout")
        time.sleep(1)
        _, r = api("GET", "/api/v1/rc/sessions", token2)
        check("W2-5 超时后会话已清理",
              not any(s.get("session_id") == "s-timeout" for s in (r.get("sessions", []) if isinstance(r, dict) else [])),
              str(r)[:200])
        ws3.close()
    finally:
        agent2.terminate(); hub2.terminate()
        try: agent2.wait(timeout=5)
        except Exception: agent2.kill()
        try: hub2.wait(timeout=5)
        except Exception: hub2.kill()

if __name__ == "__main__":
    main()
    print(f"\n=== Wave2 e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(1 if FAIL else 0)
