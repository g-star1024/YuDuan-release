#!/usr/bin/env python3
# 御端 Wave 4 定向冒烟 —— W4-2 周期同步 + W4-3 断点续传（仅标准库）。
# 复用 e2e_wave4 harness；副端经 YUDUAN_E2E_CHUNK_FAIL_AT=1 注入一次链路中断，
# 验证中枢按副端确认偏移续传并最终 SHA-256 一致。
import hashlib, json, os, subprocess, sys, threading, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave4b"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave4b-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18088")
BASE = "http://127.0.0.1:" + PORT
REPO = "/tmp/yuduan-wave4b-repo"
DL = "/tmp/yuduan-wave4b-dl"
os.makedirs(BIN, exist_ok=True)
os.makedirs(REPO, exist_ok=True)
os.makedirs(DL, exist_ok=True)

PASS = FAIL = 0
def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print(f"  ✓ {name}")
    else:
        FAIL += 1; print(f"  ✗ {name}  {detail}")

# 常驻进程日志读取器：非阻塞持续追加到 buffer，避免 read() 阻塞挂死脚本。
def start_reader(proc, buf):
    def _rd():
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            buf.append(line)
    th = threading.Thread(target=_rd, daemon=True)
    th.start()
    return th

def build():
    for name, pkg in [("hub", "./cmd/hub"), ("agent", "./cmd/agent")]:
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), pkg], cwd=DEV, check=True)
    print("[build] hub + agent 编译完成")

def start_hub():
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO=REPO, YUDUAN_HUB_ADDR=":" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent(fail_at=""):
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET,
               YUDUAN_FS_WRITE_ROOT=DL, YUDUAN_FS_PULL_ROOT=DL)
    if fail_at:
        env["YUDUAN_E2E_CHUNK_FAIL_AT"] = fail_at
    return subprocess.Popen([AGENT], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def req(path, data=None, token=None, method=None):
    url = BASE + path
    if method is None:
        method = "POST" if data is not None else "GET"
    r = urllib.request.Request(url, method=method)
    if token: r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
        r.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read()
            ct = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(raw) if "json" in ct else raw)
    except urllib.error.HTTPError as e:
        return e.code, {"_raw": e.read().decode()[:200]}
    except Exception as e:
        return -1, {"error": str(e)}

def wait_task(token, path, target, timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, b = req(path, token=token)
        if st == 200 and b.get("code") == 0:
            t = b.get("task") or {}
            if t.get("state") in target:
                return t
        time.sleep(0.3)
    return None

def login():
    st, b = req("/api/v1/login", {"username": "admin", "password": "admin123"})
    if st != 200 or not b.get("token"): raise SystemExit("login 失败: " + str(b))
    st, b = req("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"}, token=b["token"])
    return b.get("token")

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()

def main():
    build()
    hub = start_hub(); time.sleep(1.5)
    print(f"[hub] 启动 :{PORT}")
    token = login()
    check("admin 登录+改密", bool(token))
    # 副端注入：分片序号 1 触发一次链路中断（W4-3 断点续传场景）
    agent = start_agent(fail_at="1"); time.sleep(2.5)
    print("[agent] 启动（注入分片失败@seq=1），等待注册…")
    time.sleep(2)
    hub_buf, agent_buf = [], []
    start_reader(hub, hub_buf)
    start_reader(agent, agent_buf)

    st, b = req("/api/v1/devices", token=token)
    check("设备列表", st == 200 and b.get("total", 0) >= 1, f"total={b.get('total')}")
    devs = b.get("devices", [])
    if not devs:
        print("  (无设备，无法继续)"); agent.terminate(); hub.terminate()
        print(f"\n=== Wave4b e2e: PASS={PASS} FAIL={FAIL} ==="); sys.exit(1)
    dev_id = devs[0]["id"]

    # ---------- W4-3 断点续传 ----------
    src = os.path.join(REPO, "resume.bin")
    with open(src, "wb") as f:
        f.write(os.urandom(900 * 1024))  # 900KB > 256KB 分片，保证多分片
    exp_sha = sha(src)
    dest = "resume.bin"  # 相对写入根路径
    st, b = req("/api/v1/filesync/tasks", {"kind": "push", "name": "resume-test",
                                           "source": src, "dest": dest, "device_ids": [dev_id]}, token=token)
    tid = b.get("id")
    check("W4-3 创建下发任务", st == 200 and b.get("code") == 0 and tid, f"st={st} b={str(b)[:120]}")
    t = wait_task(token, f"/api/v1/filesync/tasks/{tid}", ["success", "failed"])
    if t and t.get("state") == "failed":
        print("    [task failed] recs=", json.dumps(t.get("records") or [], ensure_ascii=False)[:300])
        print("    [agent log tail] ", "".join(agent_buf[-15:]))
        print("    [hub log tail] ", "".join(hub_buf[-15:]))
    elif t is None:
        print("    [task missing] hub alive=", hub.poll() is None)
        print("    [hub log tail] ", "".join(hub_buf[-20:]))
    check("W4-3 注入中断后仍成功(续传)", t is not None and t.get("state") == "success",
          f"state={t.get('state') if t else None}")
    if t and os.path.exists(os.path.join(DL, dest)):
        got_sha = sha(os.path.join(DL, dest))
        check("W4-3 续传后 SHA-256 一致", got_sha == exp_sha, f"got={got_sha[:16]} exp={exp_sha[:16]}")
        check("W4-3 落盘字节数=源大小", os.path.getsize(os.path.join(DL, dest)) == os.path.getsize(src),
              f"got={os.path.getsize(os.path.join(DL, dest))} exp={os.path.getsize(src)}")
    else:
        check("W4-3 目标文件已落盘", False, "目标文件缺失")

    # 观测副端日志：确认确实发生过一次中断 + 一次续传
    time.sleep(0.5)
    agent_out = "".join(agent_buf)
    resumed_log = "续传=true" in agent_out or "断点续传" in agent_out
    inject_log = "注入链路中断" in agent_out
    check("W4-3 副端确认发生续传", resumed_log, "agent 日志未见续传")
    check("W4-3 副端确认注入中断", inject_log, "agent 日志未见注入")
    if not inject_log:
        print("    [agent log tail] ", "".join(agent_buf[-8:]))

    # ---------- W4-2 周期同步 ----------
    src2 = os.path.join(REPO, "sync.txt")
    with open(src2, "w") as f:
        f.write("yuduan-sync-" + time.strftime("%H%M%S"))
    dest2 = "sync.txt"  # 相对写入根路径
    st, b = req("/api/v1/filesync/tasks", {"kind": "sync", "name": "sync-test", "interval_sec": 1,
                                           "source": src2, "dest": dest2, "device_ids": [dev_id]}, token=token)
    sid = b.get("id")
    check("W4-2 创建周期同步任务", st == 200 and b.get("code") == 0 and sid, f"st={st} b={str(b)[:120]}")
    time.sleep(2.6)  # interval=1s，应至少完成一轮
    st, b = req(f"/api/v1/filesync/tasks/{sid}", token=token)
    t2 = b.get("task") or {}
    recs = t2.get("records") or []
    check("W4-2 周期同步有执行记录", st == 200 and len(recs) >= 1, f"recs={len(recs)} state={t2.get('state')}")
    check("W4-2 周期同步记录成功", any(r.get("state") == "success" for r in recs),
          f"states={[r.get('state') for r in recs]}")
    check("W4-2 周期同步目标已落盘", os.path.exists(os.path.join(DL, dest2)) and open(os.path.join(DL, dest2)).read().startswith("yuduan-sync-"),
          "目标文件缺失/内容不符")
    st, b = req(f"/api/v1/filesync/tasks/{sid}/cancel", {}, token=token)
    check("W4-2 取消周期同步", st == 200 and b.get("code") == 0, f"st={st}")

    agent.terminate(); hub.terminate()
    print(f"\n=== Wave4b e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
