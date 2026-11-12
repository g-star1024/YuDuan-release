#!/usr/bin/env python3
# 御端 Wave 4（文件分发与批量命令）端到端验证（仅标准库）。
# 覆盖：W4-1 文件下发（SHA-256 一致）/ W4-4 批量脚本异常高亮 / W4-5 危险命令二次确认+审批。
# 副端配置文件写入根（YUDUAN_FS_WRITE_ROOT）以接收下发；脚本执行走 shell（macOS 实测）。
import json, os, subprocess, sys, time, urllib.request, urllib.error, hashlib, tempfile

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave4"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave4-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18084")
BASE = "http://127.0.0.1:" + PORT
# 用真实路径作为文件允许根（/tmp 在 macOS 是符号链接，EvalSymlinks 会把目标解析到
# /private/tmp 导致路径越界判定——这是环境问题而非代码 bug，用 /var/folders 下的临时目录规避）
FSROOT = os.path.join(tempfile.gettempdir(), "yuduan-wave4-fsroot")
SRCDIR = os.path.join(tempfile.gettempdir(), "yuduan-wave4-src")
os.makedirs(BIN, exist_ok=True)
os.makedirs(FSROOT, exist_ok=True)
os.makedirs(SRCDIR, exist_ok=True)

PASS = FAIL = 0
def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print(f"  ✓ {name}")
    else:
        FAIL += 1; print(f"  ✗ {name}  {detail}")

def build():
    for name, pkg in [("hub", "./cmd/hub"), ("agent", "./cmd/agent")]:
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), pkg], cwd=DEV, check=True)
    print("[build] hub + agent 编译完成")

def start_hub():
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-wave4-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent():
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET,
               YUDUAN_FS_WRITE_ROOT=FSROOT, YUDUAN_FS_PULL_ROOT=FSROOT)
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
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read()
            ct = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(raw) if "json" in ct else raw)
    except urllib.error.HTTPError as e:
        return e.code, {"_raw": e.read().decode()[:200]}
    except Exception as e:
        return -1, {"error": str(e)}

def login():
    st, b = req("/api/v1/login", {"username": "admin", "password": "admin123"})
    if st != 200 or not b.get("token"): raise SystemExit("login 失败: " + str(b))
    st, b = req("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"}, token=b["token"])
    return b.get("token")

def wait_online(token, timeout=20):
    for _ in range(timeout):
        st, b = req("/api/v1/devices", token=token)
        if st == 200 and b.get("total", 0) >= 1:
            return b["devices"][0]["id"]
        time.sleep(1)
    return None

def wait_task(token, path, want, timeout=20):
    for _ in range(timeout):
        st, b = req(path, token=token)
        if st == 200 and b.get("code") == 0:
            t = b.get("task") or {}
            if t.get("state") == want:
                return t
        time.sleep(1)
    return None

def main():
    build()
    hub = start_hub(); time.sleep(1.5)
    print(f"[hub] 启动 :{PORT}")
    token = login()
    check("admin 登录+改密", bool(token))
    agent = start_agent(); time.sleep(2.5)
    dev_id = wait_online(token)
    check("副端注册上线", dev_id is not None, f"dev_id={dev_id}")
    if not dev_id:
        agent.terminate(); hub.terminate()
        print(f"\n=== Wave4 e2e: PASS={PASS} FAIL={FAIL} ==="); sys.exit(1)

    # ---- W4-1 文件下发（SHA-256 一致）----
    payload = os.urandom(300 * 1024)  # 300KB > 256KB 分片，触发多分片
    src = os.path.join(SRCDIR, "src.bin")
    open(src, "wb").write(payload)
    expected_sha = hashlib.sha256(payload).hexdigest()
    task_body = {"kind": "push", "name": "push-test", "source": src, "dest": "pushed.bin",
                 "device_ids": [dev_id]}
    st, b = req("/api/v1/filesync/tasks", task_body, token=token)
    check("W4-1 创建下发任务", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:100]}")
    tid = b.get("id")
    if tid:
        t = wait_task(token, f"/api/v1/filesync/tasks/{tid}", "success", 20)
        check("W4-1 下发成功（设备落盘）", t is not None, f"tid={tid}")
        if not t:
            st, b = req(f"/api/v1/filesync/tasks/{tid}", token=token)
            recs = b.get("task", {}).get("records", [])
            print(f"      [诊断] 任务状态: state={b.get('task', {}).get('state')}")
            for r in recs:
                print(f"      [诊断] record: state={r.get('state')} msg={str(r.get('msg'))[:200]}")
        else:
            recs = t.get("records", [])
            sha = recs[0].get("sha256", "") if recs else ""
            check("W4-1 全文件 SHA-256 一致", sha.lower() == expected_sha, f"sha={sha[:16]} exp={expected_sha[:16]}")
            # 验证副端实际落盘内容
            landed = os.path.join(FSROOT, "pushed.bin")
            if os.path.exists(landed):
                landed_sha = hashlib.sha256(open(landed, "rb").read()).hexdigest()
                check("W4-1 落盘内容与源一致", landed_sha == expected_sha, f"landed={landed_sha[:16]}")

    # ---- W4-4 批量脚本（正常 + 异常高亮）----
    ok_script = "echo hello-wave4"
    st, b = req("/api/v1/batchcmd/tasks", {"script": ok_script, "device_ids": [dev_id]}, token=token)
    check("W4-4 创建批量脚本任务", st == 200 and b.get("code") == 0, f"st={st}")
    bid = b.get("id")
    if bid:
        t = wait_task(token, f"/api/v1/batchcmd/tasks/{bid}", "success", 20)
        check("W4-4 正常脚本执行成功", t is not None, f"bid={bid}")
        if t:
            print(f"      summary={t.get('summary')}")
            check("W4-4 无异常高亮", t.get("summary", {}).get("abnormal", 1) == 0, f"sum={t.get('summary')}")

    # 异常脚本（exit 1）
    bad_script = "exit 1"
    st, b = req("/api/v1/batchcmd/tasks", {"script": bad_script, "device_ids": [dev_id]}, token=token)
    check("W4-4 创建异常脚本任务", st == 200 and b.get("code") == 0, f"st={st}")
    bid2 = b.get("id")
    if bid2:
        t = wait_task(token, f"/api/v1/batchcmd/tasks/{bid2}", "failed", 20)
        check("W4-4 异常脚本 → failed+异常高亮", t is not None and t.get("summary", {}).get("abnormal") >= 1, f"bid={bid2} sum={t.get('summary') if t else None}")

    # ---- W4-5 危险命令二次确认 ----
    danger_script = "rm -rf /tmp/never-delete"
    st, b = req("/api/v1/batchcmd/tasks", {"script": danger_script, "device_ids": [dev_id]}, token=token)
    check("W4-5 危险命令 → 待审批（未确认）", st == 200 and b.get("code") == 0 and b.get("danger") and not b.get("confirmed"), f"st={st} b={str(b)[:120]}")
    did = b.get("id")
    if did:
        t = wait_task(token, f"/api/v1/batchcmd/tasks/{did}", "awaiting_approval", 8)
        check("W4-5 任务停在 awaiting_approval", t is not None, f"did={did}")
        # 确认后放行
        st, b = req(f"/api/v1/batchcmd/tasks/{did}/confirm", {"confirmed": True}, token=token)
        check("W4-5 confirm 确认接口", st == 200 and b.get("code") == 0, f"st={st}")
        t2 = wait_task(token, f"/api/v1/batchcmd/tasks/{did}", "success", 20)
        check("W4-5 确认后执行完成", t2 is not None, f"did={did}")

    agent.terminate(); hub.terminate()
    print(f"\n=== Wave4 e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
