#!/usr/bin/env python3
# 御端 v0.4.8（实测报告问题 4）定向 e2e：设备注册幂等化。
# 场景：同一台机器 token 轮换后重新注册（模拟 -ResetConfig / 重装副端重新 claim），
# 必须复用既有设备 ID（台账不重复建档），且台账资产属性（分组）保留。
# v0.4.10：副端上报硬件指纹稳定 ID（sha256("yuduan-device|serial|mac|hostname") 前 16
# hex）——固定身份覆盖后，设备 ID 必须等于 python 独立重算的指纹值（Go/Rust/python
# 三方规范串一致性检查）。
import hashlib, json, os, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-identity"
SECRET = "identity-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18098")
BASE = "http://127.0.0.1:" + PORT
STATE_A = "/tmp/yd-id-state-A.json"
STATE_B = "/tmp/yd-id-state-B.json"
# 固定测试身份（YUDUAN_* 覆盖，v0.4.8 起）：使指纹 ID 可预计算
ID_HOST = "e2e-id-host"
ID_MAC = "AA:BB:CC:00:11:22"
ID_SERIAL = "E2EID0001"

def expected_fingerprint():
    canon = "yuduan-device|%s|%s|%s" % (
        ID_SERIAL.strip().lower(), ID_MAC.strip().lower(), ID_HOST.strip().lower())
    return hashlib.sha256(canon.encode()).hexdigest()[:16]

for f in (STATE_A, STATE_B):
    if os.path.exists(f):
        os.remove(f)
os.makedirs(BIN, exist_ok=True)

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
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-id-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    return subprocess.Popen([os.path.join(BIN, "hub")], cwd=DEV, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent(state_file):
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent",
               YUDUAN_HMAC_SECRET=SECRET, YUDUAN_STATE_FILE=state_file,
               YUDUAN_HOSTNAME=ID_HOST, YUDUAN_MAC=ID_MAC, YUDUAN_SERIAL=ID_SERIAL)
    return subprocess.Popen([os.path.join(BIN, "agent")], cwd=DEV, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def req(path, data=None, token=None, method=None):
    url = BASE + path
    r = urllib.request.Request(url, method=method or ("POST" if data is not None else "GET"))
    if token: r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
        r.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            raw = resp.read()
            if "json" in resp.headers.get("Content-Type", ""):
                return resp.status, json.loads(raw)
            return resp.status, raw
    except urllib.error.HTTPError as e:
        return e.code, {"_raw": e.read().decode()[:200]}
    except Exception as e:
        return -1, {"error": str(e)}

def wait_state(path, timeout=10):
    for _ in range(timeout * 2):
        if os.path.exists(path):
            try:
                st = json.load(open(path))
                if st.get("device_id"):
                    return st
            except Exception:
                pass
        time.sleep(0.5)
    return None

def main():
    build()
    hub = start_hub(); time.sleep(1.5)
    st, b = req("/api/v1/login", {"username": "admin", "password": "admin123"})
    check("admin 登录", bool(b.get("token")), str(b)[:120])
    # 首登强制改密（must_change 门控：不改密后续 API 全部 4033）
    st, b = req("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"}, token=b["token"])
    token = b.get("token")
    check("首登改密", bool(token), str(b)[:120])

    # 第一次注册（token A）
    agentA = start_agent(STATE_A); time.sleep(3)
    stateA = wait_state(STATE_A)
    check("首轮注册落盘身份", bool(stateA and stateA.get("device_id")), str(stateA)[:120])
    idA = stateA["device_id"]

    # 给该设备打台账分组（验证属性保留）
    st, b = req(f"/api/v1/devices/meta/{idA}", {"department": "研发部", "floor": "3F"}, token=token)
    check("台账分组设置", st == 200, f"st={st} {str(b)[:120]}")

    # 停掉 agent，删除本地身份（模拟密钥轮换 / 重装后重新 claim → 新 token）
    agentA.terminate()
    try: agentA.wait(timeout=5)
    except Exception: agentA.kill()
    time.sleep(1)

    # 第二次注册（token B，同机同硬件）
    agentB = start_agent(STATE_B); time.sleep(3)
    stateB = wait_state(STATE_B)
    check("次轮注册落盘身份", bool(stateB and stateB.get("device_id")), str(stateB)[:120])
    idB = stateB["device_id"] if stateB else ""

    st, b = req("/api/v1/devices", token=token)
    devices = b.get("devices", [])
    total = b.get("total", 0)
    check("台账不重复建档（total==1）", st == 200 and total == 1, f"total={total} devices={len(devices)}")
    check("设备 ID 幂等复用（A==B）", idA != "" and idA == idB, f"A={idA[:16]}… B={idB[:16]}…")
    want_fp = expected_fingerprint()
    check("设备 ID == 硬件指纹（python 独立重算）", idA == want_fp, f"idA={idA} want={want_fp}")
    if devices:
        d = devices[0]
        check("台账分组属性保留", d.get("department") == "研发部" and d.get("floor") == "3F",
              f"department={d.get('department')} floor={d.get('floor')}")
        check("在线状态", d.get("online") in (True, "true"), f"online={d.get('online')}")
    agentB.terminate()
    try: agentB.wait(timeout=5)
    except Exception: agentB.kill()
    hub.terminate()
    try: hub.wait(timeout=5)
    except Exception: hub.kill()
    try:
        out, _ = hub.communicate(timeout=3)
        print("---- hub.log tail ----")
        print("\n".join(out.split("\n")[-25:]))
    except Exception as e:
        print("hub log err:", e)

    print(f"\n=== Identity e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
