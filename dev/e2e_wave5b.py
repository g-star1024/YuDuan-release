#!/usr/bin/env python3
# 御端 Wave 5b（外设管控 / 网络准入 / 报表统计）端到端验证（仅标准库）。
# 覆盖：W5-3 外设策略 CRUD+按设备下发+副端诚实回执 / W5-4 准入动作下发/解除 /
#       W5-7 统计概览 + CSV/XLSX 导出。
import json, os, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave5b"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave5b-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18086")
BASE = "http://127.0.0.1:" + PORT
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
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-wave5b-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent():
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET)
    return subprocess.Popen([AGENT], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def req(path, data=None, token=None, method=None, raw=False):
    url = BASE + path
    if method is None:
        method = "POST" if data is not None else "GET"
    r = urllib.request.Request(url, method=method)
    if token: r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
        r.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            rawb = resp.read()
            ct = resp.headers.get("Content-Type", "")
            if raw:
                return resp.status, rawb
            return resp.status, (json.loads(rawb) if "json" in ct else rawb)
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

def wait_apply(token, path, timeout=15):
    for _ in range(timeout):
        st, b = req(path, token=token)
        if st == 200 and b.get("code") == 0:
            sts = b.get("states") or []
            if sts and sts[0].get("status") not in ("pending",):
                return sts[0]
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
        print(f"\n=== Wave5b e2e: PASS={PASS} FAIL={FAIL} ==="); sys.exit(1)

    # ---- W5-3 外设策略 CRUD ----
    policy = {"name": "usb-block-test", "scope_type": "device", "scope_value": dev_id,
              "usb_storage": "block", "optical": "allow", "bluetooth": "allow"}
    st, b = req("/api/v1/peripheral/policies", policy, token=token)
    check("W5-3 创建外设策略", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:100]}")
    pid = (b.get("policy") or {}).get("id")
    check("W5-3 创建返回策略ID", pid is not None, f"pid={pid}")
    if pid:
        st, b = req(f"/api/v1/peripheral/policies/{pid}", token=token)
        check("W5-3 策略详情", st == 200 and b.get("code") == 0, f"st={st}")

    # 按设备下发（dry-run：副端诚实回执）
    st, b = req("/api/v1/peripheral/apply", {"device_id": dev_id, "policy_id": pid}, token=token)
    check("W5-3 按设备下发策略", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:100]}")
    if pid:
        stt = wait_apply(token, f"/api/v1/peripheral/status?device_id={dev_id}")
        check("W5-3 副端回执（诚实状态）", stt is not None, f"stt={stt}")
        if stt:
            print(f"      status={stt.get('status')} items={[(i.get('item'), i.get('state')) for i in stt.get('items', [])]}")
        else:
            st, b = req(f"/api/v1/peripheral/status?device_id={dev_id}", token=token)
            print(f"      [诊断] status 响应: {str(b)[:250]}")

    # ---- W5-4 网络准入 ----
    st, b = req("/api/v1/nac/apply", {"device_id": dev_id, "action": "quarantine", "reason": "e2e-test"}, token=token)
    check("W5-4 下发准入隔离", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:100]}")
    st, b = req("/api/v1/nac/actions", token=token)
    check("W5-4 准入列表", st == 200 and b.get("code") == 0, f"st={st}")
    nac = b.get("actions") or []
    check("W5-4 隔离动作已记录", any(a.get("device_id") == dev_id and a.get("action") == "quarantine" for a in nac), f"nac={len(nac)}")
    st, b = req("/api/v1/nac/release", {"device_id": dev_id, "reason": "e2e-release"}, token=token)
    check("W5-4 解除准入", st == 200 and b.get("code") == 0, f"st={st}")

    # ---- W5-7 统计概览 + 导出 ----
    st, b = req("/api/v1/stats/overview", token=token)
    check("W5-7 统计概览", st == 200 and b.get("code") == 0 and b.get("overview"), f"st={st}")
    ov = b.get("overview") or {}
    check("W5-7 覆盖率指标存在", "coverage" in ov or "total" in ov, f"keys={list(ov.keys())[:6]}")

    st, rawb = req("/api/v1/stats/export?format=csv&type=coverage", token=token, raw=True)
    check("W5-7 CSV 导出", st == 200 and isinstance(rawb, (bytes, bytearray)) and len(rawb) > 0, f"st={st} len={len(rawb) if isinstance(rawb,(bytes,bytearray)) else '?'}")
    if isinstance(rawb, (bytes, bytearray)):
        txt = rawb.decode("utf-8", "replace")
        check("W5-7 CSV 内容非空", len(txt.splitlines()) >= 1, f"lines={len(txt.splitlines())}")

    st, rawb = req("/api/v1/stats/export?format=xlsx&type=coverage", token=token, raw=True)
    check("W5-7 XLSX 导出", st == 200 and isinstance(rawb, (bytes, bytearray)) and rawb[:2] == b"PK", f"st={st} head={rawb[:2] if isinstance(rawb,(bytes,bytearray)) else '?'}")

    agent.terminate(); hub.terminate()
    print(f"\n=== Wave5b e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
