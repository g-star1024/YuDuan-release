#!/usr/bin/env python3
# 御端 Wave 5a（终端安全合规域 · W5-1 合规基线检查）端到端验证（仅标准库）。
# 覆盖：副端合规采集上报 → 中枢评估 → 合规分计算 → 概览/设备列表视图。
# 注：W5-2 黑名单 / W5-5 漏洞的闭环逻辑与 e2e 由并行开发单元（原 wave5a 单元）
# 在本会话限流前未及落盘，本脚本聚焦验证「W5-1 采集链路」这一已接好并可验证的核心。
import json, os, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave5a"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave5a-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18085")
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
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-wave5a-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent():
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET)
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

def login():
    st, b = req("/api/v1/login", {"username": "admin", "password": "admin123"})
    if st != 200 or not b.get("token"): raise SystemExit("login 失败: " + str(b))
    st, b = req("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"}, token=b["token"])
    return b.get("token")

def main():
    build()
    hub = start_hub(); time.sleep(1.5)
    print(f"[hub] 启动 :{PORT}")
    token = login()
    check("admin 登录+改密", bool(token))
    agent = start_agent(); time.sleep(2.5)
    print("[agent] 启动，等待注册…")
    time.sleep(2)

    st, b = req("/api/v1/devices", token=token)
    check("设备列表", st == 200 and b.get("total", 0) >= 1, f"total={b.get('total')}")
    devs = b.get("devices", [])
    if not devs:
        print("  (无设备，无法继续)"); agent.terminate(); hub.terminate()
        print(f"\n=== Wave5a e2e: PASS={PASS} FAIL={FAIL} ==="); sys.exit(1)
    dev_id = devs[0]["id"]

    # W5-1 触发合规采集（中枢下发 compliance_collect → 副端 collect.Compliance() 回执）
    st, b = req(f"/api/v1/compliance/devices/{dev_id}/collect", {}, token=token)
    ok = st == 200 and b.get("code") == 0 and b.get("compliance")
    check("W5-1 触发合规采集并回执", ok, f"st={st} b={str(b)[:160]}")
    comp = b.get("compliance") or {}
    items = comp.get("items") or []
    check("W5-1 副端回执合规项非空", len(items) > 0, f"items={len(items)}")
    cats = {it.get("category") for it in items}
    check("W5-1 覆盖多类基线(patch/av/firewall/screensaver)",
          any(c in cats for c in ["patch", "antivirus", "firewall", "screensaver"]), f"cats={cats}")
    states = {it.get("state") for it in items}
    check("W5-1 含诚实状态(pass/fail/unknown)", states & {"pass", "fail", "unknown"} == states and states, f"states={states}")
    score = comp.get("score")
    check("W5-1 合规分已计算(整数)", isinstance(score, int), f"score={score}")
    print(f"    采集到 {len(items)} 项，合规分={score}，状态分布={states}")

    # 概览视图
    st, b = req("/api/v1/compliance/overview", token=token)
    check("W5-1 合规概览可访问", st == 200 and b.get("code") == 0, f"st={st}")

    # 设备合规列表（含分数/违规数）
    st, b = req("/api/v1/compliance/devices", token=token)
    check("W5-1 设备合规列表", st == 200 and b.get("code") == 0, f"st={st}")

    agent.terminate(); hub.terminate()
    print(f"\n=== Wave5a e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
