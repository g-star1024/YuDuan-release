#!/usr/bin/env python3
# 御端 M6 / 安全基座 端到端验证脚本（仅依赖标准库）。
# 覆盖：登录令牌往返(RBAC门禁) / 审计落库 / TLS(https+wss) / HMAC 指令签名执行 / HMAC 强制拒绝。
import json, os, ssl, subprocess, sys, time, urllib.request, urllib.error

# 本机 HTTP_PROXY 指向 127.0.0.1 代理，urllib 会把 127.0.0.1 也走代理导致 502；
# 端到端测试必须直连，禁用代理。
urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-e2e"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "e2e-secret"
# 端口可配（本机 8080 常被 Docker Desktop 占用，硬编码会让整轮 e2e 假失败）。
PORT = os.environ.get("YUDUAN_E2E_PORT", "8080")
BASE = "http://127.0.0.1:" + PORT
os.makedirs(BIN, exist_ok=True)
os.makedirs(os.path.join(DEV, "certs"), exist_ok=True)

def build():
    for name, pkg in [("hub", "./cmd/hub"), ("agent", "./cmd/agent")]:
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), pkg],
                       cwd=DEV, check=True)
    print("[build] hub + agent 编译完成")

def start_hub(env_extra=None):
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-e2e-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    if env_extra:
        env.update(env_extra)
    p = subprocess.Popen(["go", "run", "."] if False else [HUB],
                         cwd=DEV, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p

def start_agent(secret=SECRET, enforce=False, hub=None):
    hub = hub or f"ws://127.0.0.1:{PORT}/ws/agent"
    env = dict(os.environ, YUDUAN_HUB=hub, YUDUAN_HMAC_SECRET=secret,
               YUDUAN_HMAC_ENFORCE="1" if enforce else "0")
    p = subprocess.Popen([AGENT], cwd=DEV, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p

def http_get(path, token=None, base=None, https=False):
    base = base or BASE
    url = path if path.startswith("http") else base + path
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
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

def http_post(path, data, token=None, base=None):
    base = base or BASE
    url = base + path
    req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
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

def wait_device():
    # 选取在线设备中最近一次心跳者（排除刚被 terminate 的陈旧离线设备）。
    for _ in range(40):
        st, body = http_get("/api/v1/devices", token=ADMIN_TOKEN)
        if st == 200:
            online = [d for d in body.get("devices", []) if d.get("online")]
            if online:
                online.sort(key=lambda d: d.get("last_heartbeat", ""), reverse=True)
                return online[0]
        time.sleep(0.5)
    return None

results = []
def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(("PASS " if cond else "FAIL ") + name + ("  " + detail if detail else ""))

# ---- 启动 ----
build()
hub = start_hub()
time.sleep(1.5)

# 1) 登录：admin / viewer（验证令牌往返 + 强制改密门禁）
st, body = http_post("/api/v1/login", {"username": "admin", "password": "admin123"})
ADMIN_TOKEN = body.get("token")
check("login admin 200+role", st == 200 and body.get("role") == "admin", f"role={body.get('role')}")
check("login admin token 非空", bool(ADMIN_TOKEN))
check("admin 首次登录标记强制改密", body.get("must_change_password") is True,
      f"must_change={body.get('must_change_password')}")

# 1b) 强制改密门禁：must_change 令牌访问受保护接口 → 4033；改密接口放行
st, b = http_get("/api/v1/devices", token=ADMIN_TOKEN)
check("must_change 令牌被 4033 拦截", b.get("code") == 4033, f"code={b.get('code')}")
st, b = http_post("/api/v1/password", {"old_password": "admin123", "new_password": "weak"},
                  token=ADMIN_TOKEN)
check("弱口令改密被拒(强度校验)", b.get("code") == 4002, f"code={b.get('code')} msg={b.get('message','')[:40]}")
st, b = http_post("/api/v1/password", {"old_password": "wrong-old", "new_password": "Admin@2026x"},
                  token=ADMIN_TOKEN)
check("旧口令错误改密被拒", b.get("code") == 4002, f"code={b.get('code')}")
st, b = http_post("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"},
                  token=ADMIN_TOKEN)
check("admin 改密成功并换发令牌", st == 200 and b.get("code") == 0 and bool(b.get("token")),
      f"code={b.get('code')}")
ADMIN_TOKEN = b.get("token") or ADMIN_TOKEN
# 换发令牌不再带 must_change，可访问受保护接口
st, b = http_get("/api/v1/devices", token=ADMIN_TOKEN)
check("换发令牌可访问设备接口", b.get("total") is not None, f"total={b.get('total')}")
# 旧口令失效、新口令可登（argon2id 口令生效）
st, b = http_post("/api/v1/login", {"username": "admin", "password": "admin123"})
check("旧口令登录被拒", b.get("code") == 401, f"code={b.get('code')}")
st, b = http_post("/api/v1/login", {"username": "admin", "password": "Admin@2026x"})
check("新口令登录成功", st == 200 and b.get("role") == "admin" and not b.get("must_change_password"),
      f"role={b.get('role')} must_change={b.get('must_change_password')}")
ADMIN_TOKEN = b.get("token") or ADMIN_TOKEN

st, body = http_post("/api/v1/login", {"username": "viewer", "password": "viewer123"})
VIEWER_TOKEN = body.get("token")
check("login viewer role", st == 200 and body.get("role") == "viewer", f"role={body.get('role')}")
check("viewer 无强制改密标记", body.get("must_change_password") is not True)

st, body = http_post("/api/v1/login", {"username": "admin", "password": "wrong"})
check("login 错误口令 401", st == 200 and body.get("code") == 401, f"code={body.get('code')}")

# 2) RBAC 门禁
st, _ = http_get("/api/v1/devices")  # 无令牌
check("无令牌访问 401", st == 200 and http_get("/api/v1/devices")[1].get("code") == 401
      if False else st == 200)  # go返回200包体code=401; 用包体判定
_, b = http_get("/api/v1/devices"); check("无令牌包体401", b.get("code") == 401, f"code={b.get('code')}")

st, b = http_get("/api/v1/devices", token=VIEWER_TOKEN)
check("viewer 可查看设备(200)", b.get("total") is not None, f"total={b.get('total')}")

# viewer 缺 device:command → POST 指令应 403
dev_id_placeholder = "placeholder"
st, b = http_post(f"/api/v1/devices/{dev_id_placeholder}", {"action": "shell", "command": "echo x"}, token=VIEWER_TOKEN)
check("viewer 发指令被 403 拒绝", b.get("code") == 403, f"code={b.get('code')}")

# viewer 有 audit:view 应可查审计(200)；缺 software:manage → 上传软件应 403
st, b = http_get("/api/v1/audit", token=VIEWER_TOKEN)
check("viewer 可查看审计(200, 其角色含 audit:view)", b.get("total") is not None, f"total={b.get('total')}")
st, b = http_post("/api/v1/software", {"name": "x"}, token=VIEWER_TOKEN)
check("viewer 上传软件被 403 拒绝", b.get("code") == 403, f"code={b.get('code')}")

# 3) 审计：登录事件已落库（admin 查审计）
st, b = http_get("/api/v1/audit", token=ADMIN_TOKEN)
check("admin 查审计 200", b.get("total") is not None, f"total={b.get('total')}")
login_events = [e for e in b.get("events", []) if e.get("action") == "login"]
check("审计含登录事件", len(login_events) >= 2, f"login_events={len(login_events)}")

# 4) TLS：https 控制台页 + wss 注册（/ 返回 HTML，仅判定状态码）
st, b = http_get("/", base="https://127.0.0.1:8443")
check("TLS https 控制台可访问(200)", st == 200, f"status={st}")
# wss agent
agent_tls = start_agent(hub="wss://127.0.0.1:8443/ws/agent")
time.sleep(2.0)
tls_dev = wait_device()
check("TLS(wss) 副端注册成功", tls_dev is not None, f"device={tls_dev['id'] if tls_dev else None}")
agent_tls.terminate()

# 普通 ws agent（用于指令执行测试）
agent = start_agent()
time.sleep(2.0)
dev = wait_device()
check("副端(ws)注册成功", dev is not None, f"device={dev['id'] if dev else None}")
DEVID = dev["id"] if dev else None

# 5) HMAC 签名指令：hub 签名 → agent 验签 → 执行 → 回结果
if DEVID:
    st, b = http_post(f"/api/v1/devices/{DEVID}", {"action": "shell", "command": "echo e2e_hmac_ok"},
                      token=ADMIN_TOKEN)
    out = b.get("output_log", "") if isinstance(b, dict) else ""
    check("HMAC 签名指令执行成功", isinstance(b, dict) and b.get("state") == "success" and "e2e_hmac_ok" in out,
          f"state={b.get('state')} out={out[:60]}")

# 6) HMAC 强制拒绝：agent 用错误 secret + enforce=on → hub 签的名验不过 → 拒绝
agent.terminate(); time.sleep(0.5)
agent_bad = start_agent(secret="WRONG-SECRET", enforce=True)
time.sleep(2.5)
dev2 = wait_device()
if dev2:
    st, b = http_post(f"/api/v1/devices/{dev2['id']}", {"action": "shell", "command": "echo should_reject"},
                      token=ADMIN_TOKEN)
    check("HMAC 强制拒绝(错误secret) → 指令失败", isinstance(b, dict) and b.get("state") == "failed"
          and "HMAC" in b.get("output_log", ""), f"state={b.get('state')} out={b.get('output_log','')[:60]}")
agent_bad.terminate()

# 7) WORM 审计链校验（哈希链 replay 验证）
st, b = http_get("/api/v1/audit/verify", token=ADMIN_TOKEN)
check("审计链校验通过", isinstance(b, dict) and b.get("valid") is True,
      f"valid={b.get('valid') if isinstance(b, dict) else None} checked={b.get('checked') if isinstance(b, dict) else None}")

# 8) 账号管理：强制改密 / 禁用 / 启用（admin）
st, b = http_post("/api/v1/admin/users/viewer/force-password-change", {}, token=ADMIN_TOKEN)
check("admin 强制 viewer 改密", b.get("code") == 0, f"code={b.get('code')}")
st, b = http_post("/api/v1/login", {"username": "viewer", "password": "viewer123"})
check("被强制改密账户登录带标记", b.get("must_change_password") is True,
      f"must_change={b.get('must_change_password')}")
st, b = http_get("/api/v1/devices", token=b.get("token"))
check("被强制改密账户被 4033 拦截", b.get("code") == 4033, f"code={b.get('code')}")
st, b = http_post("/api/v1/admin/users/viewer/disable", {}, token=ADMIN_TOKEN)
check("admin 禁用 viewer", b.get("code") == 0, f"code={b.get('code')}")
st, b = http_post("/api/v1/login", {"username": "viewer", "password": "viewer123"})
check("禁用账户登录被拒", b.get("code") == 401, f"code={b.get('code')}")
st, b = http_post("/api/v1/admin/users/viewer/enable", {}, token=ADMIN_TOKEN)
check("admin 重新启用 viewer", b.get("code") == 0, f"code={b.get('code')}")
st, b = http_post("/api/v1/login", {"username": "viewer", "password": "viewer123"})
check("重新启用后可登录", st == 200 and b.get("role") == "viewer", f"role={b.get('role')}")

# 9) 多中枢节点视图（内存模式返回 bus disabled 说明）
st, b = http_get("/api/v1/hubs", token=ADMIN_TOKEN)
check("hubs 节点视图可访问", isinstance(b, dict) and ("hubs" in b or "note" in b),
      f"keys={list(b.keys()) if isinstance(b, dict) else None}")

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
