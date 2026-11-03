#!/usr/bin/env python3
# 御端 PostgreSQL / 多中枢总线 端到端验证（仅依赖标准库 + 本机 PostgreSQL）。
# 覆盖：initdb 本地实例 → 双 Hub 共享 PG → 跨实例指令总线（去粘性）→ PG 持久化（重启不丢）
#       → WORM 触发器（SQL 层禁改删）→ 审计链校验 → 参数化查询（注入串安全落库）。
import json, os, shutil, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
HUB = os.path.join(DEV, "bin", "hub")
AGENT = os.path.join(DEV, "bin", "agent")
PGDATA = "/tmp/yuduan-pg-data"
PORT = 55432
DSN = f"host=127.0.0.1 port={PORT} user=yuduan dbname=yuduan password=yuduan"
SECRET = "e2e-secret"
NEW_PW = "Admin@2026x"

results = []
def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(("PASS " if cond else "FAIL ") + name + ("  " + detail if detail else ""))

def psql(sql, db="yuduan", user="yuduan", expect_fail=False):
    """执行一条 SQL，返回 (returncode, stdout)"""
    p = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(PORT), "-U", user, "-d", db,
                        "-v", "ON_ERROR_STOP=1", "-tAc", sql],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, (p.stdout + p.stderr).strip()

def http_get(path, token=None, base="http://127.0.0.1:8080"):
    req = urllib.request.Request(base + path)
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}

def http_post(path, data, token=None, base="http://127.0.0.1:8080"):
    req = urllib.request.Request(base + path, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=130) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}

def start_hub(port, hub_id, log_name):
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_DB_DSN=DSN,
               YUDUAN_HUB_ADDR=f":{port}", YUDUAN_TLS_ADDR="", YUDUAN_HUB_ID=hub_id,
               YUDUAN_REPO="/tmp/yuduan-pg-e2e-repo")
    log = open(f"/tmp/yuduan-e2e-{log_name}.log", "w")
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=log, stderr=subprocess.STDOUT, text=True)

def wait_hub(port, timeout=20):
    # 探测：POST 登录接口返回 JSON（含 code）即服务就绪
    for _ in range(timeout * 2):
        st, b = http_post("/api/v1/login", {"username": "probe", "password": "probe"},
                          base=f"http://127.0.0.1:{port}")
        if st == 200 and isinstance(b, dict) and "code" in b:
            return True
        time.sleep(0.5)
    return False

def wait_device(token, base, timeout=30):
    for _ in range(timeout * 2):
        st, body = http_get("/api/v1/devices", token=token, base=base)
        if st == 200:
            online = [d for d in body.get("devices", []) if d.get("online")]
            if online:
                online.sort(key=lambda d: d.get("last_heartbeat", ""), reverse=True)
                return online[0]
        time.sleep(0.5)
    return None

def login_admin(base):
    # 兼容重复执行：admin123 失败说明上次已改密，用新口令登
    st, body = http_post("/api/v1/login", {"username": "admin", "password": "admin123"}, base=base)
    if body.get("code") == 401:
        st, body = http_post("/api/v1/login", {"username": "admin", "password": NEW_PW}, base=base)
    tok = body.get("token")
    if body.get("must_change_password"):
        st, body = http_post("/api/v1/password", {"old_password": "admin123", "new_password": NEW_PW},
                             token=tok, base=base)
        tok = body.get("token") or tok
    return tok

# ===================== 1. 本地 PostgreSQL =====================
if not os.path.exists(PGDATA):
    print("[pg] initdb …")
    subprocess.run(["initdb", "-D", PGDATA, "-A", "trust", "-U", "postgres"],
                   capture_output=True, check=True)
# 确保 host 信任（initdb -A trust 已含 127.0.0.1/32 trust；重复执行幂等）
def pg_running():
    return subprocess.run(["pg_ctl", "-D", PGDATA, "status"], capture_output=True).returncode == 0

if not pg_running():
    print("[pg] 启动 PostgreSQL …")
    for attempt in range(3):
        p = subprocess.run(["pg_ctl", "-D", PGDATA, "-l", "/tmp/yuduan-pg.log",
                            "-o", f"-p {PORT} -k /tmp"], capture_output=True, text=True)
        if p.returncode == 0:
            break
        print(f"[pg] 启动重试 {attempt + 1}: {p.stdout.strip()} {p.stderr.strip()}")
        time.sleep(1)
for _ in range(40):
    rc, _ = psql("SELECT 1", db="postgres", user="postgres")
    if rc == 0: break
    time.sleep(0.5)
rc, out = psql("SELECT 1", db="postgres", user="postgres")
check("PostgreSQL 本地实例就绪", rc == 0, f"rc={rc}")

rc, out = psql("SELECT 1 FROM pg_roles WHERE rolname='yuduan'", db="postgres", user="postgres")
if out.strip() != "1":
    psql("CREATE ROLE yuduan LOGIN", db="postgres", user="postgres")
rc, out = psql("SELECT 1 FROM pg_database WHERE datname='yuduan'", db="postgres", user="postgres")
if out.strip() != "1":
    psql("CREATE DATABASE yuduan OWNER yuduan", db="postgres", user="postgres")
rc, out = psql("SELECT 1")
check("yuduan 角色/库就绪", rc == 0, f"rc={rc} out={out[:40]}")

# ===================== 2. 双 Hub 共享 PG =====================
# 清库重建（保证哈希链口径切换后可重复执行）
psql("DROP TABLE IF EXISTS audit_events, devices, users, cmd_outbox, hub_nodes CASCADE")
psql("DROP FUNCTION IF EXISTS yuduan_audit_worm() CASCADE")

hubA = start_hub(8080, "hub-a", "hub-a")
hubB = start_hub(8081, "hub-b", "hub-b")
check("hub-a 启动(PG)", wait_hub(8080))
check("hub-b 启动(PG)", wait_hub(8081))

TOKEN = login_admin("http://127.0.0.1:8080")
check("hub-a 登录+改密", bool(TOKEN))

# ===================== 3. 跨实例指令总线（去粘性） =====================
# 副端只连 hub-b；运维在 hub-a 下发指令 → outbox → b 认领执行 → 结果回传 a
env = dict(os.environ, YUDUAN_HUB="ws://127.0.0.1:8081/ws/agent", YUDUAN_HMAC_SECRET=SECRET)
agent = subprocess.Popen([AGENT], cwd=DEV, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
dev = wait_device(TOKEN, "http://127.0.0.1:8080")  # 经 hub-a 查看（共享库可见 b 的设备）
check("副端经 hub-b 注册、hub-a 可见(PG共享)", dev is not None, f"device={dev['id'] if dev else None}")

if dev:
    st, b = http_post(f"/api/v1/devices/{dev['id']}",
                      {"action": "shell", "command": "echo bus_desticky_ok"}, token=TOKEN)
    out = b.get("output_log", "") if isinstance(b, dict) else ""
    check("跨实例指令总线执行(hub-a下发/b hub-b执行)", isinstance(b, dict) and b.get("state") == "success"
          and "bus_desticky_ok" in out, f"state={b.get('state')} out={out[:60]}")

    # 参数化查询安全：直接以 SQL 注入串作为主机名落库，API 参数化读取不炸表
    rc, _ = psql(f"INSERT INTO devices (id, hostname, os, online, last_seen) "
                 f"VALUES ('inj-test', 'x''); DROP TABLE devices;--', 'linux', false, now()) "
                 f"ON CONFLICT (id) DO UPDATE SET hostname = EXCLUDED.hostname")
    check("注入串直接入库(准备)", rc == 0, f"rc={rc}")
    st, b = http_get("/api/v1/devices", token=TOKEN)
    inj = [d for d in b.get("devices", []) if d.get("id") == "inj-test"]
    check("参数化查询读取注入串且 devices 表完好", st == 200 and len(inj) == 1
          and inj[0].get("hostname") == "x'); DROP TABLE devices;--",
          f"hostname={inj[0].get('hostname') if inj else None}")
    psql("DELETE FROM devices WHERE id='inj-test'")

# ===================== 4. 多中枢节点视图 =====================
time.sleep(6)  # 心跳 5s
st, b = http_get("/api/v1/hubs", token=TOKEN)
hub_ids = {n.get("id") for n in b.get("hubs", [])} if isinstance(b, dict) else set()
check("hubs 视图含双节点(心跳)", {"hub-a", "hub-b"} <= hub_ids, f"hubs={sorted(hub_ids)}")

# ===================== 5. WORM 触发器 =====================
rc, out = psql("UPDATE audit_events SET result='tampered' WHERE id=1")
check("WORM: SQL UPDATE 被触发器拒绝", rc != 0 and ("WORM" in out or "not allowed" in out), f"rc={rc} out={out[:80]}")
rc, out = psql("DELETE FROM audit_events WHERE id=1")
check("WORM: SQL DELETE 被触发器拒绝", rc != 0 and ("WORM" in out or "not allowed" in out), f"rc={rc} out={out[:80]}")

# ===================== 6. 审计链校验 =====================
st, b = http_get("/api/v1/audit/verify", token=TOKEN)
check("PG 审计链校验通过", isinstance(b, dict) and b.get("valid") is True,
      f"valid={b.get('valid')} checked={b.get('checked')}")

# ===================== 7. PG 持久化：重启 hub-a 数据不丢 =====================
audit_before = http_get("/api/v1/audit", token=TOKEN)[1].get("total")
dev_before = http_get("/api/v1/devices", token=TOKEN)[1].get("total")
hubA.terminate(); hubA.wait()
time.sleep(1.0)
hubA = start_hub(8080, "hub-a", "hub-a-restart")
check("hub-a 重启(PG)", wait_hub(8080))
TOKEN2 = login_admin("http://127.0.0.1:8080")
st, b = http_get("/api/v1/devices", token=TOKEN2)
check("重启后设备台账保留(PG)", st == 200 and b.get("total", 0) >= dev_before,
      f"before={dev_before} after={b.get('total')}")
st, b = http_get("/api/v1/audit", token=TOKEN2)
check("重启后审计记录保留(PG)", st == 200 and b.get("total", 0) >= audit_before,
      f"before={audit_before} after={b.get('total')}")
st, b = http_get("/api/v1/audit/verify", token=TOKEN2)
check("重启后审计链仍有效", isinstance(b, dict) and b.get("valid") is True)

# 收尾
agent.terminate(); agent.wait()
hubA.terminate(); hubB.terminate()
print("\n==== 汇总 ====")
passed = sum(1 for _, c, _ in results if c)
print(f"{passed}/{len(results)} 通过")
fails = [n for n, c, _ in results if not c]
if fails:
    print("失败项: " + ", ".join(fails))
    sys.exit(1)
print("ALL PASS")
