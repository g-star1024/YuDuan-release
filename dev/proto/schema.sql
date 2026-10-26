-- 御端 · 数据模型（M1 冻结基线 v1）
-- 引擎：PostgreSQL 14+
-- 命名：snake_case；主键 uuid；时间用 timestamptz

-- 组织架构
CREATE TABLE org_units (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  parent_id   UUID REFERENCES org_units(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 设备资产
CREATE TABLE devices (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  hostname        TEXT NOT NULL,
  os              TEXT NOT NULL,            -- windows / macos / linux
  os_version      TEXT,
  arch            TEXT,                     -- x86_64 / arm64
  cpu             TEXT,
  memory_gb       INT,
  disk_gb         INT,
  serial_no       TEXT,
  mac             TEXT,
  ip              TEXT,
  org_unit_id     UUID REFERENCES org_units(id),
  status          TEXT NOT NULL DEFAULT 'assigned', -- assigned/transferred/returned/scrapped
  agent_version   TEXT,
  last_heartbeat  TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_devices_org ON devices(org_unit_id);
CREATE INDEX idx_devices_status ON devices(status);

-- 硬件资产快照（变更追踪）
CREATE TABLE hardware_inventory (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id   UUID NOT NULL REFERENCES devices(id),
  cpu         TEXT, memory_gb INT, disk_gb INT,
  serial_no   TEXT, display   TEXT,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 软件资产
CREATE TABLE software_inventory (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id      UUID NOT NULL REFERENCES devices(id),
  name           TEXT NOT NULL,
  version        TEXT,
  vendor         TEXT,
  install_source TEXT,
  license_info   TEXT,
  discovered_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sw_device ON software_inventory(device_id);

-- 任务
CREATE TABLE tasks (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type           TEXT NOT NULL,  -- sw_install/file_push/script_run/policy
  creator_id     UUID,
  target_scope   JSONB NOT NULL, -- {kind:'device'|'group'|'all', ids:[...]}
  payload_json   JSONB NOT NULL,
  schedule_type  TEXT NOT NULL DEFAULT 'now', -- now/scheduled/idle
  scheduled_at   TIMESTAMPTZ,
  status         TEXT NOT NULL DEFAULT 'pending',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 任务结果
CREATE TABLE task_results (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  task_id      UUID NOT NULL REFERENCES tasks(id),
  device_id    UUID NOT NULL REFERENCES devices(id),
  state        TEXT NOT NULL,  -- pending/running/success/failed/skipped
  exit_code    INT,
  output_log   TEXT,
  finished_at  TIMESTAMPTZ,
  UNIQUE (task_id, device_id)
);

-- 远控会话
CREATE TABLE sessions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id   UUID,
  device_id     UUID NOT NULL REFERENCES devices(id),
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ,
  recording_path TEXT,
  approved_by   UUID,
  reason        TEXT
);
CREATE INDEX idx_sessions_device ON sessions(device_id);

-- 账号与角色（RBAC）
CREATE TABLE roles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  permissions JSONB NOT NULL DEFAULT '[]'
);
CREATE TABLE accounts (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username     TEXT UNIQUE NOT NULL,
  display_name TEXT,
  role_id      UUID REFERENCES roles(id),
  mfa_enabled  BOOLEAN NOT NULL DEFAULT true,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 审计日志
CREATE TABLE audit_logs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id     UUID,
  action       TEXT NOT NULL,
  target_type  TEXT,
  target_id    TEXT,
  detail_json  JSONB,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_time ON audit_logs(created_at);

-- 策略
CREATE TABLE policies (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         TEXT NOT NULL,
  kind         TEXT NOT NULL, -- software_allow/software_deny/patch/peripheral/remote
  rules_json   JSONB NOT NULL,
  scope        JSONB NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
