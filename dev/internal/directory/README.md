# 目录同步（AD / LDAP）

M6 的账号体系支持从企业目录（Active Directory / OpenLDAP）同步，避免手工维护后台账号。

## 架构

```
DirectorySource（抽象）
  ├── FileDirectory   —— 读取 JSON 目录导出（离线演示 / 验证用）
  └── LDAPDirectory   —— 真实 AD/LDAP（go-ldap，build tag `ldap` 隔离）

        ↓ SyncEngine（组名 -> RBAC 角色映射）

   auth.UserStore（RBAC 账号：admin / operator / viewer）
```

- 同步引擎与具体目录协议解耦：无论目录来自文件还是 LDAP，都先转为 `DirUser/DDirGroup`，再按 `RoleMapping` 落库。
- 角色优先级：`admin > operator > viewer`；用户所属多个映射组时取最高者；未命中任何组则默认 `viewer`。

## 验证（离线）

```bash
# hub 启动时带目录文件即可自动同步：
YUDUAN_DIR_FILE=./directory-sample.json ./bin/hub
# 或运行时触发：
curl -X POST http://127.0.0.1:8080/api/v1/dirsync -H 'Authorization: Bearer <admin-token>'
```

同步后 `alice`（yd-admins）→ admin，`bob` → operator，`carol` → viewer，`dave` → viewer（无组），`eve`（disabled）被跳过。

## 生产启用真实 LDAP

1. `go get github.com/go-ldap/ldap/v3`
2. 去掉 `ldap.go` 首行 `//go:build ldap`（或 `go build -tags ldap`）
3. 在 hub 配置中填入 `LDAP_HOST/PORT/BindDN/BindPwd/BaseDN`
4. **认证方式**：当前同步账户使用演示口令 `Synced@2026`。生产应改为目录认证（Kerberos / LDAP bind），由中枢代理校验口令后再签发本地会话令牌，避免本地存储目录口令。
