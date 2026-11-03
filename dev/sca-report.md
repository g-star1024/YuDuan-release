# 御端 SCA 软件成分分析报告

- 生成时间：2026-10-23T08:57:04Z
- 扫描根：/Users/huluobo/WorkBuddy/jiankong
- 判定：**PASS(with notes): 零第三方依赖；14 项需安全评审（unsafe/ffi/credential）**

## 1. 依赖成分（SBOM）

| 生态 | 组件 | 版本 | 直接依赖 |
|---|---|---|---|
| std | go-stdlib | 1.26 | true |
| std | rust-stdlib | edition2021 | true |

## 2. 安全发现

| 级别 | 类别 | 文件 | 行 | 说明 |
|---|---|---|---|---|
| warn | ffi | rust/agent/src/rc.rs | 34 | FFI 外部函数接口（需评审：参数封送/生命周期） |
| warn | ffi | rust/agent/src/rc.rs | 98 | FFI 外部函数接口（需评审：参数封送/生命周期） |
| warn | ffi | rust/agent/src/rc.rs | 107 | FFI 外部函数接口（需评审：参数封送/生命周期） |
| warn | unsafe | rust/agent/src/rc.rs | 342 | unsafe { |
| warn | unsafe | rust/agent/src/rc.rs | 403 | unsafe { |
| warn | unsafe | rust/agent/src/rc.rs | 499 | unsafe { |
| warn | unsafe | rust/agent/src/rc.rs | 602 | unsafe fn key_input(vk: u16, down: bool) -> win32::INPUT { |
| warn | ffi | rust/agent/src/tamper.rs | 211 | FFI 外部函数接口（需评审：参数封送/生命周期） |
| warn | unsafe | rust/agent/src/tamper.rs | 218 | unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) < 0 } |
| warn | ffi | rust/agent/src/tamper.rs | 224 | FFI 外部函数接口（需评审：参数封送/生命周期） |
| warn | unsafe | rust/agent/src/tamper.rs | 227 | unsafe { IsDebuggerPresent() != 0 } |
| warn | credential | dev/internal/auth/auth.go | 68 | secret = "yuduan-dev-secret" |
| info | credential | dev/internal/directory/ldap_test.go | 14 | Password = "Alice@2026" (测试文件) |
| info | credential | dev/internal/directory/ldap_test.go | 15 | Password = "Bob@2026" (测试文件) |
| info | credential | dev/internal/directory/ldap_test.go | 16 | Password = "Carol@2026" (测试文件) |
| info | credential | dev/internal/directory/ldap_test.go | 17 | Password = "Dave@2026" (测试文件) |
| info | credential | dev/internal/directory/ldap_test.go | 18 | Password = "Eve@2026" (测试文件) |
| warn | credential | rust/agent/src/secure.rs | 169 | secret = "diagsecret" |
| warn | credential | rust/agent/src/secure.rs | 192 | secret = "diagsecret" |

## 3. 结论

供应链攻击面收敛于语言标准库（Go stdlib / Rust stdlib）。
请对标注的 `unsafe` / `extern "C"`(FFI) / 硬编码凭据逐项进行安全评审；
生产环境应由 KMS/配置下发密钥，禁止源码硬编码。
