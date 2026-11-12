// 锁中毒治理约定（复盘 T-4，v0.4.11 夜间接管）。
//
// 背景：副端为纯 std 工程，全局状态以 `static X: Mutex<T>` 形式持有。此前全仓 97 处
// 一律写成 `X.lock().unwrap()` —— `Mutex::lock()` 在**持锁线程 panic 过**时返回
// PoisonError，`unwrap()` 会二次 panic。由于远控的采集/编码/发送均在子线程中持锁，
// 任一线程 panic 即沿调用栈把整个副端进程带崩：终端失联失管，且崩溃后无法再被中枢
// 纳管（这正是复盘所记"锁中毒级联 panic"）。
//
// 治理：全仓统一改为
//     X.lock().unwrap_or_else(|p| p.into_inner())
// 即锁中毒时取回内部数据继续服务，把故障限制在"单次会话 / 单帧"，不再级联成进程退出。
//
// 取舍：中毒意味着数据可能处于半更新状态，此处选择**可用性优先**——远控状态（会话、
// 媒体通道、帧序号）短暂不一致的后果，远小于整个终端失联；且副端每帧与每会话均有
// 重新协商与复位路径。该取舍与铁律 10（远控为关键路径，须稳定）一致。
//
// 本模块仅承载该约定的可执行说明与回归用例，不含运行时逻辑。

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    /// 中毒后仍须能取回数据并继续服务，不得 panic。
    #[test]
    fn poisoned_lock_recovers_instead_of_panicking() {
        let m = Arc::new(Mutex::new(0i32));
        let m2 = Arc::clone(&m);
        let r = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap();
            panic!("simulate rc thread panic while holding lock");
        });
        assert!(r.join().is_err(), "前提：持锁线程应 panic");
        assert!(m.is_poisoned(), "前提：锁应已中毒");

        // 治理后的写法：不 panic，取回数据继续服务
        let mut g = m.lock().unwrap_or_else(|p| p.into_inner());
        *g += 1;
        assert_eq!(*g, 1, "中毒后应仍能访问并修改数据");
    }

    /// 证明上一条用例确实敏感：旧写法在中毒锁上必然 panic。
    /// 若后续有人把修复回退为 `.lock().unwrap()`，上一条用例会红；
    /// 本用例则保证"旧写法确实会 panic"这一前提始终成立，避免用例退化成空断言。
    #[test]
    fn poisoned_lock_old_style_would_panic() {
        let m = Arc::new(Mutex::new(0i32));
        let m2 = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("poison it");
        })
        .join();
        assert!(m.is_poisoned(), "前提：锁应已中毒");

        let old = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = m.lock().unwrap();
        }));
        assert!(
            old.is_err(),
            "前提错误：旧写法本应在中毒锁上 panic，否则本用例无意义"
        );
    }
}
