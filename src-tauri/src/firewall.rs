// Windows 防火墙自处理:解决"首次弹窗误点取消 → 生成 Block 入站规则 → 手机永久连不上,
// 且普通用户在'允许应用通过防火墙'界面删不掉 Block"的问题。
//
// 机制(普通权限只能读规则,New/Remove 都要管理员):
//   1. ensure():启动前只读检测——有没有针对自己 exe 的 Block 规则(上次会话遗留)?
//      有则标记 PENDING_REPAIR。同时读取上次修复遗留的 result 文件记日志。
//   2. prompt_repair_if_needed():窗口就绪后,若标记了修复,弹 MessageBox(是/否);
//      点"是" → 写临时 .ps1 → Start-Process -Verb RunAs 触发 UAC,提权执行:
//      删所有针对本 exe 的 Block + 补一条 Allow。规则变更即时生效,同一会话手机即可连上。
//   3. schedule_post_startup_check():启动后轮询 ~30s——因为 Windows 防火墙弹窗在
//      bind 时才出现,ensure() 跑在 bind 前检测不到"当次新建"的 block。轮询能在用户
//      当次点取消生成 block 后,几秒内就弹修复框,不让本次会话白白失效。
//
// 用临时 .ps1 文件而非 -ArgumentList 传脚本,避开引号/花括号转义在命令行传递中被破坏。
// 仅 Windows 生效;其它平台为空操作。
use crate::logger::logf;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

const RULE_ALLOW: &str = "tinbox_Allow_Inbound";

#[cfg(windows)]
fn exe_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

/// exe 同级目录,用于放临时 .ps1 与 result 文件。
#[cfg(windows)]
fn data_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Windows 进程创建标志:CREATE_NO_WINDOW,避免拉起 powershell 时闪控制台窗口。
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// 运行一段 PowerShell,返回 (是否成功, stdout)。用 CREATE_NO_WINDOW 避免闪终端。
#[cfg(windows)]
fn run_ps(script: &str) -> Option<(bool, String)> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => {
            let ok = o.status.success();
            if !ok {
                let err = String::from_utf8_lossy(&o.stderr);
                logf(&format!("ps 失败: stderr={}", err.trim()));
            }
            Some((ok, String::from_utf8_lossy(&o.stdout).to_string()))
        }
        Err(e) => {
            logf(&format!("无法启动 powershell: {}", e));
            None
        }
    }
}

/// 是否存在针对自己 exe 的 Block 入站规则;返回命中规则名。
#[cfg(windows)]
fn find_block_rule(exe: &str) -> Option<String> {
    let ps = format!(
        r#"$exe = '{exe}'
$name = ''
Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue | ForEach-Object {{
  $f = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
  if ($f -and $f.Program -ieq $exe) {{ $name = $_.DisplayName }}
}}
$name"#
    );
    match run_ps(&ps) {
        Some((true, out)) => {
            let s = out.trim();
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        }
        _ => None,
    }
}

/// 是否存在自己的 Allow 入站规则(只读)。
#[cfg(windows)]
fn has_allow_rule() -> bool {
    let ps = format!(
        "[bool](Get-NetFirewallRule -DisplayName '{RULE_ALLOW}' -ErrorAction SilentlyContinue)"
    );
    matches!(run_ps(&ps), Some((true, ref s)) if s.trim().eq_ignore_ascii_case("true"))
}

static PENDING_REPAIR: AtomicBool = AtomicBool::new(false);

/// 入口:后台执行防火墙检测,不阻塞 setup/窗口创建(否则 powershell 冷启动会卡数秒)。
/// 检测到 Block → 标记 PENDING_REPAIR + 置顶窗口,前端轮询 /fw-status 显示 HTML 修复浮层。
/// 无 Block 但缺 Allow → 启动后轮询(等 Windows 弹窗被响应)。
pub fn ensure_background(app: AppHandle) {
    #[cfg(windows)]
    {
        std::thread::spawn(move || {
            let Some(exe) = exe_path() else {
                logf("防火墙:取不到 exe 路径,跳过");
                return;
            };
            // 先检测启动前是否已存在 Block(上次遗留)。
            if let Some(name) = find_block_rule(&exe) {
                let has_allow = has_allow_rule();
                logf(&format!(
                    "防火墙需要修复:检测到 Block 入站规则 name={name}(allow共存={has_allow})"
                ));
                mark_need_repair(&app);
                return; // 已有 pre-existing block,前端会显示浮层,不再轮询。
            }
            if has_allow_rule() {
                logf("防火墙状态正常:存在 Allow,无 Block");
                return;
            }
            // 缺 Allow 但无 Block:Windows bind 时才弹询问框,启动后轮询等用户响应。
            logf("防火墙:暂无 Allow 规则,启动后轮询等 Windows 弹窗响应");
            post_startup_poll(&app, &exe);
        });
    }
    #[cfg(not(windows))]
    {
        let _ = app;
    }
}

/// 启动后轮询:bind 时 Windows 才弹防火墙询问框,检测不到当次新建的 block。
/// 每 3s 查一次、持续约 30s,发现 block 立即标记需修复(前端显示浮层)。
#[cfg(windows)]
fn post_startup_poll(app: &AppHandle, exe: &str) {
    // 给 Windows 弹窗一点时间出现并被用户响应。
    std::thread::sleep(std::time::Duration::from_secs(2));
    for _ in 0..10 {
        if PENDING_REPAIR.load(Ordering::SeqCst) {
            return;
        }
        if let Some(name) = find_block_rule(exe) {
            logf(&format!(
                "启动后轮询检测到 Block 入站规则 name={name},标记需修复"
            ));
            mark_need_repair(app);
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    // 30s 内未出现 block:用户多半点了允许或未弹窗,正常。
}

/// 标记需修复 + 置顶窗口,确保用户看到前端的 HTML 修复浮层(不会被最小化/遮挡错过)。
#[cfg(windows)]
fn mark_need_repair(app: &AppHandle) {
    PENDING_REPAIR.store(true, Ordering::SeqCst);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
        let _ = w.set_always_on_top(true);
    }
}

/// 前端查:是否需要显示防火墙修复浮层。
/// 实际查 Block 规则是否还在(而非缓存标志),这样修复后浮层能正确消失。
pub fn need_repair() -> bool {
    #[cfg(windows)]
    {
        let Some(exe) = exe_path() else { return false; };
        // 标志位为 false 直接返回(避免每次都拉 powershell);为 true 时实查确认。
        if !PENDING_REPAIR.load(Ordering::SeqCst) {
            return false;
        }
        let still_blocked = find_block_rule(&exe).is_some();
        if !still_blocked {
            // Block 已消失(修复成功):清标志。
            PENDING_REPAIR.store(false, Ordering::SeqCst);
        }
        still_blocked
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// 前端点"修复":拉起 UAC 提权脚本删 Block 补 Allow。返回是否拉起成功。
pub fn repair() -> bool {
    #[cfg(windows)]
    {
        let Some(exe) = exe_path() else { return false; };
        repair_as_admin(&exe)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// 前端点"退出":无法联网则无意义,直接退出。
pub fn quit(app: &AppHandle) {
    logf("用户选择退出(未修复)");
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.close();
    }
    std::process::exit(0);
}

/// 写一个临时 .ps1,用 Start-Process -Verb RunAs -Wait 触发 UAC 提权执行:
/// 删所有针对本 exe 的 Block + 补一条 Allow。用 -Wait 阻塞到脚本结束(=UAC 授权 + 删 Block 完成),
/// 返回前实查 Block 是否真删,给前端确定的结果,不让前端猜时间/轮询。
///
/// 阻塞调用线程:但此时前端 modal 挡着界面,用户就是在等修复,阻塞合理。
#[cfg(windows)]
fn repair_as_admin(exe: &str) -> bool {
    let dir = data_dir();
    let ps1 = dir.join("tinbox_fw_fix.ps1");

    // 脚本自包含:删 Block + 补 Allow,最后自删 ps1。
    // 注意:Get-NetFirewallRule 的 -DisplayName 不能与 -Direction/-Action 混用(不同参数集)。
    let script = format!(
        r#"$exe = '{exe}'
try {{
  Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue | ForEach-Object {{
    $f = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    if ($f -and $f.Program -ieq $exe) {{
      Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    }}
  }}
  Get-NetFirewallRule -DisplayName '{RULE_ALLOW}' -ErrorAction SilentlyContinue | ForEach-Object {{
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
  }}
  # 一次性迁移:清理旧版(filedrop 时代)的允许规则,避免孤儿规则残留。
  Get-NetFirewallRule -DisplayName 'FileDrop_Allow_Inbound' -ErrorAction SilentlyContinue | ForEach-Object {{
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
  }}
  New-NetFirewallRule -DisplayName '{RULE_ALLOW}' -Direction Inbound -Action Allow -Program $exe -Profile Any -ErrorAction Stop | Out-Null
}} catch {{
  Write-Host ('FAIL:' + $_.Exception.Message)
}}
Remove-Item $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue"#
    );
    if std::fs::write(&ps1, &script).is_err() {
        logf("修复:写临时 ps1 失败");
        return false;
    }

    use std::os::windows::process::CommandExt;
    use std::process::Command;
    // -Wait:阻塞到提权脚本结束(UAC 授权后才执行,执行完才返回)。
    // -WindowStyle Hidden:提权 PowerShell 窗口隐藏,只留 UAC 框。
    let launcher = format!(
        "Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','{}' -Verb RunAs -Wait",
        ps1.to_string_lossy()
    );
    let launched = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &launcher])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok();
    // 拉起失败(用户在 UAC 取消):launcher 的 Start-Process 会报错,output 仍返回但非 0。
    // 真正的成功判据:实查 Block 是否还在。在就说明没修成(取消 UAC 或脚本失败)。
    let fixed = find_block_rule(exe).is_none();
    logf(&format!(
        "修复: 拉起={}, Block是否已删={}",
        if launched { "是" } else { "否" },
        if fixed { "是(成功)" } else { "否(未修成)" }
    ));
    fixed
}

// 抑制非 windows 下未使用告警。
#[allow(dead_code)]
fn _silence() {
    let _ = Mutex::new(());
    let _ = PathBuf::new();
}
