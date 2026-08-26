mod catalog;
mod firewall;
mod logger;
mod server;

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // 单实例:已有实例在跑时,第二次启动只把旧窗口前置,不重复起服务。
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
                let _ = w.unminimize();
            }
        }));
    }

    builder
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // 先起 axum,等端口 bind 成功,再创建窗口加载该页面,
            // 否则窗口先于服务器加载会出空白/连接错误。
            // channel 传回实际端口(8765 被占用时会顺延),窗口用它拼 URL。
            let ready = server::spawn(app.handle().clone());
            let port = ready.blocking_recv().ok().flatten().unwrap_or_else(|| {
                crate::logger::logf("本地服务器启动失败,退出");
                std::process::exit(1);
            });

            // 防火墙检测放后台线程,不阻塞窗口创建(powershell 冷启动会卡数秒)。
            firewall::ensure_background(app.handle().clone());

            WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::External(format!("http://localhost:{port}").parse().unwrap()),
            )
            .title("tinbox")
            .inner_size(520.0, 720.0)
            .min_inner_size(360.0, 480.0)
            .center()
            .disable_drag_drop_handler() // 让 HTML5 拖拽上传生效,不经 Tauri 拦截
            .build()?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
