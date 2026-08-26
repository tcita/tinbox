mod catalog;
mod firewall;
mod logger;
mod server;

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // Single instance: if one is already running, a second launch only brings
    // the old window to the front instead of starting a new server.
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
            // Start axum first and wait for the port to bind before creating the
            // window that loads that page; otherwise the window shows a blank
            // page / connection error because it loads before the server is up.
            // The channel carries back the actual port (falls forward when 8765
            // is taken), and the window uses it to build the URL.
            let ready = server::spawn(app.handle().clone());
            let port = ready.blocking_recv().ok().flatten().unwrap_or_else(|| {
                crate::logger::logf("local server failed to start, exiting");
                std::process::exit(1);
            });

            // Run the firewall check on a background thread so it does not block
            // window creation (a cold powershell start can hang for seconds).
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
            .disable_drag_drop_handler() // let HTML5 drag-and-drop upload work, not intercepted by Tauri
            .build()?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
