mod catalog;
mod desktop;
mod firewall;
mod logger;
mod netinfo;
mod pairing;
mod presence;
mod server;
mod transfer;

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // Single instance: if one is already running, a second launch only brings
    // the old window to the front instead of starting a new server. Keyed by
    // bundle id, NOT exe path — launching a copy from another folder focuses
    // the running one (no second server, no shared-catalog race, no second
    // firewall verdict). Log the attempt with its cwd so a "wrong copy"
    // focus is explainable from the log instead of mysterious.
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, cwd| {
            crate::logger::logf(&format!(
                "second launch from {cwd} — already running, focused existing window",
            ));
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
            // The channel carries back the actual port (falls forward when 7765
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
            // Keep Tauri's drag-drop handler ENABLED: it injects the real
            // `path` onto dropped File objects (that is what lets the frontend
            // send the path to /add-local, which copies it into Inbox locally
            // instead of the phone uploading a copy). It also preventDefaults
            // the drop, so no navigation to the file.
            .build()?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
