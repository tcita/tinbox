mod catalog;
mod desktop;
mod firewall;
mod logger;
mod media;
mod poster;
mod netinfo;
mod pairing;
mod presence;
mod server;
mod transfer;

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

#[cfg(desktop)]
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    WindowEvent,
};

/// Build the main window against the already-bound LAN server port, and arm
/// the close interceptor (desktop only — see below).
fn create_main_window<R: tauri::Runtime>(
    manager: &impl Manager<R>,
    port: u16,
) -> tauri::Result<tauri::WebviewWindow<R>> {
    let window = WebviewWindowBuilder::new(
        manager,
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

    // Close (x) DESTROYS the window instead of quitting: the LAN server (and
    // its pairing token) is process-lifetime, so a quit-on-close would force
    // the phone to rescan on every window reopen — while a merely hidden
    // webview keeps its renderer alive at ~hundreds of MB. Destroying frees
    // the whole WebView2 tree; the page is a stateless view (state replays
    // over /events on reload), so rebuilding later is cheap. Quitting stays
    // explicit via the tray menu / repair overlay.
    #[cfg(desktop)]
    {
        let doomed = window.clone();
        window.on_window_event(move |event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = doomed.destroy();
                crate::logger::logf(
                    "window destroyed on close (webview memory freed; server keeps running)",
                );
            }
        });
    }

    Ok(window)
}

/// Make sure the main window is on screen: focus it if present, rebuild it
/// if a tray-hide destroyed it. Serialized so a double-click / second launch
/// racing a rebuild cannot build the window twice.
#[cfg(desktop)]
pub(crate) fn ensure_main_window(app: &tauri::AppHandle) {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
        return;
    }
    let port = crate::server::BOUND_PORT
        .get()
        .copied()
        .unwrap_or(crate::server::PORT);
    match create_main_window(app, port) {
        Ok(_) => crate::logger::logf("tray: main window rebuilt"),
        Err(e) => crate::logger::loge(&format!("tray: could not rebuild main window: {e}")),
    }
}

/// Tray icon ("显示窗口" / "退出"): closing the window hides it to the tray,
/// so this is the only explicit quit path besides the repair overlay.
#[cfg(desktop)]
fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "显示窗口", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/32x32.png"))?;
    TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("tinbox")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => ensure_main_window(app),
            "quit" => {
                crate::logger::logf("tray: user chose to quit");
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Left-click (or double-click) restores the window; right-click
            // opens the menu (menu_on_left_click stays off).
            let restore = match event {
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } => true,
                TrayIconEvent::DoubleClick { .. } => true,
                _ => false,
            };
            if restore {
                ensure_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

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
            // The window may be tray-destroyed, not just minimized.
            ensure_main_window(app);
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

            let _window = create_main_window(app, port)?;

            #[cfg(desktop)]
            if let Err(e) = build_tray(app.handle()) {
                crate::logger::loge(&format!("tray: could not build tray icon: {e}"));
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building app")
        .run(|_app_handle, event| {
            // Destroying the last window fires ExitRequested{code: None} and
            // would end the process (the tray icon does NOT keep it alive).
            // Prevent exactly that: a closed window means "tray-hide", the LAN
            // server keeps serving. Programmatic exits (tray Quit / restart,
            // code Some) pass through untouched.
            if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() {
                    api.prevent_exit();
                }
            }
        });
}
