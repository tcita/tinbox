// Video posters: after a file is at rest in inbox, ask Windows Shell for a
// thumbnail (the same IShellItemImageFactory pipeline Explorer uses) and
// store the JPEG under data_root/posters/{id}.jpg. Production lives in the
// server process — not the webview, not the sending phone — so every
// entrance (phone upload, PC add-local, orphan adoption, startup backfill)
// is the same job. Failure is silent and the timeline row stays compact;
// success flips catalog.poster and pushes List so both ends rebuild the
// card as a brick. Sidecars live outside inbox so reconcile never adopts
// them as messages.

use crate::catalog;
use crate::logger::logf;
use crate::media::is_video_name;
use crate::server::{notifier, PushEvent};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Mutex, OnceLock};

struct Job {
    id: String,
    path: PathBuf,
}

static TX: OnceLock<Mutex<Option<mpsc::Sender<Job>>>> = OnceLock::new();

fn poster_dir() -> PathBuf {
    crate::logger::data_root().join("posters")
}

pub fn path_for(id: &str) -> PathBuf {
    poster_dir().join(format!("{id}.jpg"))
}

pub fn unlink(id: &str) {
    let _ = std::fs::remove_file(path_for(id));
}

pub fn clear_all() {
    let _ = std::fs::remove_dir_all(poster_dir());
}

/// Queue a poster extract if this is a video. No-op for other types, missing
/// files, or a sidecar that already exists (that path just marks catalog).
pub fn request(id: &str, path: &Path, name: &str) {
    if !is_video_name(name) {
        return;
    }
    enqueue(Job {
        id: id.to_string(),
        path: path.to_path_buf(),
    });
}

/// Startup: drop poster files whose message is gone, then queue every video
/// that still has no sidecar. Serial — one Shell call at a time.
pub fn backfill() {
    let known: std::collections::HashSet<String> = catalog::all_items()
        .into_iter()
        .map(|i| i.id)
        .collect();
    if let Ok(rd) = std::fs::read_dir(poster_dir()) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".jpg") else {
                continue;
            };
            if !known.contains(id) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let mut queued = 0usize;
    for it in catalog::all_items() {
        if it.kind != "file" || it.pending || !is_video_name(&it.name) {
            continue;
        }
        if it.poster && path_for(&it.id).is_file() {
            continue;
        }
        let Some(entry) = catalog::find(&it.id) else {
            continue;
        };
        let path = match &entry.body {
            catalog::MsgBody::File { source, .. } => PathBuf::from(source.path()),
            catalog::MsgBody::Text { .. } => continue,
        };
        request(&it.id, &path, &it.name);
        queued += 1;
    }
    if queued > 0 {
        logf(&format!(
            "poster: backfill queued {queued} video{}",
            if queued == 1 { "" } else { "s" }
        ));
    }
}

fn enqueue(job: Job) {
    let slot = TX.get_or_init(|| Mutex::new(None));
    let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("tinbox-poster".into())
            .spawn(move || worker(rx))
            .ok();
        *guard = Some(tx);
    }
    if let Some(tx) = guard.as_ref() {
        let _ = tx.send(job);
    }
}

fn worker(rx: mpsc::Receiver<Job>) {
    #[cfg(windows)]
    unsafe {
        let _ = windows::Win32::System::Com::CoInitializeEx(
            None,
            windows::Win32::System::Com::COINIT_APARTMENTTHREADED,
        );
    }
    while let Ok(job) = rx.recv() {
        if path_for(&job.id).is_file() {
            mark_ready(&job.id);
            continue;
        }
        if !job.path.is_file() {
            continue;
        }
        let Some(bytes) = extract(&job.path) else {
            continue;
        };
        if std::fs::create_dir_all(poster_dir()).is_err() {
            continue;
        }
        let dest = path_for(&job.id);
        let tmp = dest.with_extension("jpg.tmp");
        if std::fs::write(&tmp, &bytes).is_err() {
            let _ = std::fs::remove_file(&tmp);
            continue;
        }
        if std::fs::rename(&tmp, &dest).is_err() {
            let _ = std::fs::remove_file(&tmp);
            continue;
        }
        if catalog::find(&job.id).is_none() {
            let _ = std::fs::remove_file(&dest);
            continue;
        }
        logf(&format!(
            "poster: extracted {} ({} KB)",
            job.id,
            bytes.len() / 1024
        ));
        mark_ready(&job.id);
    }
}

fn mark_ready(id: &str) {
    if catalog::set_poster(id, true) {
        let _ = notifier().send(PushEvent::List(catalog::all_items()));
    }
}

#[cfg(not(windows))]
fn extract(_path: &Path) -> Option<Vec<u8>> {
    None
}

#[cfg(windows)]
fn extract(path: &Path) -> Option<Vec<u8>> {
    extract_shell(path)
}

#[cfg(windows)]
fn extract_shell(path: &Path) -> Option<Vec<u8>> {
    use windows::core::{Interface, HSTRING};
    use windows::Win32::Foundation::SIZE;
    use windows::Win32::Graphics::Gdi::{
        DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO,
        BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HGDIOBJ,
    };
    use windows::Win32::UI::Shell::{
        IShellItem, IShellItemImageFactory, SHCreateItemFromParsingName, SIIGBF_BIGGERSIZEOK,
        SIIGBF_RESIZETOFIT, SIIGBF_THUMBNAILONLY,
    };

    let path_s = HSTRING::from(path.to_string_lossy().as_ref());
    let rgb = unsafe {
        let item: IShellItem = SHCreateItemFromParsingName(&path_s, None).ok()?;
        let factory: IShellItemImageFactory = item.cast().ok()?;
        let hbmp = factory
            .GetImage(
                SIZE { cx: 320, cy: 320 },
                SIIGBF_RESIZETOFIT | SIIGBF_THUMBNAILONLY | SIIGBF_BIGGERSIZEOK,
            )
            .ok()?;
        let hdc = GetDC(None);
        if hdc.0.is_null() {
            let _ = DeleteObject(HGDIOBJ(hbmp.0));
            return None;
        }
        let mut bm = BITMAP::default();
        if GetObjectW(
            HGDIOBJ(hbmp.0),
            std::mem::size_of::<BITMAP>() as i32,
            Some((&mut bm as *mut BITMAP).cast()),
        ) == 0
        {
            ReleaseDC(None, hdc);
            let _ = DeleteObject(HGDIOBJ(hbmp.0));
            return None;
        }
        let w = bm.bmWidth;
        let h = bm.bmHeight.unsigned_abs() as i32;
        if w <= 0 || h == 0 {
            ReleaseDC(None, hdc);
            let _ = DeleteObject(HGDIOBJ(hbmp.0));
            return None;
        }
        let mut info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bgra = vec![0u8; (w as usize) * (h as usize) * 4];
        let got = GetDIBits(
            hdc,
            hbmp,
            0,
            h as u32,
            Some(bgra.as_mut_ptr() as *mut core::ffi::c_void),
            &mut info,
            DIB_RGB_COLORS,
        );
        ReleaseDC(None, hdc);
        let _ = DeleteObject(HGDIOBJ(hbmp.0));
        if got == 0 {
            return None;
        }
        let mut rgb = Vec::with_capacity((w as usize) * (h as usize) * 3);
        for px in bgra.chunks_exact(4) {
            rgb.push(px[2]);
            rgb.push(px[1]);
            rgb.push(px[0]);
        }
        (w as u32, h as u32, rgb)
    };
    let (w, h, rgb) = rgb;
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 80)
        .encode(&rgb, w, h, image::ExtendedColorType::Rgb8)
        .ok()?;
    Some(out)
}
