// The pairing gate: the per-process token behind the QR code, the cookie
// check, and the page served to every unpaired LAN visitor instead of the
// transfer page.

use axum::{
    extract::{ConnectInfo, Request},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::sync::OnceLock;
use crate::server::{notifier, PushEvent};
// ── Pairing token ─────────────────────────────────────────────────────────
// The QR code encodes http://IP:PORT/?t=<token>; a phone's first visit with the
// correct ?t= is handed a cookie and needs no further interaction. The PC's own
// window rides loopback and never needs the token. Token lifetime = process
// lifetime (no persistence): the app runs desk-range sessions of minutes to a
// few hours, so every restart is also a natural "expire all pairings" event,
// and knowing the bare IP:PORT on this LAN is not enough after a restart.
static REQ_TOKEN: OnceLock<String> = OnceLock::new();

/// The per-process pairing token, lazily generated on first use. 8 chars from
/// a 31-symbol alphabet without look-alike glyphs (~39.6 bits): the length is
/// for hand-typable manual phone entry when a scan fails, and the entropy is
/// plenty against LAN online guessing — every miss logs a 403 line, and any
/// restart rotates the token anyway. Bytes come straight from the OS CSPRNG
/// (rejection-sampled to keep the 31-way mapping unbiased); no hand-rolled
/// hashing anywhere in this pipeline.
pub(crate) fn request_token() -> &'static String {
    REQ_TOKEN.get_or_init(|| {
        const RAND_CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
        let mut buf = String::with_capacity(8);
        // 248 = 31 * 8: bytes above it are redrawn so no symbol is favored.
        while buf.len() < 8 {
            let mut chunk = [0u8; 16];
            getrandom::fill(&mut chunk).expect("OS randomness unavailable");
            for b in chunk {
                if buf.len() >= 8 {
                    break;
                }
                if b < 248 {
                    buf.push(RAND_CHARS[(b % 31) as usize] as char);
                }
            }
        }
        buf
    })
}

const COOKIE_NAME: &str = "tb_auth";

/// Deterministic axum query split: token is alnum-only, so a plain byte check
/// needs no percent-decoding.
fn query_has_token(q: Option<&str>, tok: &str) -> bool {
    let Some(q) = q else { return false };
    q.split('&').any(|kv| match kv.split_once('=') {
        Some((k, v)) => k == "t" && v == tok,
        None => false,
    })
}

fn cookie_carries_token(headers: &HeaderMap, tok: &str) -> bool {
    headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        .map_or(false, |c| {
            c.split(';').any(|p| {
                let p = p.trim();
                match p.split_once('=') {
                    Some((k, v)) => k == COOKIE_NAME && v == tok,
                    None => false,
                }
            })
        })
}

/// What an unpaired, non-loopback visitor sees: a card visually identical to
/// the in-app pairing overlay (same glyph, card geometry, type,
/// theme-following palette). One variant now: every refusal — expired session,
/// stale or forwarded link — is told to rescan. The old path-based "invalid
/// share link" page is gone: a shared link is just another unpaired visitor,
/// and splitting the copy by path only papered over the same answer. All CSS
/// and the glyph are inline; the page makes ZERO further requests (every asset
/// it could want is behind the very gate that served it). The PC's loopback
/// window never reaches this branch, so the text below is visitor-only.
fn unpaired_page(glyph: &str, title: &str, heading: &str, body: &str) -> String {
    // Dark-only, like the app page: no light variant, no media query.
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
        <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
        <meta name=\"color-scheme\" content=\"dark\">\
        <title>{title}</title><style>\
        body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;\
        box-sizing:border-box;background:#000000;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}}\
        .card{{max-width:380px;width:100%;box-sizing:border-box;text-align:center;padding:36px 32px 30px;\
        background:#1c1c1e;border-radius:28px;border:1px solid rgba(255,255,255,0.08);\
        box-shadow:0 16px 48px rgba(0,0,0,0.35)}}\
        .glyph{{font-size:44px;line-height:1;margin-bottom:12px;color:#ffffff}}\
        .glyph svg{{width:44px;height:auto;display:inline-block;vertical-align:top}}\
        h1{{font-size:20px;font-weight:700;letter-spacing:-0.4px;margin:0 0 6px;color:#e3e3e5}}\
        p{{font-size:13px;line-height:1.65;margin:0;color:#8e8e93;text-align:left}}\
        </style></head><body><div class=\"card\">\
        <div class=\"glyph\">{glyph}</div>\
        <h1>{heading}</h1>\
        <p>{body}</p>\
        </div></body></html>"
    )
}

/// Inline "scan" glyph for the refusal page (SVG Repo
/// "Qr Code Scanner Phone Qr Code Smartphone", Objects Infographic Icons
/// collection, CC0 License, uploader SVG Repo).
/// Optimized for inline use: prolog/dimensions stripped, fill=currentColor so
/// it follows the page's dark palette. Inline, not /logo: this page
/// makes ZERO further requests by design, so it cannot reference any served
/// asset. Kept as a file (like logo.svg) instead of a string literal so the
/// 1.5KB of path data stays out of the source.
const SCAN_GLYPH: &str = include_str!("scan.svg");

/// Response marker the pairing gate attaches to every refusal: log_requests
/// reads it after the fact to decide which of the two presence stamps this
/// request may update (firewall proof: any inbound; device presence: paired
/// only).
pub(crate) const UNPAIRED_MARKER: HeaderName = HeaderName::from_static("x-tinbox-unpaired");

/// Gate every non-loopback request: no valid pairing cookie, no access. A valid
/// `?t=<token>` query (the QR payload / hand-typed URL) passes once and sets
/// the long-lived cookie, so afterwards the pairing rides the browser jar with
/// no URL decoration — the /view URLs the immutable cache keys on stay stable
/// across restarts. The `?t=` pass also broadcasts `PushEvent::Paired`, the
/// exact pairing moment already-connected pages toast on — and it is checked
/// before the cookie, so a re-scan while paired still counts as a scan.
pub(crate) async fn require_token(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if peer.ip().is_loopback() {
        return next.run(req).await;
    }
    let tok = request_token().clone();
    // ?t= first: a scan is a pairing gesture even when the jar already holds
    // a valid cookie (re-scan while paired) — checking the cookie first made
    // re-scans silent: no Paired broadcast, no toast, lightbox stays. Cookie-
    // only requests (reloads, subresource fetches never carry the query) fall
    // through to the silent branch below.
    if query_has_token(req.uri().query(), &tok) {
        let mut resp = next.run(req).await;
        // 30-day browser-side life; server restart is the real expiry.
        let cookie = format!(
            "{COOKIE_NAME}={tok}; Path=/; Max-Age=2592000; HttpOnly"
        );
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
        // A fresh credential just crossed the gate — QR scan or hand-typed
        // URL, cookie issued now. Broadcast so already-connected pages react
        // at the moment of the scan (PC toast + QR lightbox dismiss); the
        // scanning page itself hasn't opened its SSE stream yet.
        let _ = notifier().send(PushEvent::Paired);
        return resp;
    }
    if cookie_carries_token(req.headers(), &tok) {
        return next.run(req).await;
    }
    // Refused: one copy for every unpaired visitor — expired session, or a
    // stale/forwarded link. SCAN_GLYPH names the fix (scan again): an inline SVG
    // illustration instead of the 📷 emoji, which never had a dedicated QR-scan
    // codepoint and read as "camera" rather than "scan".
    let mut resp = (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            // no-store, not no-cache: a refusal must never populate any cache —
            // error pages share their URL with the real bytes (/view?id=…).
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        unpaired_page(
            SCAN_GLYPH,
            "tinbox — 请重新扫码连接",
            "请重新扫码连接",
            "配对二维码已经更换，请在电脑上点击「连接手机」重新扫码连接。",
        ),
    )
        .into_response();
    resp.headers_mut().insert(UNPAIRED_MARKER, HeaderValue::from_static("1"));
    resp
}
