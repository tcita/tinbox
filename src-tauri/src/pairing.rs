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
// ── Pairing token ─────────────────────────────────────────────────────────
// The QR code encodes http://IP:PORT/?t=<token>; a phone's first visit with the
// correct ?t= is handed a cookie and needs no further interaction. The PC's own
// window rides loopback and never needs the token. Token lifetime = process
// lifetime (no persistence): the app runs desk-range sessions of minutes to a
// few hours, so every restart is also a natural "expire all pairings" event,
// and knowing the bare IP:PORT on this LAN is not enough after a restart.
static REQ_TOKEN: OnceLock<String> = OnceLock::new();

/// The per-process pairing token, lazily generated on first use. Desktop-sized
/// secrets are plenty against a LAN attacker who might see but mistype the
/// QR once; 8 characters are also hand-typable for manual phone entry, which
/// is why the alphabet avoids look-alike glyphs.
pub(crate) fn request_token() -> &'static String {
    REQ_TOKEN.get_or_init(|| {
        // No crypto dependency here: RandomState's SipHash keys come from the
        // OS CSPRNG, so folding a process id through two fresh hashers yields
        // two independent words of OS-grade randomness per run.
        use std::hash::{BuildHasher, Hasher};
        const RAND_CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
        let mut buf = String::with_capacity(8);
        let pid = std::process::id() as u64;
        for salt in [0u8, 1] {
            let mut h = std::collections::hash_map::RandomState::new()
                .build_hasher();
            h.write_u64(pid ^ 0x5a1fe93b2346_0000 | (salt as u64) << 24);
            let mut v = h.finish();
            for _ in 0..4 {
                buf.push(RAND_CHARS[(v % 31) as usize] as char);
                v /= 31;
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
/// the in-app "Pairing expired" overlay (same glyph, card geometry, type,
/// theme-following palette and the SAME wording — one message for every
/// unpaired arrival: expired session, first-time visitor, stale link; the
/// instruction is the same "rescan", so the wording is one). All CSS and the
/// emoji are inline; the page makes ZERO further requests (every asset it
/// could want is behind the very gate that served it). The PC's loopback
/// window never reaches this branch, so the text below is visitor-only.
const UNPAIRED_PAGE: &str = concat!(
    "<!doctype html><html><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>tinbox — 配对已过期</title><style>",
    "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;",
    "box-sizing:border-box;background:#f2f2f7;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}",
    "@media (prefers-color-scheme: dark){body{background:#000000}}",
    ".card{max-width:380px;width:100%;box-sizing:border-box;text-align:center;padding:36px 32px 30px;",
    "background:#ffffff;border-radius:28px;border:1px solid rgba(0,0,0,0.04);",
    "box-shadow:0 16px 48px rgba(0,0,0,0.08)}",
    "@media (prefers-color-scheme: dark){.card{background:#1c1c1e;border-color:rgba(255,255,255,0.08)}}",
    ".glyph{font-size:44px;line-height:1;margin-bottom:12px}",
    "h1{font-size:20px;font-weight:700;letter-spacing:-0.4px;margin:0 0 6px;color:#1a1a1e}",
    "@media (prefers-color-scheme: dark){h1{color:#ffffff}}",
    "p{font-size:13px;line-height:1.55;margin:0;color:#86868b}",
    "@media (prefers-color-scheme: dark){p{color:#8e8e93}}",
    "</style></head><body><div class=\"card\">",
    "<div class=\"glyph\">📦</div>",
    "<h1>配对已过期</h1>",
    "<p>请重新扫码连接。</p>",
    "</div></body></html>"
);

/// Response marker the pairing gate attaches to every refusal: log_requests
/// reads it after the fact to decide which of the two presence stamps this
/// request may update (firewall proof: any inbound; device presence: paired
/// only).
pub(crate) const UNPAIRED_MARKER: HeaderName = HeaderName::from_static("x-tinbox-unpaired");

/// Gate every non-loopback request: no valid pairing cookie, no access. A valid
/// `?t=<token>` query (the QR payload / hand-typed URL) passes once and sets
/// the long-lived cookie, so afterwards the pairing rides the browser jar with
/// no URL decoration — the /view URLs the immutable cache keys on stay stable
/// across restarts.
pub(crate) async fn require_token(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if peer.ip().is_loopback() {
        return next.run(req).await;
    }
    let tok = request_token().clone();
    if cookie_carries_token(req.headers(), &tok) {
        return next.run(req).await;
    }
    if query_has_token(req.uri().query(), &tok) {
        let mut resp = next.run(req).await;
        // 30-day browser-side life; server restart is the real expiry.
        let cookie = format!(
            "{COOKIE_NAME}={tok}; Path=/; Max-Age=2592000; HttpOnly"
        );
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
        return resp;
    }
    let mut resp = (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
        ],
        UNPAIRED_PAGE,
    )
        .into_response();
    resp.headers_mut().insert(UNPAIRED_MARKER, HeaderValue::from_static("1"));
    resp
}
