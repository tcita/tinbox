// LAN topology: pick the IP the QR code points at (wireless-first, virtual
// adapters excluded), the QR PNG itself, and the foreign-subnet diagnostic
// for the access log.

use crate::logger::{loge, logf};
use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Mutex, OnceLock};
/// Peers already warned about coming from a different subnet than the QR IP.
static SUBNET_WARNED: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();


/// A LAN peer whose /24 differs from the address the QR code points at is the
/// classic "phone joined the guest network / the other band" symptom: packets
/// still arrive but the user thinks they scanned the right URL. Warn once per
/// peer.
pub(crate) fn note_foreign_subnet(peer: &SocketAddr) {
    let IpAddr::V4(peer_v4) = peer.ip() else { return };
    let Some(qr_ip) = collect_ips().first().cloned() else { return };
    let Ok(qr_v4) = qr_ip.parse::<Ipv4Addr>() else { return };
    let same = qr_v4.octets()[..3] == peer_v4.octets()[..3];
    if same {
        return;
    }
    let key = peer.ip().to_string();
    let set = SUBNET_WARNED.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    let mut set = set.lock().unwrap_or_else(|e| e.into_inner());
    if set.contains(&key) {
        return;
    }
    set.insert(key);
    logf(&format!(
        "warning: request from {} is in a different subnet than the QR IP {} (phone may be on a guest network or another WiFi band)",
        peer.ip(), qr_ip
    ));
}

/// Cached QR PNG for the last URL the monitor rendered. Opening the lightbox
/// used to go blank for seconds after a network switch: the handler computed
/// current_url() inline, and the first collect_ips() past a switch paid a
/// full adapter enumeration. The monitor now renders the PNG when it sees
/// the URL change (see presence::monitor_loop), so that open is an
/// in-memory copy.
static QR_CACHE: OnceLock<Mutex<(String, Vec<u8>)>> = OnceLock::new();

fn qr_cache() -> &'static Mutex<(String, Vec<u8>)> {
    QR_CACHE.get_or_init(|| Mutex::new((String::new(), Vec::new())))
}

/// Render the QR PNG for `url`. Cheap (encode + rasterize, a few ms) — the
/// expensive half of the old path was assembling the URL, not drawing it.
fn render_qr(url: &str) -> Option<Vec<u8>> {
    let qr = match qrcode::QrCode::new(url.as_bytes()) {
        Ok(q) => q,
        Err(e) => {
            loge(&format!("QR generation failed: {}  url={}", e, url));
            return None;
        }
    };
    let modules = qr.width();
    // Scale 10 keeps the PNG crisp when the frontend displays it at ~104 CSS px.
    let scale = 10u32;
    let border = 4 * scale;
    let size = modules as u32 * scale + border * 2;
    let mut img = image::GrayImage::new(size, size);
    for y in 0..size {
        for x in 0..size {
            let mx = (x as i64 - border as i64) / scale as i64;
            let my = (y as i64 - border as i64) / scale as i64;
            let dark = mx >= 0
                && my >= 0
                && (mx as usize) < modules
                && (my as usize) < modules
                && qr[(mx as usize, my as usize)] == qrcode::Color::Dark;
            img.put_pixel(x, y, image::Luma([if dark { 0 } else { 255 }]));
        }
    }
    let mut buf = std::io::Cursor::new(Vec::new());
    if img.write_to(&mut buf, image::ImageFormat::Png).is_err() {
        loge(&format!("QR encode failed  url={url}"));
        return None;
    }
    Some(buf.into_inner())
}

/// Pre-render the QR for the current URL into the cache. Called by the monitor
/// when the URL changes, so the user's next lightbox open is instant.
/// `render_qr` logs its own failures; a stale/empty cache just falls back to
/// an on-demand render in `qr()`.
pub(crate) fn refresh_qr() {
    if !crate::server::lan_usable() {
        // No LAN address: whatever we could draw would encode 127.0.0.1 and
        // scan to nothing. Drop any previous code so nothing stale survives;
        // qr() refuses outright.
        *qr_cache().lock().unwrap_or_else(|e| e.into_inner()) = (String::new(), Vec::new());
        return;
    }
    let url = crate::server::current_url();
    if let Some(bytes) = render_qr(&url) {
        *qr_cache().lock().unwrap_or_else(|e| e.into_inner()) = (url, bytes);
    }
}

pub(crate) async fn qr() -> impl IntoResponse {
    if !crate::server::lan_usable() {
        // No LAN address — the UI hides the QR and explains instead. Never hand
        // out a code that points at 127.0.0.1.
        return (StatusCode::NOT_FOUND, "no LAN address").into_response();
    }
    // Cached copy first, but only while it still matches the current URL: the
    // snapshot is updated by the monitor the moment it sees a change, so a
    // cache for a superseded URL is never served. Compute on demand for a cold
    // start or a failed pre-render. (current_url() is read before the QR lock,
    // so the two locks are never held together.)
    let cur = crate::server::current_url();
    let cached = {
        let g = qr_cache().lock().unwrap_or_else(|e| e.into_inner());
        if g.1.is_empty() || g.0 != cur { None } else { Some(g.1.clone()) }
    };
    let bytes = match cached {
        Some(b) => b,
        None => match render_qr(&cur) {
            Some(b) => b,
            None => return (StatusCode::INTERNAL_SERVER_ERROR, "qr error").into_response(),
        },
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/png"),
            // Never cached: the payload carries the per-process pairing token,
            // so a cached copy scanned after a restart 403s forever.
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response()
}

/// Sort key for QR candidates: wireless first (the app promises "同一 Wi-Fi"),
/// then the adapter name for determinism. A free function so the ordering is
/// unit-testable without touching Win32 enumeration.
fn cand_key(wireless: bool, name: &str) -> (bool, &str) {
    (!wireless, name)
}

/// Enumerate this machine's IPv4 candidates for the QR code.
///
/// Virtual adapters (TUN VPNs, Docker/WSL vswitches) can never be reached by
/// the phone, so they are excluded outright by name/description keyword and are
/// never returned, not even as a fallback. The remaining real adapters are
/// ordered wireless-first, then by adapter name for determinism (see the
/// ordering note in the body) — there is no gateway probe: it would measure
/// "PC -> gateway", not "phone -> PC", and misorder exactly the machines where
/// the choice matters.
pub(crate) fn collect_ips() -> Vec<String> {
    // All private IPv4s with their interface names, deduplicated. Only
    // adapters that are actually connected are considered (see
    // local_private_v4): this is what stops a disconnected Wi-Fi adapter's
    // stale DHCP address from keeping the QR alive.
    // The (desc, wireless) metadata rides the same GetAdaptersAddresses pass,
    // so it is fresh every call (~1/s) with no cache and no powershell.
    let mut cands: Vec<(String, Ipv4Addr, String, bool)> = Vec::new();
    for (name, v4, desc, wireless) in local_private_v4() {
        if !cands.iter().any(|(_, v, _, _)| *v == v4) {
            cands.push((name, v4, desc, wireless));
        }
    }
    if cands.is_empty() {
        return vec![];
    }

    // Filter 1: known virtual adapters out. Name matching always applies;
    // description matching adds the adapter's type.
    let mut real: Vec<(String, Ipv4Addr, String, bool)> = Vec::new();
    let mut dropped_virtual: Vec<String> = Vec::new();
    let mut virtual_ips: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
    for (name, v4, desc, _wireless) in &cands {
        if virtual_adapter(name) || virtual_adapter(desc) {
            dropped_virtual.push(format!("{name} {v4}"));
            virtual_ips.insert(*v4);
        } else {
            real.push((name.clone(), *v4, desc.clone(), *_wireless));
        }
    }

    // Nothing real survived (an all-virtual machine). Never emit a vswitch/TUN
    // address: the fallback probes the machine's default-route IP, and with a
    // VPN TUN up that route IS the tunnel (`xray` etc.), so an unguarded
    // local_ip() would hand back exactly the lie this branch exists to avoid —
    // a QR for 172.18.x.x no phone can reach. Reject anything already seen on a
    // virtual adapter; a real adapter our enumeration happened to miss is not in
    // virtual_ips and still gets rescued. A blank/unreachable QR is honest.
    if real.is_empty() {
        let mut out: Vec<String> = Vec::new();
        if let Ok(IpAddr::V4(v4)) = local_ip_address::local_ip() {
            if is_private(v4) && !virtual_ips.contains(&v4) {
                out.push(v4.to_string());
            }
        }
        let mut last = LAST_DECISION.lock().unwrap_or_else(|e| e.into_inner());
        let signature = format!("{}|{}", out.join(","), dropped_virtual.join(","));
        if *last != signature {
            *last = signature;
            logf(&format!(
                "LAN IP selection: no real adapter; using default route {}; virtual [{}]",
                out.first().map(String::as_str).unwrap_or("(none)"),
                dropped_virtual.join(", ")
            ));
        }
        return out;
    }

    // Order the survivors. One key means anything, and it is not a guess about
    // the phone's network:
    //   wireless — the app's copy promises "同一 Wi-Fi", so prefer the
    //              interface the user was told to use.
    // When that ties (a machine on two Wi-Fis, or two wired segments) nothing
    // can know which one the phone is on, so the remaining key is pure
    // determinism — the adapter name. It implies no preference; it only
    // guarantees "same adapter set -> same order", which the 1s URL comparison
    // needs to avoid phantom network-change reports.
    //
    // There is deliberately no gateway-reachability key. A gateway probe
    // measures "PC -> its gateway", not "phone -> PC": they diverge exactly
    // where it would matter (a hotspot/AP that does not answer ICMP, a VPN TUN
    // eating the probe, an uplink-less LAN), so ranking by it can pick an
    // interface the phone cannot reach while demoting the one it is on.
    // Wireless-first is the better proxy for "the phone is here".
    struct Cand {
        name: String,
        v4: Ipv4Addr,
        wireless: bool,
    }
    let mut cands: Vec<Cand> = real
        .into_iter()
        .map(|(name, v4, _desc, wireless)| Cand {
            wireless,
            name,
            v4,
        })
        .collect();
    // Wireless first (so !wireless sorts last), then the name.
    cands.sort_by(|a, b| cand_key(a.wireless, &a.name).cmp(&cand_key(b.wireless, &b.name)));
    let ips: Vec<String> = cands.iter().map(|c| c.v4.to_string()).collect();

    // Log whenever this decision changes, not just the winner: a new virtual
    // adapter appearing or a candidate changing class is diagnostic noise
    // worth one line, while steady-state checks stay silent.
    let best = ips.first().cloned().unwrap_or_default();
    let signature = format!(
        "{best}|{:?}|{dropped_virtual:?}",
        cands.iter().map(|c| (c.v4, c.wireless)).collect::<Vec<_>>()
    );
    {
        let mut last = LAST_DECISION.lock().unwrap_or_else(|e| e.into_inner());
        if *last != signature {
            let list = cands
                .iter()
                .map(|c| format!("{} {}", c.v4, if c.wireless { "wifi" } else { "wired" }))
                .collect::<Vec<_>>()
                .join(", ");
            logf(&format!(
                "LAN IP selection: using {best}; candidates [{list}]; virtual [{}]",
                dropped_virtual.join(", "),
            ));
            *last = signature;
        }
    }
    ips
}

/// Private-range addresses only: loopback, link-local (169.254/16) and
/// public addresses can never be reached from the phone's browser.
fn is_private(v4: Ipv4Addr) -> bool {
    match v4.octets() {
        [10, ..] | [192, 168, ..] => true,
        [172, b, ..] => (16..=31).contains(&b),
        _ => false,
    }
}

fn virtual_adapter(s: &str) -> bool {
    const KW: &[&str] = &[
        "tun", "tap", "vpn", "docker", "wsl", "vmware", "virtual", "hyper-v", "vethernet",
        "loopback", "clash", "xray", "sing-box", "singbox", "wireguard", "zerotier", "tailscale",
        "wi-fi direct", "bluetooth",
    ];
    let l = s.to_lowercase();
    KW.iter().any(|k| l.contains(k))
}

/// Private IPv4 candidates for the QR, preferring a status-filtered Windows
/// enumeration and falling back to the crate only when that fails.
///
/// The `local-ip-address` crate's `list_afinet_netifas()` walks every adapter
/// and unicast address from `GetAdaptersAddresses` WITHOUT consulting
/// `OperStatus`, so a media-disconnected adapter whose DHCP address Windows has
/// not yet released (`ipconfig` says "Media disconnected", but the address
/// still rides the adapter struct) reads as a live LAN address. tinbox would
/// then keep advertising a QR for a network that is gone, and the monitor sees
/// no change so it never logs `network changed`. See `connected_private_v4`.
///
/// Returns (name, ip, desc, wireless): the metadata rides the same
/// GetAdaptersAddresses pass, so it is fresh every call (~1/s) with no cache
/// and no powershell.
fn local_private_v4() -> Vec<(String, Ipv4Addr, String, bool)> {
    #[cfg(windows)]
    if let Some(v) = connected_private_v4() {
        return v;
    }
    local_ip_address::list_afinet_netifas()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .filter_map(|(name, ip)| match ip {
                    IpAddr::V4(v4) if is_private(v4) => {
                        let wireless = wireless_by_keywords(&name, "");
                        Some((name, v4, String::new(), wireless))
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// IANA IF_TYPE for 802.11 wireless (matches Get-NetAdapter PhysicalMediaType
/// 802.11/Wireless that the old powershell query read).
#[cfg(windows)]
const IF_TYPE_IEEE80211: u32 = 71;

/// Keyword fallback for wireless detection: the old `Get-NetAdapter` query
/// matched `"desc name" -match 'Wi-?Fi|WLAN|Wireless|802\.11'`. Kept so a
/// wireless NIC whose IfType is not 71 still sorts first.
fn wireless_by_keywords(name: &str, desc: &str) -> bool {
    let l = format!("{desc} {name}").to_lowercase();
    l.contains("wifi")
        || l.contains("wi-fi")
        || l.contains("wlan")
        || l.contains("wireless")
        || l.contains("802.11")
}

/// Enumerate private IPv4 addresses but keep ONLY adapters whose `OperStatus`
/// is Up, so a disconnected interface (stale DHCP address, cable/Wi-Fi down)
/// cannot masquerade as a reachable LAN. Returns `None` on any API failure so
/// `local_private_v4` can fall back to the crate.
#[cfg(windows)]
fn connected_private_v4() -> Option<Vec<(String, Ipv4Addr, String, bool)>> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    // Vec<u64> not Vec<u8>: the buffer is reinterpreted as IP_ADAPTER_ADDRESSES_LH,
    // which holds pointers/u64 and needs 8-byte alignment that a u8 Vec cannot
    // promise (a misaligned deref is UB).
    let mut size: u32 = 15_000;
    let mut buf: Vec<u64>;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_INET.0 as u32,
                GET_ADAPTERS_ADDRESSES_FLAGS(GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0),
                None,
                Some(buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut size,
            )
        };
        match ret {
            ERROR_SUCCESS => break,
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return None,
        }
    }
    let mut out: Vec<(String, Ipv4Addr, String, bool)> = Vec::new();
    unsafe {
        let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            let a = &*adapter;
            if a.OperStatus == IfOperStatusUp && a.FriendlyName.0 != std::ptr::null_mut() {
                let name = pwstr_to_string(a.FriendlyName);
                let desc = if a.Description.0 != std::ptr::null_mut() {
                    pwstr_to_string(a.Description)
                } else {
                    String::new()
                };
                let wireless = a.IfType == IF_TYPE_IEEE80211
                    || wireless_by_keywords(&name, &desc);
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    let ua = &*u;
                    let sa = ua.Address.lpSockaddr;
                    if !sa.is_null() && (*sa).sa_family == AF_INET {
                        let sin = &*sa.cast::<SOCKADDR_IN>();
                        let v4 = Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes());
                        if is_private(v4)
                            && !out.iter().any(|(_, v, _, _)| *v == v4)
                        {
                            out.push((name.clone(), v4, desc.clone(), wireless));
                        }
                    }
                    u = ua.Next;
                }
            }
            adapter = a.Next;
        }
    }
    Some(out)
}

/// Decode a NUL-terminated wide string returned by Win32.
#[cfg(windows)]
unsafe fn pwstr_to_string(p: windows::core::PWSTR) -> String {
    let mut len = 0usize;
    while *p.0.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p.0, len))
}

static LAST_DECISION: Mutex<String> = Mutex::new(String::new());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_only() {
        for ip in ["192.168.1.7", "10.0.0.2", "172.16.0.1", "172.31.255.255"] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        // 172.15/172.32 are public, 169.254 is link-local, loopback is not LAN.
        for ip in ["172.15.9.9", "172.32.0.1", "8.8.8.8", "169.254.10.20", "127.0.0.1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn virtual_keywords_never_reach_the_qr() {
        for name in [
            "vEthernet (WSL)",
            "WireGuard Tunnel",
            "TAP-Windows Adapter",
            "ZeroTier One",
        ] {
            assert!(virtual_adapter(name), "{name}");
        }
        for name in [
            "WLAN",
            "Intel(R) Wi-Fi 6 AX201",
            "Realtek PCIe GbE Family Controller",
            "Wi-Fi",
        ] {
            assert!(!virtual_adapter(name), "{name}");
        }
    }

    #[test]
    fn wireless_first_then_name() {
        // Wireless beats wired no matter the names.
        assert!(cand_key(true, "Zulu") < cand_key(false, "Alpha"));
        // Ties break on the name: deterministic, implying no preference.
        assert!(cand_key(false, "Alpha") < cand_key(false, "Beta"));
        assert_eq!(cand_key(true, "WLAN"), cand_key(true, "WLAN"));
    }

    #[test]
    fn wireless_keywords_match_old_ps_query() {
        // Old Get-NetAdapter query: "desc name" -match 'Wi-?Fi|WLAN|Wireless|802.11'.
        assert!(wireless_by_keywords("WLAN", ""));
        assert!(wireless_by_keywords("Wi-Fi", ""));
        assert!(wireless_by_keywords("Ethernet", "Intel(R) Wi-Fi 6 AX201"));
        assert!(wireless_by_keywords("Ethernet", "802.11n USB Wireless LAN Card"));
        assert!(!wireless_by_keywords(
            "Ethernet",
            "Realtek PCIe GbE Family Controller"
        ));
    }
}

