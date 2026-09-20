// LAN topology: pick the IP the QR code points at (gateway-reachability
// scoring, virtual adapters excluded), the QR PNG itself, and the
// foreign-subnet diagnostic for the access log.

use crate::logger::{loge, logf};
use crate::presence::now_mono;
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
/// current_url() inline, and the first collect_ips() past a switch probes the
/// new gateway (up to ~2s) and re-queries adapters through PowerShell. The
/// monitor now renders the PNG when it sees the URL change (see
/// presence::monitor_loop), so that open is an in-memory copy.
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

/// Enumerate this machine's IPv4 candidates for the QR code.
///
/// Virtual adapters (TUN VPNs, Docker/WSL vswitches) can never be reached by
/// the phone, so they are excluded outright by name/description keyword and are
/// never returned, not even as a fallback. The remaining real adapters are
/// ordered by gateway reachability (alive first), but a probe miss does NOT
/// remove an adapter: an active VPN TUN hijacks the ICMP to the real gateway
/// and produces false "dead"s, and any real IP is still a better QR target
/// than a vswitch address.
pub(crate) fn collect_ips() -> Vec<String> {
    // All private IPv4s with their interface names, deduplicated. Only
    // adapters that are actually connected are considered (see
    // local_private_v4): this is what stops a disconnected Wi-Fi adapter's
    // stale DHCP address from keeping the QR alive.
    let mut cands: Vec<(String, Ipv4Addr)> = Vec::new();
    for (name, v4) in local_private_v4() {
        if !cands.iter().any(|(_, v)| *v == v4) {
            cands.push((name, v4));
        }
    }
    if cands.is_empty() {
        return vec![];
    }

    let facts = adapter_facts();

    // Filter 1: known virtual adapters out. Name matching always applies even
    // when facts are missing; description matching adds the adapter's type.
    let mut real: Vec<(String, Ipv4Addr)> = Vec::new();
    let mut dropped_virtual: Vec<String> = Vec::new();
    let mut virtual_ips: std::collections::HashSet<Ipv4Addr> = std::collections::HashSet::new();
    for (name, v4) in &cands {
        let desc = facts.get(name).map(|f| f.desc.as_str()).unwrap_or("");
        if virtual_adapter(name) || virtual_adapter(desc) {
            dropped_virtual.push(format!("{name} {v4}"));
            virtual_ips.insert(*v4);
        } else {
            real.push((name.clone(), *v4));
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

    // Filter 2: gateway reachability, probed with the candidate's own address
    // as source so the answer is per-interface, not whatever the default route
    // happens to pick. A failed probe only demotes the adapter; it never drops
    // it (false negatives are common with a VPN TUN active, and any real IP
    // beats a virtual one).
    let probes: Vec<(Ipv4Addr, Ipv4Addr)> = real
        .iter()
        .filter_map(|(name, v4)| {
            facts
                .get(name)
                .and_then(|f| f.gateway.as_deref())
                .and_then(|g| g.parse::<Ipv4Addr>().ok())
                .map(|g| (*v4, g))
        })
        .collect();
    let probed = probe_gateways(&probes);

    // Order the survivors. Only two keys mean anything, and neither is a guess
    // about the phone's network:
    //   1. wireless   — the app's copy promises "同一 Wi-Fi", so prefer the
    //                   interface the user was told to use.
    //   2. gateway ok — measured evidence the interface is on a live network
    //                   (an unplugged NIC's gateway times out).
    // When those tie (a machine on two live Wi-Fis, or two live wired segments)
    // nothing can know which one the phone is on, so the remaining key is pure
    // determinism — the adapter name. It implies no preference; it only
    // guarantees "same adapter set -> same order", which the 1s URL comparison
    // needs to avoid phantom network-change reports. There is deliberately no
    // IP-value or interface-metric key: neither improves the chance of picking
    // the phone's network, so neither earns a place.
    struct Cand {
        name: String,
        v4: Ipv4Addr,
        wireless: bool,
        rank: u8, // 0 = gateway ok, 1 = no gateway to probe, 2 = gateway dead
    }
    let mut cands: Vec<Cand> = real
        .into_iter()
        .map(|(name, v4)| {
            let fact = facts.get(&name);
            let gw = fact
                .and_then(|f| f.gateway.as_deref())
                .and_then(|g| g.parse::<Ipv4Addr>().ok());
            let rank = match gw {
                Some(g) if probed.get(&(v4, g)) == Some(&true) => 0,
                Some(_) => 2,
                None => 1,
            };
            Cand {
                name,
                v4,
                wireless: fact.map(|f| f.wireless).unwrap_or(false),
                rank,
            }
        })
        .collect();
    // Wireless first (so !wireless sorts last), then reachable, then the name.
    cands.sort_by(|a, b| (!a.wireless, a.rank, &a.name).cmp(&(!b.wireless, b.rank, &b.name)));
    let ips: Vec<String> = cands.iter().map(|c| c.v4.to_string()).collect();

    // Log whenever this decision changes, not just the winner: a new virtual
    // adapter appearing or a candidate flipping to dead is diagnostic noise
    // worth one line, while steady-state checks stay silent.
    let best = ips.first().cloned().unwrap_or_default();
    let signature = format!(
        "{best}|{:?}|{dropped_virtual:?}",
        cands
            .iter()
            .map(|c| (c.v4, c.wireless, c.rank))
            .collect::<Vec<_>>()
    );
    {
        let mut last = LAST_DECISION.lock().unwrap_or_else(|e| e.into_inner());
        if *last != signature {
            let list = cands
                .iter()
                .map(|c| {
                    format!(
                        "{} {}/{}",
                        c.v4,
                        if c.wireless { "wifi" } else { "wired" },
                        ["alive", "no-gateway", "dead"][c.rank as usize],
                    )
                })
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
fn local_private_v4() -> Vec<(String, Ipv4Addr)> {
    #[cfg(windows)]
    if let Some(v) = connected_private_v4() {
        return v;
    }
    local_ip_address::list_afinet_netifas()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .filter_map(|(name, ip)| match ip {
                    IpAddr::V4(v4) if is_private(v4) => Some((name, v4)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Enumerate private IPv4 addresses but keep ONLY adapters whose `OperStatus`
/// is Up, so a disconnected interface (stale DHCP address, cable/Wi-Fi down)
/// cannot masquerade as a reachable LAN. Returns `None` on any API failure so
/// `local_private_v4` can fall back to the crate.
#[cfg(windows)]
fn connected_private_v4() -> Option<Vec<(String, Ipv4Addr)>> {
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
    let mut out: Vec<(String, Ipv4Addr)> = Vec::new();
    unsafe {
        let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            let a = &*adapter;
            if a.OperStatus == IfOperStatusUp && a.FriendlyName.0 != std::ptr::null_mut() {
                let name = pwstr_to_string(a.FriendlyName);
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    let ua = &*u;
                    let sa = ua.Address.lpSockaddr;
                    if !sa.is_null() && (*sa).sa_family == AF_INET {
                        let sin = &*sa.cast::<SOCKADDR_IN>();
                        let v4 = Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes());
                        if is_private(v4) && !out.iter().any(|(_, v): &(String, Ipv4Addr)| *v == v4) {
                            out.push((name.clone(), v4));
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

/// Probe several (source address, gateway) pairs concurrently; each answer
/// is cached for 60s because collect_ips runs on every `info` event / connect
/// replay and a probe costs up to ~2s of ping timeout (1s per attempt, two attempts).
fn probe_gateways(
    probes: &[(Ipv4Addr, Ipv4Addr)],
) -> std::collections::HashMap<(Ipv4Addr, Ipv4Addr), bool> {
    // (last probe unix, (src addr, gateway)) -> reachable, invalidated after 60s
    type ProbeCache = (u64, std::collections::HashMap<(Ipv4Addr, Ipv4Addr), bool>);
    static CACHE: OnceLock<Mutex<ProbeCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new((0, Default::default())));
    let mut g = cache.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_mono();
    if now.saturating_sub(g.0) >= 60 {
        g.0 = now;
        g.1.clear();
    }
    let missing: Vec<(Ipv4Addr, Ipv4Addr)> = probes
        .iter()
        .copied()
        .filter(|p| !g.1.contains_key(p))
        .collect();
    if !missing.is_empty() {
        let handles: Vec<_> = missing
            .iter()
            .map(|p| {
                let p = *p;
                std::thread::spawn(move || (p, gateway_reachable(p.0, p.1)))
            })
            .collect();
        for h in handles {
            if let Ok((p, ok)) = h.join() {
                g.1.insert(p, ok);
            }
        }
    }
    probes
        .iter()
        .map(|p| (*p, g.1.get(p).copied().unwrap_or(false)))
        .collect()
}

/// One ICMP echo to the gateway with the interface address pinned as source
/// (`ping -S`), 1s cap per attempt, up to two attempts. A single dropped ICMP
/// (transient WiFi blip, or a VPN TUN capturing the packet) is otherwise a
/// false "dead" that misorders multi-adapter machines. Exit code 0 means at
/// least one reply came back.
/// Logging is change-or-failure only: a steady `alive` would be one line a
/// minute of idle noise, so it stays silent. First probe, any `no reply`,
/// and dead->alive recovery still log.
#[cfg(windows)]
fn gateway_reachable(src: Ipv4Addr, gw: Ipv4Addr) -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::time::Instant;
    let started = Instant::now();
    let mut ok = false;
    for _ in 0..2 {
        let out = Command::new("ping")
            .args(["-n", "1", "-w", "1000", "-S", &src.to_string(), &gw.to_string()])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output();
        if out.map(|o| o.status.success()).unwrap_or(false) {
            ok = true;
            break;
        }
    }
    // Last logged verdict per (src, gateway): steady `alive` repeats are
    // suppressed, so an idle machine stays silent. Failures always log
    // (each 60s miss while dead is evidence, not noise); recovery logs via
    // the verdict change.
    static LAST_VERDICT: OnceLock<Mutex<std::collections::HashMap<(Ipv4Addr, Ipv4Addr), bool>>> =
        OnceLock::new();
    let prev = LAST_VERDICT
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((src, gw), ok);
    if prev != Some(ok) || !ok {
        logf(&format!(
            "gateway probe from {src} to {gw}: {} in {}ms",
            if ok { "alive" } else { "no reply" },
            started.elapsed().as_millis()
        ));
    }
    ok
}

/// Never called: adapter facts are empty off-Windows, so collect_ips returns
/// before probing. Kept only so the crate compiles on other platforms.
#[cfg(not(windows))]
fn gateway_reachable(_src: Ipv4Addr, _gw: Ipv4Addr) -> bool {
    false
}

/// Adapter metadata used for filtering and for ordering the QR candidates.
/// Gathered by one powershell call, cached 30s — `info` events fire on connect
/// and on phone transitions, so the query must not spawn a process each time.
#[derive(Clone, Default)]
struct AdapterFact {
    /// InterfaceDescription ("Intel(R) Wi-Fi 6 AX201 …"); the virtual-adapter
    /// keyword filter reads it.
    desc: String,
    /// Default gateway, when the interface has one (else it cannot be probed).
    gateway: Option<String>,
    /// 802.11/Wi-Fi family — see the ordering in collect_ips (the app tells
    /// users "同一 Wi-Fi", so the wireless interface wins).
    wireless: bool,
}

type AdapterFacts = std::collections::HashMap<String, AdapterFact>;

static ADAPTER_FACTS: OnceLock<Mutex<(u64, AdapterFacts)>> = OnceLock::new();
static LAST_DECISION: Mutex<String> = Mutex::new(String::new());

fn adapter_facts() -> AdapterFacts {
    let cache = ADAPTER_FACTS.get_or_init(|| Mutex::new((0, Default::default())));
    let mut g = cache.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_mono();
    if now.saturating_sub(g.0) < 30 {
        return g.1.clone();
    }
    let facts = gather_adapter_facts();
    if !facts.is_empty() {
        g.0 = now;
        g.1 = facts.clone();
    }
    facts
}

/// One read-only powershell query: for every Up adapter, its name, description,
/// IPv4 addresses, default gateway and wireless flag, tab-separated per address.
#[cfg(windows)]
fn gather_adapter_facts() -> AdapterFacts {
    let ps = r#"Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
  $n = $_.Name; $d = $_.InterfaceDescription; $i = $_.ifIndex
  $w = if (("$d $n" -match 'Wi-?Fi|WLAN|Wireless|802\.11') -or ($_.PhysicalMediaType -match '802\.11|Wireless')) { '1' } else { '0' }
  Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $g = (Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    "{0}`t{1}`t{2}`t{3}`t{4}" -f $n, $d, $_.IPAddress, $g, $w
  }
}"#;
    let mut map = AdapterFacts::new();
    if let Some((true, out)) = crate::firewall::run_ps(ps) {
        for line in out.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 5 {
                continue;
            }
            let gw = parts[3].trim();
            map.insert(
                parts[0].trim().to_string(),
                AdapterFact {
                    desc: parts[1].trim().to_string(),
                    gateway: if gw.is_empty() { None } else { Some(gw.to_string()) },
                    wireless: parts[4].trim() == "1",
                },
            );
        }
    }
    map
}

#[cfg(not(windows))]
fn gather_adapter_facts() -> AdapterFacts {
    AdapterFacts::new()
}

