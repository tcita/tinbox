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

/// Return a QR code PNG whose content is http://<best-LAN-IP>:<port>. The IP
/// is picked by the scoring in collect_ips (gateway-in-subnet evidence), which
/// stays correct even with TUN-mode VPNs or virtual adapters active. The page
/// shows it via <img src="/qr">; the phone scans it to open this page.
pub(crate) async fn qr() -> impl IntoResponse {
    // One URL builder for the whole app: current_url() assembles the pairing
    // URL (server.rs), so the QR payload and the displayed address can never
    // drift apart on an IP/port change.
    let url = crate::server::current_url();
    let qr = match qrcode::QrCode::new(url.as_bytes()) {
        Ok(q) => q,
        Err(e) => {
            loge(&format!("QR generation failed: {}  url={}", e, url));
            return (StatusCode::INTERNAL_SERVER_ERROR, "qr error").into_response();
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
    if img
        .write_to(&mut buf, image::ImageFormat::Png)
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode error").into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/png"),
            // Never cached: the payload carries the per-process pairing token,
            // so a cached copy scanned after a restart 403s forever.
            (header::CACHE_CONTROL, "no-store"),
        ],
        buf.into_inner(),
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
    // All private IPv4s with their interface names, deduplicated.
    let mut cands: Vec<(String, Ipv4Addr)> = Vec::new();
    if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in ifaces {
            if let IpAddr::V4(v4) = ip {
                if is_private(v4) && !cands.iter().any(|(_, v)| *v == v4) {
                    cands.push((name, v4));
                }
            }
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
    for (name, v4) in &cands {
        let desc = facts.get(name).map(|(d, _)| d.as_str()).unwrap_or("");
        if virtual_adapter(name) || virtual_adapter(desc) {
            dropped_virtual.push(format!("{name} {v4}"));
        } else {
            real.push((name.clone(), *v4));
        }
    }

    // Nothing real survived (an all-virtual machine). Still never emit a
    // vswitch address - fall back to the machine's default-route private IP, or
    // nothing at all. A blank/unreachable QR is honest; a vswitch IP is always
    // a lie.
    if real.is_empty() {
        let mut out: Vec<String> = Vec::new();
        if let Ok(IpAddr::V4(v4)) = local_ip_address::local_ip() {
            if is_private(v4) {
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

    // Filter 2: gateway reachability, probed with the candidate's own
    // address as source so the answer is per-interface, not whatever the
    // default route happens to pick. No gateway configured -> cannot probe,
    // kept last. A failed probe only demotes the adapter in the ordering; it
    // never drops it from the list (false negatives are common with a VPN TUN
    // active, and any real IP beats a virtual one).
    let probes: Vec<(Ipv4Addr, Ipv4Addr)> = real
        .iter()
        .filter_map(|(name, v4)| {
            facts
                .get(name)
                .and_then(|(_, gw)| gw.as_deref())
                .and_then(|g| g.parse::<Ipv4Addr>().ok())
                .map(|g| (*v4, g))
        })
        .collect();
    let probed = probe_gateways(&probes);

    let mut alive: Vec<Ipv4Addr> = Vec::new();
    let mut unprobed: Vec<Ipv4Addr> = Vec::new();
    let mut dead: Vec<(Ipv4Addr, String)> = Vec::new();
    for (name, v4) in real {
        let gw = facts
            .get(&name)
            .and_then(|(_, gw)| gw.as_deref())
            .and_then(|g| g.parse::<Ipv4Addr>().ok());
        match gw {
            Some(g) if probed.get(&(v4, g)) == Some(&true) => alive.push(v4),
            Some(g) => dead.push((v4, format!("{v4} (gateway {g} unreachable)"))),
            None => unprobed.push(v4),
        }
    }
    alive.sort_by_key(|v| v.octets());
    unprobed.sort_by_key(|v| v.octets());
    dead.sort_by_key(|(v, _)| v.octets());
    let ips: Vec<String> = alive
        .iter()
        .chain(&unprobed)
        .chain(dead.iter().map(|(v, _)| v))
        .map(ToString::to_string)
        .collect();

    // Log whenever any bucket changes, not just the winner: a new virtual
    // adapter appearing or a candidate flipping to dead is diagnostic noise
    // worth one line, while steady-state checks stay silent.
    let best = ips.first().cloned().unwrap_or_default();
    let signature = format!("{best}|{alive:?}|{unprobed:?}|{dead:?}|{dropped_virtual:?}");
    {
        let mut last = LAST_DECISION.lock().unwrap_or_else(|e| e.into_inner());
        if *last != signature {
            let list = |v: &[Ipv4Addr]| {
                v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            };
            logf(&format!(
                "LAN IP selection: using {best}; alive [{}]; no gateway [{}]; dead [{}]; virtual [{}]",
                list(&alive),
                list(&unprobed),
                dead.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>().join(", "),
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
/// Each real probe (60s cache miss) logs target, verdict and latency.
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
    logf(&format!(
        "gateway probe from {src} to {gw}: {} in {}ms",
        if ok { "alive" } else { "no reply" },
        started.elapsed().as_millis()
    ));
    ok
}

/// Never called: adapter facts are empty off-Windows, so collect_ips returns
/// before probing. Kept only so the crate compiles on other platforms.
#[cfg(not(windows))]
fn gateway_reachable(_src: Ipv4Addr, _gw: Ipv4Addr) -> bool {
    false
}

/// Adapter metadata used for filtering: interface name -> (description,
/// default gateway if any). Gathered by one powershell call, cached 30s —
/// `info` events fire on connect and on phone transitions, so the query must
/// not spawn a process each time.
#[cfg(windows)]
type AdapterFacts = std::collections::HashMap<String, (String, Option<String>)>;

#[cfg(not(windows))]
type AdapterFacts = std::collections::HashMap<String, (String, Option<String>)>;

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

/// One read-only powershell query: for every adapter, its name, description,
/// IPv4 addresses and default gateway, tab-separated per address.
#[cfg(windows)]
fn gather_adapter_facts() -> AdapterFacts {
    let ps = r#"Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
  $n = $_.Name; $d = $_.InterfaceDescription; $i = $_.ifIndex
  Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $g = (Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    "{0}`t{1}`t{2}`t{3}" -f $n, $d, $_.IPAddress, $g
  }
}"#;
    let mut map = AdapterFacts::new();
    if let Some((true, out)) = crate::firewall::run_ps(ps) {
        for line in out.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 4 {
                continue;
            }
            let gw = parts[3].trim();
            map.insert(
                parts[0].trim().to_string(),
                (
                    parts[1].trim().to_string(),
                    if gw.is_empty() { None } else { Some(gw.to_string()) },
                ),
            );
        }
    }
    map
}

#[cfg(not(windows))]
fn gather_adapter_facts() -> AdapterFacts {
    AdapterFacts::new()
}

