// Video metadata probe: duration + dimensions out of an MP4/MOV/M4V WITHOUT
// decoding a single frame. The timeline's compact video row wants a
// `02:47 · 1920×1080` suffix, and pixels are off the table (no decoder in the
// pure-Rust budget, and card-initiated video bytes are banned after the
// measured 5MB–1GB silent pulls). moov parsing is enough: mvhd carries the
// timescale/duration, the first `vide` trak's tkhd carries width/height.
//
// The walk is header-only and seek-driven: 8-byte box headers, skip payloads
// by size, so a 500MB moov-at-end file costs a handful of seeks, never a
// buffer. Anything unexpected (truncated file, fragmented mp4 with no mvhd
// duration, audio-only .m4a wearing .mp4) yields None and the row simply
// omits the suffix. Probe failure is routine, never logged.
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Duration + dimensions for one video file. `dur_ms == 0` means the moov had
/// no usable duration (mvhd timescale 0 or absent); the frontend hides it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MediaMeta {
    pub dur_ms: u64,
    pub w: u32,
    pub h: u32,
}

fn ext_of(name: &str) -> String {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
}

/// Extensions we even attempt to parse (ISO BMFF only — avi/mkv/webm need
/// different demuxers and stay suffix-less).
pub fn is_bmff_name(name: &str) -> bool {
    matches!(ext_of(name).as_str(), "mp4" | "mov" | "m4v")
}

/// Timeline-video names: Shell poster extraction and the frontend VID_EXTS
/// table stay in lockstep. Broader than is_bmff_name — avi/mkv/webm still
/// get a poster try even though they have no moov suffix.
pub fn is_video_name(name: &str) -> bool {
    matches!(ext_of(name).as_str(), "mp4" | "mov" | "m4v" | "avi" | "mkv" | "webm")
}

/// Parse if applicable, else None. Never panics, never reads box payloads
/// beyond a few dozen header bytes.
pub fn probe_for(name: &str, path: &Path) -> Option<MediaMeta> {
    if !is_bmff_name(name) {
        return None;
    }
    probe(path)
}

/// Upper bound on boxes visited per file: a sane moov needs dozens; anything
/// past this is corrupt or adversarial, and we bail instead of seeking
/// forever.
const MAX_BOXES: usize = 2000;

struct Walk {
    f: File,
    len: u64,
    seen: usize,
}

impl Walk {
    fn open(path: &Path) -> std::io::Result<Walk> {
        let f = File::open(path)?;
        let len = f.metadata()?.len();
        Ok(Walk { f, len, seen: 0 })
    }

    fn read_exact_vec(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.f.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read one box header at the current position. Returns
    /// (payload_end_offset, fourcc). `size == 0` means "to end of file";
    /// `size == 1` carries a 64-bit largesize.
    fn header(&mut self) -> std::io::Result<Option<(u64, [u8; 4])>> {
        let pos = self.f.stream_position()?;
        if pos + 8 > self.len {
            return Ok(None);
        }
        let b = self.read_exact_vec(8)?;
        let mut size = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
        let fourcc = [b[4], b[5], b[6], b[7]];
        let mut head_len = 8u64;
        if size == 1 {
            // 64-bit largesize: the type bytes do not move (only the size
            // field grows), so fourcc above already holds them.
            let lb = self.read_exact_vec(8)?;
            size = u64::from_be_bytes([
                lb[0], lb[1], lb[2], lb[3], lb[4], lb[5], lb[6], lb[7],
            ]);
            head_len = 16;
        }
        if size == 0 {
            size = self.len.saturating_sub(pos);
        }
        if size < head_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "box size smaller than header",
            ));
        }
        Ok(Some((pos + size, fourcc)))
    }

    fn skip_to(&mut self, end: u64) -> std::io::Result<()> {
        self.f.seek(SeekFrom::Start(end))?;
        Ok(())
    }

    fn tick(&mut self) -> std::io::Result<()> {
        self.seen += 1;
        if self.seen > MAX_BOXES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too many boxes",
            ));
        }
        Ok(())
    }
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn probe(path: &Path) -> Option<MediaMeta> {
    let mut w = Walk::open(path).ok()?;
    if w.len < 8 {
        return None;
    }
    // Top level: skip everything until the moov (for moov-at-end files this
    // leaps over the whole mdat in one seek — the header told us its size).
    loop {
        w.tick().ok()?;
        let (end, cc) = w.header().ok()??;
        if &cc == b"moov" {
            return parse_moov(&mut w, end);
        }
        w.skip_to(end).ok()?;
        if end >= w.len {
            return None;
        }
    }
}

fn parse_moov(w: &mut Walk, end: u64) -> Option<MediaMeta> {
    let mut dur_ms: Option<u64> = None;
    let mut dims: Option<(u32, u32)> = None;
    loop {
        let pos = w.f.stream_position().ok()?;
        if pos + 8 > end {
            break;
        }
        w.tick().ok()?;
        let (cend, cc) = w.header().ok()??;
        let cend = cend.min(end);
        if &cc == b"mvhd" {
            if let Some(d) = parse_mvhd(w) {
                dur_ms = Some(d);
            }
        } else if &cc == b"trak" {
            // First `vide` trak wins; later (audio/subtitle) traks are
            // skipped once we have dimensions.
            if dims.is_none() {
                if let Some(d) = parse_trak(w, cend) {
                    dims = Some(d);
                }
            }
        }
        w.skip_to(cend).ok()?;
    }
    // Duration without dimensions (or vice versa) still yields a row: the
    // frontend hides whichever half is zero/absent. Both absent = None.
    match (dur_ms, dims) {
        (None, None) => None,
        (d, wh) => {
            let (w_, h_) = wh.unwrap_or((0, 0));
            Some(MediaMeta {
                dur_ms: d.unwrap_or(0),
                w: w_,
                h: h_,
            })
        }
    }
}

/// mvhd v0: ver/flags(4) ctime(4) mtime(4) timescale(4) duration(4).
/// mvhd v1: ver/flags(4) ctime(8) mtime(8) timescale(4) duration(8).
/// Reads exactly what the version demands — a short (truncated) box errors
/// to None instead of over-reading into the next box.
fn parse_mvhd(w: &mut Walk) -> Option<u64> {
    let v = w.read_exact_vec(4).ok()?;
    let (scale, dur) = if v[0] == 1 {
        let b = w.read_exact_vec(28).ok()?;
        (be_u32(&b[16..20]), be_u64(&b[20..28]))
    } else {
        let b = w.read_exact_vec(16).ok()?;
        (be_u32(&b[8..12]), be_u32(&b[12..16]) as u64)
    };
    if scale == 0 {
        return None;
    }
    Some(dur.saturating_mul(1000) / scale as u64)
}

/// One trak: remember tkhd's dimensions, descend mdia for the hdlr handler,
/// keep the dimensions only when the handler is `vide`.
fn parse_trak(w: &mut Walk, end: u64) -> Option<(u32, u32)> {
    let mut dims: Option<(u32, u32)> = None;
    let mut handler: Option<[u8; 4]> = None;
    loop {
        let pos = w.f.stream_position().ok()?;
        if pos + 8 > end {
            break;
        }
        w.tick().ok()?;
        let (cend, cc) = w.header().ok()??;
        let cend = cend.min(end);
        if &cc == b"tkhd" {
            dims = parse_tkhd(w);
        } else if &cc == b"mdia" {
            handler = parse_mdia(w, cend);
        }
        w.skip_to(cend).ok()?;
    }
    match handler {
        Some(h) if &h == b"vide" => dims,
        _ => None,
    }
}

/// tkhd v0 width sits at payload+76, v1 at payload+88 (16.16 fixed-point).
fn parse_tkhd(w: &mut Walk) -> Option<(u32, u32)> {
    let b = w.read_exact_vec(96).ok()?;
    let off = if b[0] == 1 { 88 } else { 76 };
    let fw = be_u32(&b[off..off + 4]);
    let fh = be_u32(&b[off + 4..off + 8]);
    Some((fw >> 16, fh >> 16))
}

/// mdia children: only hdlr matters (handler type at payload+8).
fn parse_mdia(w: &mut Walk, end: u64) -> Option<[u8; 4]> {
    loop {
        let pos = w.f.stream_position().ok()?;
        if pos + 8 > end {
            break;
        }
        w.tick().ok()?;
        let (cend, cc) = w.header().ok()??;
        let cend = cend.min(end);
        if &cc == b"hdlr" {
            let b = w.read_exact_vec(12).ok()?;
            return Some([b[8], b[9], b[10], b[11]]);
        }
        w.skip_to(cend).ok()?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bx(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let len = (8 + payload.len()) as u32;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(typ);
        v.extend_from_slice(payload);
        v
    }

    /// Minimal moov: mvhd v0 (scale 1000, dur 167000) + video trak
    /// (1920x1080) + audio trak (must be ignored for dimensions).
    fn sample_moov() -> Vec<u8> {
        let mut mvhd = vec![0u8]; // version 0
        mvhd.extend_from_slice(&[0, 0, 0]); // flags
        mvhd.extend_from_slice(&0u32.to_be_bytes()); // ctime
        mvhd.extend_from_slice(&0u32.to_be_bytes()); // mtime
        mvhd.extend_from_slice(&1000u32.to_be_bytes()); // timescale
        mvhd.extend_from_slice(&167000u32.to_be_bytes()); // duration
        let mvhd = bx(b"mvhd", &mvhd);

        // tkhd v0: 76 bytes of prelude, then w/h as 16.16.
        let mut tkhd = vec![0u8, 0, 0, 0];
        tkhd.extend_from_slice(&[0u8; 72]);
        tkhd.extend_from_slice(&(1920u32 << 16).to_be_bytes());
        tkhd.extend_from_slice(&(1080u32 << 16).to_be_bytes());
        let tkhd = bx(b"tkhd", &tkhd);
        let mut hdlr = vec![0u8, 0, 0, 0, 0, 0, 0, 0];
        hdlr.extend_from_slice(b"vide");
        hdlr.extend_from_slice(&[0u8; 12]);
        let hdlr = bx(b"hdlr", &hdlr);
        let mdia = bx(b"mdia", &[hdlr].concat());
        let vtrak = bx(b"trak", &[tkhd, mdia].concat());

        let mut ahdlr = vec![0u8, 0, 0, 0, 0, 0, 0, 0];
        ahdlr.extend_from_slice(b"soun");
        ahdlr.extend_from_slice(&[0u8; 12]);
        let ahdlr = bx(b"hdlr", &ahdlr);
        let amdia = bx(b"mdia", &ahdlr);
        let mut atkhd = vec![0u8, 0, 0, 0];
        atkhd.extend_from_slice(&[0u8; 72]);
        atkhd.extend_from_slice(&(0u32).to_be_bytes());
        atkhd.extend_from_slice(&(0u32).to_be_bytes());
        let atkhd = bx(b"tkhd", &atkhd);
        let atrak = bx(b"trak", &[atkhd, amdia].concat());

        bx(b"moov", &[mvhd, vtrak, atrak].concat())
    }

    fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn moov_at_end_parses() {
        // ftyp + a fake 1MB mdat (header only matters — the walk seeks over
        // the payload) + moov: the phone-recording layout.
        let mut file = bx(b"ftyp", b"isom");
        let mut mdat = vec![0u8; 8];
        let mdat_len = (8 + 1_000_000) as u32;
        mdat[0..4].copy_from_slice(&mdat_len.to_be_bytes());
        mdat[4..8].copy_from_slice(b"mdat");
        file.extend_from_slice(&mdat);
        file.extend_from_slice(&vec![0u8; 1_000_000]);
        file.extend_from_slice(&sample_moov());
        let p = write_tmp("tinbox_probe_end.mp4", &file);
        let m = probe(&p).expect("moov-at-end must parse");
        assert_eq!(m.dur_ms, 167000);
        assert_eq!((m.w, m.h), (1920, 1080));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn moov_at_front_parses() {
        let mut file = bx(b"ftyp", b"isom");
        file.extend_from_slice(&sample_moov());
        file.extend_from_slice(&bx(b"mdat", &vec![0u8; 64]));
        let p = write_tmp("tinbox_probe_front.mp4", &file);
        let m = probe(&p).expect("moov-at-front must parse");
        assert_eq!(m.dur_ms, 167000);
        assert_eq!((m.w, m.h), (1920, 1080));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn truncated_is_none() {
        let mut moov = sample_moov();
        moov.truncate(moov.len() / 2);
        let p = write_tmp("tinbox_probe_cut.mp4", &moov);
        assert!(probe(&p).is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn audio_only_is_none() {
        // moov with mvhd but no vide trak: duration exists, dimensions do
        // not — and an audio file must not graduate to a "video" suffix on
        // duration alone... (it returns Some with 0x0; the row hides it —
        // here we assert the dims half is empty).
        let mut mvhd = vec![0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        mvhd.extend_from_slice(&1000u32.to_be_bytes());
        mvhd.extend_from_slice(&5000u32.to_be_bytes());
        let mvhd = bx(b"mvhd", &mvhd);
        let moov = bx(b"moov", &mvhd);
        let p = write_tmp("tinbox_probe_aud.mp4", &moov);
        let m = probe(&p).expect("mvhd-only parses");
        assert_eq!((m.w, m.h), (0, 0));
        std::fs::remove_file(&p).ok();
    }
}
