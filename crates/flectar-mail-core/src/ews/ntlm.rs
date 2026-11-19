//! NTLMv2 client messages (MS-NLMP) for HTTP authentication.

use anyhow::{Result, anyhow, bail};
use hmac::{Hmac, KeyInit, Mac};
use md4::{Digest, Md4};
use md5::Md5;

const SIG: &[u8; 8] = b"NTLMSSP\0";
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const REQUEST_TARGET: u32 = 0x0000_0004;
const NEGOTIATE_NTLM: u32 = 0x0000_0200;
const ALWAYS_SIGN: u32 = 0x0000_8000;
const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
const NEGOTIATE_128: u32 = 0x2000_0000;
const NEGOTIATE_56: u32 = 0x8000_0000;
const FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_NTLM
    | ALWAYS_SIGN
    | EXTENDED_SESSIONSECURITY
    | NEGOTIATE_128
    | NEGOTIATE_56;
const AV_EOL: u16 = 0;
const AV_TIMESTAMP: u16 = 7;

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// Type 1 message.
pub fn negotiate() -> Vec<u8> {
    let mut m = Vec::with_capacity(32);
    m.extend_from_slice(SIG);
    m.extend_from_slice(&1u32.to_le_bytes());
    m.extend_from_slice(&FLAGS.to_le_bytes());
    m.extend_from_slice(&[0u8; 16]); // empty domain and workstation fields
    m
}

/// Parsed type 2 message.
pub struct Challenge {
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
}

fn secbuf(m: &[u8], at: usize) -> Result<&[u8]> {
    let hdr = m
        .get(at..at + 8)
        .ok_or_else(|| anyhow!("NTLM message too short"))?;
    let len = u16::from_le_bytes([hdr[0], hdr[1]]) as usize;
    let off = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    m.get(off..off + len)
        .ok_or_else(|| anyhow!("NTLM field out of range"))
}

impl Challenge {
    pub fn parse(m: &[u8]) -> Result<Self> {
        if m.len() < 32 || &m[..8] != SIG || m[8..12] != 2u32.to_le_bytes() {
            bail!("not an NTLM challenge");
        }
        let flags = u32::from_le_bytes(m[20..24].try_into().unwrap());
        let target_info = if flags & NEGOTIATE_TARGET_INFO != 0 && m.len() >= 48 {
            secbuf(m, 40)?.to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            server_challenge: m[24..32].try_into().unwrap(),
            target_info,
        })
    }

    fn timestamp(&self) -> Option<[u8; 8]> {
        let mut p = 0;
        while p + 4 <= self.target_info.len() {
            let id = u16::from_le_bytes([self.target_info[p], self.target_info[p + 1]]);
            let len =
                u16::from_le_bytes([self.target_info[p + 2], self.target_info[p + 3]]) as usize;
            if id == AV_EOL {
                break;
            }
            if id == AV_TIMESTAMP && len == 8 {
                return self
                    .target_info
                    .get(p + 4..p + 12)
                    .map(|s| s.try_into().unwrap());
            }
            p += 4 + len;
        }
        None
    }
}

pub fn nt_hash_v2(user: &str, domain: &str, password: &str) -> [u8; 16] {
    let nt_hash: [u8; 16] = Md4::digest(utf16le(password)).into();
    hmac_md5(&nt_hash, &[&utf16le(&(user.to_uppercase() + domain))])
}

/// Current time as a Windows FILETIME (100 ns ticks since 1601).
fn filetime_now() -> [u8; 8] {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    ((unix.as_nanos() / 100) as u64 + 116_444_736_000_000_000).to_le_bytes()
}

/// Returns (LM response, NT response).
fn responses(
    ch: &Challenge,
    key: &[u8; 16],
    client: [u8; 8],
    time: [u8; 8],
    server_time: bool,
) -> (Vec<u8>, Vec<u8>) {
    let mut temp = vec![1, 1, 0, 0, 0, 0, 0, 0];
    temp.extend_from_slice(&time);
    temp.extend_from_slice(&client);
    temp.extend_from_slice(&[0; 4]);
    temp.extend_from_slice(&ch.target_info);
    temp.extend_from_slice(&[0; 4]);
    let proof = hmac_md5(key, &[&ch.server_challenge, &temp]);
    let mut nt = proof.to_vec();
    nt.extend_from_slice(&temp);
    // With a server timestamp the LMv2 response must be zeros (MS-NLMP 3.1.5.1.2).
    let lm = if server_time {
        vec![0; 24]
    } else {
        let mut lm = hmac_md5(key, &[&ch.server_challenge, &client]).to_vec();
        lm.extend_from_slice(&client);
        lm
    };
    (lm, nt)
}

/// Type 3 message.
pub fn authenticate(ch: &Challenge, user: &str, domain: &str, password: &str) -> Result<Vec<u8>> {
    let mut client = [0u8; 8];
    getrandom::fill(&mut client).map_err(|e| anyhow!("no randomness for NTLM: {e}"))?;
    let server_time = ch.timestamp();
    let key = nt_hash_v2(user, domain, password);
    let (lm, nt) = responses(
        ch,
        &key,
        client,
        server_time.unwrap_or_else(filetime_now),
        server_time.is_some(),
    );
    let fields = [
        lm,
        nt,
        utf16le(domain),
        utf16le(user),
        Vec::new(),
        Vec::new(),
    ];
    let mut m = Vec::new();
    m.extend_from_slice(SIG);
    m.extend_from_slice(&3u32.to_le_bytes());
    let mut offset = 64u32;
    for f in &fields {
        let len = f.len() as u16;
        m.extend_from_slice(&len.to_le_bytes());
        m.extend_from_slice(&len.to_le_bytes());
        m.extend_from_slice(&offset.to_le_bytes());
        offset += f.len() as u32;
    }
    m.extend_from_slice(&(FLAGS | NEGOTIATE_TARGET_INFO).to_le_bytes());
    for f in &fields {
        m.extend_from_slice(f);
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from MS-NLMP 4.2.4 (NTLMv2 authentication).
    #[test]
    fn ms_nlmp_vector() {
        let key = nt_hash_v2("User", "Domain", "Password");
        assert_eq!(
            key,
            [
                0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
                0x2e, 0x3f
            ]
        );
        let mut ti = Vec::new();
        for (id, val) in [(2u16, "Domain"), (1, "Server")] {
            let v = utf16le(val);
            ti.extend_from_slice(&id.to_le_bytes());
            ti.extend_from_slice(&(v.len() as u16).to_le_bytes());
            ti.extend_from_slice(&v);
        }
        ti.extend_from_slice(&[0; 4]);
        let ch = Challenge {
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            target_info: ti,
        };
        let (lm, nt) = responses(&ch, &key, [0xaa; 8], [0; 8], false);
        assert_eq!(
            nt[..16],
            [
                0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef,
                0x6a, 0x1c
            ]
        );
        assert_eq!(
            lm[..16],
            [
                0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc,
                0xcc, 0x19
            ]
        );
    }

    #[test]
    fn type3_roundtrip_fields() {
        let mut t2 = Vec::from(&SIG[..]);
        t2.extend_from_slice(&2u32.to_le_bytes());
        t2.extend_from_slice(&[0; 8]);
        t2.extend_from_slice(&FLAGS.to_le_bytes());
        t2.extend_from_slice(&[9; 8]);
        t2.extend_from_slice(&[0; 16]);
        let ch = Challenge::parse(&t2).unwrap();
        assert_eq!(ch.server_challenge, [9; 8]);
        let m = authenticate(&ch, "bob", "PUSAT", "pw").unwrap();
        assert_eq!(secbuf(&m, 28).unwrap(), utf16le("PUSAT"));
        assert_eq!(secbuf(&m, 36).unwrap(), utf16le("bob"));
    }
}
