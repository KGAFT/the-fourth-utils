use std::sync::atomic::{AtomicU64, Ordering};
use aead::AeadInPlace;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{ KeyInit},
};use hkdf::Hkdf;
use sha2::Sha256;
use bytes::BytesMut;

/// Per-direction AEAD state for the tunnel.
///
/// The record counter is **implicit**: it is never written to the wire. Both
/// ends derive it from their own position in the stream, exactly as TLS 1.3
/// does with its sequence number (RFC 8446 §5.2). Transmitting it would put a
/// small, zero-padded, monotonically increasing big-endian integer at a fixed
/// offset in every record, which is a stateless DPI signature — real TLS 1.3
/// record bodies are indistinguishable from random.
///
/// This relies on the transport being ordered and lossless (TCP + a framed
/// codec). A gap or reorder is unrecoverable by design: the counters desync,
/// the tag fails, and the connection dies. That is the intended failure mode.
pub struct SessionKeys {
    pub send: Aes256Gcm,
    pub recv: Aes256Gcm,

    /// Per-session, per-direction base IV. The counter is XORed into this to
    /// form the nonce. This adds no *uniqueness* — XOR by a constant is a
    /// bijection, so unique counters already give unique nonces — but it makes
    /// the nonce unpredictable without the session secret, so no structure
    /// derived from the record index is recoverable by an observer.
    send_base_iv: [u8; NONCE_LEN],
    recv_base_iv: [u8; NONCE_LEN],

    /// Next outbound record counter.
    send_counter: AtomicU64,

    /// Counter of the last successfully authenticated inbound record.
    recv_counter: AtomicU64,
}


const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;


struct OffsetBuffer<'a> {
    buf: &'a mut BytesMut,
    offset: usize,
}

impl AsRef<[u8]> for OffsetBuffer<'_> {
    fn as_ref(&self) -> &[u8] { &self.buf[self.offset..] }
}

impl AsMut<[u8]> for OffsetBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.buf[self.offset..] }
}

impl aead::Buffer for OffsetBuffer<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.buf.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.buf.truncate(self.offset + len);
    }
}
/// Label for the client's key-confirmation tag.
pub const CONFIRM_LABEL_CLIENT: &[u8] = b"tf-confirm-client";
/// Label for the server's key-confirmation tag.
pub const CONFIRM_LABEL_SERVER: &[u8] = b"tf-confirm-server";

/// Derive a key-confirmation tag from the SPAKE2 shared output.
///
/// Only a party that ran SPAKE2 with the correct password can compute `shared`,
/// so a PRF keyed by it over the handshake transcript proves password knowledge
/// without ever exposing the password to an offline dictionary attack.
/// HKDF-Expand is HMAC-SHA256 underneath, so with `shared` as IKM and
/// `label || transcript` as `info` this is a MAC over the transcript keyed by
/// the shared secret. The distinct labels keep the two directions' tags — and
/// the tunnel keys, which expand the same IKM under different `info` — mutually
/// independent.
pub fn derive_confirmation_tag(shared: &[u8], label: &[u8], transcript: &[u8]) -> Option<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(label.len() + transcript.len());
    info.extend_from_slice(label);
    info.extend_from_slice(transcript);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).ok()?;
    Some(out)
}

/// Constant-time byte-slice comparison, so verifying a confirmation tag cannot
/// leak how many leading bytes matched through timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl SessionKeys {
    /// Derive the tunnel keys, bound to the handshake transcript.
    ///
    /// The transcript goes in as the HKDF salt so the session keys commit to the
    /// exact handshake that produced them; two runs that agreed on a password
    /// but not on what was said still end up with different keys.
    pub fn derive_session_keys(shared: &[u8], transcript: &[u8], is_server: bool) -> Option<Self> {
        let hk = Hkdf::<Sha256>::new(Some(transcript), shared);

        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        let mut iv_a = [0u8; NONCE_LEN];
        let mut iv_b = [0u8; NONCE_LEN];

        hk.expand(b"aes-tunnel-key-a", &mut key_a).ok()?;
        hk.expand(b"aes-tunnel-key-b", &mut key_b).ok()?;
        hk.expand(b"aes-tunnel-iv-a", &mut iv_a).ok()?;
        hk.expand(b"aes-tunnel-iv-b", &mut iv_b).ok()?;

        let (send_key, recv_key, send_iv, recv_iv) = if is_server {
            (key_b, key_a, iv_b, iv_a)
        } else {
            (key_a, key_b, iv_a, iv_b)
        };

        Some(Self {
            send: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&send_key)),
            recv: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&recv_key)),
            send_base_iv: send_iv,
            recv_base_iv: recv_iv,
            send_counter: AtomicU64::new(1),
            recv_counter: AtomicU64::new(0),
        })
    }

    #[inline]
    fn nonce_from_counter(base_iv: &[u8; NONCE_LEN], counter: u64) -> [u8; NONCE_LEN] {
        let mut nonce = *base_iv;
        let counter_bytes = counter.to_be_bytes();
        // Right-align the counter against the IV, as TLS 1.3 does.
        for (n, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(counter_bytes.iter()) {
            *n ^= *c;
        }
        nonce
    }

    fn next_send_counter(&self) -> Option<u64> {
        let mut current = self.send_counter.load(Ordering::Relaxed);
        loop {
            if current == u64::MAX {
                return None;
            }
            match self.send_counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(current),
                Err(actual) => current = actual,
            }
        }
    }

    pub fn seal_in_place(&self, buf: &mut BytesMut) -> Option<()> {
        let counter = self.next_send_counter()?;

        let counter_bytes = counter.to_be_bytes();
        let nonce_bytes = Self::nonce_from_counter(&self.send_base_iv, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        buf.reserve(TAG_LEN);

        let mut framed = OffsetBuffer { buf: &mut *buf, offset: 0 };
        self.send
            .encrypt_in_place(nonce, &counter_bytes, &mut framed)
            .ok()?;

        Some(())
    }

    pub fn open_in_place(&self, buf: &mut BytesMut) -> Option<()> {
        if buf.len() < TAG_LEN {
            return None;
        }

        let last = self.recv_counter.load(Ordering::Acquire);
        let counter = last.checked_add(1)?;

        let counter_bytes = counter.to_be_bytes();
        let nonce_bytes = Self::nonce_from_counter(&self.recv_base_iv, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut framed = OffsetBuffer { buf: &mut *buf, offset: 0 };
        self.recv
            .decrypt_in_place(nonce, &counter_bytes, &mut framed)
            .ok()?;


        self.recv_counter
            .compare_exchange(last, counter, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;

        Some(())
    }

    pub const fn seal_overhead() -> usize {
        TAG_LEN
    }


    pub const fn sealed_len(plaintext_len: usize) -> usize {
        plaintext_len + Self::seal_overhead()
    }

    pub const fn plaintext_len(sealed_len: usize) -> Option<usize> {
        sealed_len.checked_sub(Self::seal_overhead())
    }
}