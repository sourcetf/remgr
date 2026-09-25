//! frp control-channel crypto (post-login), mirroring
//! github.com/fatedier/golib `crypto.NewWriter/NewReader`:
//!
//! - key = PBKDF2-HMAC-SHA1(token, salt, iterations=64, len=16), where the salt
//!   is frp's, not golib's: since v0.44.0 every frp build sets
//!   `crypto.DefaultSalt = "frp"` in `client/service.go` and `cmd/frps/main.go`
//!   (checked in the v0.44.0 … v0.71.0 sources), overriding golib's own
//!   `"crypto"`. Only clients older than 0.44 derive with golib's default, which
//!   is what `crypto_salt` in the frps config is for.
//! - each direction: 16-byte random IV prefix, then AES-128-CFB (full-block
//!   feedback) applied as one continuous byte stream over all subsequent data.
//!
//! The `Login` message and `LoginResp` travel in plaintext; every control
//! message after that is encrypted. Work connections are never encrypted.
//!
//! Verified against a real frpc 0.71.0 (openbsd/amd64) talking to this server:
//! login, proxy registration and a tcp tunnel all complete with salt "frp".

use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const IV_LEN: usize = 16;
/// frp's `crypto.DefaultSalt`; see `FrpsConfig::crypto_salt`.
pub const DEFAULT_SALT: &str = "frp";

fn derive_key(token: &[u8], salt: &[u8]) -> [u8; IV_LEN] {
    let mut out = [0u8; IV_LEN];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(token, salt, 64, &mut out);
    out
}

/// AES-128-CFB128 keystream, byte-granular like Go's cipher.StreamReader/Writer.
pub(crate) struct Cfb {
    enc: Aes128,
    reg: [u8; IV_LEN],
    ks: [u8; IV_LEN],
    ct: [u8; IV_LEN],
    pos: usize,
    decrypt: bool,
}

impl Cfb {
    pub(crate) fn new(key: &[u8; IV_LEN], iv: &[u8; IV_LEN], decrypt: bool) -> Self {
        let enc = Aes128::new_from_slice(key).expect("aes-128 key");
        let mut s = Self { enc, reg: *iv, ks: [0; IV_LEN], ct: [0; IV_LEN], pos: IV_LEN, decrypt };
        s.refresh();
        s
    }

    fn refresh(&mut self) {
        let mut block = aes::Block::clone_from_slice(&self.reg);
        self.enc.encrypt_block(&mut block);
        self.ks.copy_from_slice(&block);
        self.pos = 0;
    }

    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.pos == IV_LEN {
                self.reg = self.ct;
                self.refresh();
            }
            if self.decrypt {
                // CFB-decrypt: the feedback register takes the ciphertext
                // (the input byte, before XOR)
                self.ct[self.pos] = *b;
                *b ^= self.ks[self.pos];
            } else {
                // CFB-encrypt: the feedback register takes the ciphertext
                // (the output byte, after XOR)
                *b ^= self.ks[self.pos];
                self.ct[self.pos] = *b;
            }
            self.pos += 1;
        }
    }
}

pub struct CryptoStream<S> {
    inner: S,
    key: [u8; IV_LEN],
    /// optional separate key for our writes (client read direction)
    write_key: Option<[u8; IV_LEN]>,

    // read side: peer's IV arrives before any ciphertext
    iv_read: usize,
    iv_buf: [u8; IV_LEN],
    dec: Option<Cfb>,

    // write side: our IV goes out before any ciphertext
    iv_written: usize,
    iv: [u8; IV_LEN],
    enc: Option<Cfb>,
    // ciphertext awaiting flush to inner (encrypt exactly once per buffer)
    pending: Option<(Vec<u8>, usize)>,
}

impl<S> CryptoStream<S> {
    pub fn new(inner: S, token: &[u8]) -> Self {
        Self::with_write_key(inner, token, None)
    }

    pub fn with_write_key(inner: S, read_pass: &[u8], write_pass: Option<&[u8]>) -> Self {
        Self::with_salt(inner, read_pass, write_pass, DEFAULT_SALT.as_bytes())
    }

    /// Same, with an explicit PBKDF2 salt (see `FrpsConfig::crypto_salt`).
    pub fn with_salt(inner: S, read_pass: &[u8], write_pass: Option<&[u8]>, salt: &[u8]) -> Self {
        let mut iv = [0u8; IV_LEN];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut iv);
        Self {
            inner,
            key: derive_key(read_pass, salt),
            write_key: write_pass.map(|p| derive_key(p, salt)),
            iv_read: 0,
            iv_buf: [0u8; IV_LEN],
            dec: None,
            iv_written: 0,
            iv,
            enc: None,
            pending: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CryptoStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.dec.is_none() {
            while this.iv_read < IV_LEN {
                let mut tmp = [0u8; IV_LEN];
                let want = IV_LEN - this.iv_read;
                let mut read_buf = ReadBuf::new(&mut tmp[..want]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "eof while reading crypto iv",
                            )));
                        }
                        this.iv_buf[this.iv_read..this.iv_read + n].copy_from_slice(read_buf.filled());
                        this.iv_read += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let iv = this.iv_buf;
            let hexs: String = iv.iter().map(|b| format!("{b:02x}")).collect();
            tracing::debug!("frps crypto: peer iv = {hexs}");
            this.dec = Some(Cfb::new(&this.key, &iv, true));
        }

        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = &mut buf.filled_mut()[before..];
                if !filled.is_empty() {
                    this.dec.as_mut().unwrap().apply(filled);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CryptoStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.enc.is_none() {
            while this.iv_written < IV_LEN {
                match Pin::new(&mut this.inner).poll_write(cx, &this.iv[this.iv_written..]) {
                    Poll::Ready(Ok(n)) => this.iv_written += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let iv = this.iv;
            let wk = this.write_key.unwrap_or(this.key);
            this.enc = Some(Cfb::new(&wk, &iv, false));
        }
        // Encrypt the caller's buffer exactly once; if the inner writer is
        // temporarily unavailable, keep the ciphertext and resume on the next
        // poll (the caller retries with the same buffer, per AsyncWrite).
        if this.pending.is_none() {
            let mut out = buf.to_vec();
            this.enc.as_mut().unwrap().apply(&mut out);
            this.pending = Some((out, 0));
        }
        let len = this.pending.as_ref().unwrap().0.len();
        while this.pending.as_ref().unwrap().1 < len {
            let (ref pending, off) = *this.pending.as_ref().unwrap();
            match Pin::new(&mut this.inner).poll_write(cx, &pending[off..]) {
                Poll::Ready(Ok(n)) => this.pending.as_mut().unwrap().1 += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.pending.take();
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    //! Hostile-input tests for the control cipher, in the spirit of
    //! `chunk_test`: the peer here is built from bare `Cfb`, so every byte that
    //! reaches the reader is chosen by the test, not by a cooperating writer.

    use super::*;
    use crate::msg;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn key_of(token: &[u8]) -> [u8; IV_LEN] {
        derive_key(token, DEFAULT_SALT.as_bytes())
    }

    /// The plaintext byte layout of a sequence of frames.
    fn plain_frames(frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut plain = Vec::new();
        for (tb, body) in frames {
            assert!(body.len() <= msg::MAX_MSG_LEN as usize);
            plain.push(*tb);
            plain.extend_from_slice(&(body.len() as i64).to_be_bytes());
            plain.extend_from_slice(body);
        }
        plain
    }

    /// Frames as the peer encrypts them: one continuous CFB stream, exactly
    /// like golib's `crypto.Writer` (which wraps the whole connection in a
    /// single `cipher.StreamWriter`, so the keystream never restarts).
    fn wire_frames(key: &[u8; IV_LEN], iv: &[u8; IV_LEN], frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut cfb = Cfb::new(key, iv, false);
        let mut plain = plain_frames(frames);
        cfb.apply(&mut plain);
        plain
    }

    /// Feed `data` to the peer side in chunks of the given sizes, one segment
    /// per write, so framing/segment boundaries never line up.
    async fn feed_chunks(peer: tokio::io::DuplexStream, mut data: Vec<u8>, sizes: &[usize]) {
        let mut peer = peer;
        let mut i = 0;
        let mut sent = 0;
        // every iteration removes at least one byte; a size of 0 would not
        let budget = data.len() + sizes.len() + 16;
        while !data.is_empty() {
            let take = sizes[i % sizes.len()].max(1).min(data.len());
            let rest = data.split_off(take);
            peer.write_all(&data).await.unwrap();
            // let the reader observe each partial write on its own
            tokio::task::yield_now().await;
            data = rest;
            i += 1;
            sent += 1;
            assert!(sent <= budget, "chunk loop did not terminate");
        }
        peer.flush().await.unwrap();
        // keep the peer alive (and the stream open) until the reader is done
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    async fn read_all(mut r: CryptoStream<tokio::io::DuplexStream>, count: usize) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        for _ in 0..count {
            out.push(msg::read_frame(&mut r).await.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn keystream_is_continuous_across_frame_boundaries() {
        // 34 frames of assorted sizes (0, 1, 15, 16, 17, 4096, 10240 bytes…):
        // if `apply` restarted its feedback register per call — or per frame —
        // every byte after the first 16 of each write would be garbage.
        let key = key_of(b"test123");
        let iv = [0x11u8; IV_LEN];
        let mut frames = Vec::new();
        for i in 0..34usize {
            let len = match i % 7 {
                0 => 0,
                1 => 1,
                2 => 15,
                3 => 16,
                4 => 17,
                5 => 4096,
                _ => 10240,
            };
            frames.push((b'a' + (i % 26) as u8, vec![(i % 251) as u8; len]));
        }
        let wire = wire_frames(&key, &iv, &frames);

        // IV and ciphertext in one byte per segment: the reader must take
        // exactly 16 bytes as the IV and treat the rest as ciphertext.
        let (peer, mine) = tokio::io::duplex(1 << 16);
        let mut all = iv.to_vec();
        all.extend_from_slice(&wire);
        let feeder = tokio::spawn(feed_chunks(peer, all, &[1]));
        let got = read_all(CryptoStream::new(mine, b"test123"), frames.len()).await;
        feeder.await.unwrap();
        assert_eq!(got, frames);

        // and again with adversarial segment sizes, run through the reader in
        // 1-byte reads
        let (peer, mine) = tokio::io::duplex(1 << 16);
        let mut all = iv.to_vec();
        all.extend_from_slice(&wire);
        let feeder = tokio::spawn(feed_chunks(peer, all, &[3, 1, 7, 64, 4096, 2]));
        let mut r = CryptoStream::new(mine, b"test123");
        let mut got = Vec::new();
        for _ in 0..frames.len() {
            let mut hdr = [0u8; 9];
            for b in hdr.iter_mut() {
                r.read_exact(std::slice::from_mut(b)).await.unwrap();
            }
            let len = i64::from_be_bytes(hdr[1..9].try_into().unwrap()) as usize;
            let mut body = vec![0u8; len];
            for b in body.iter_mut() {
                r.read_exact(std::slice::from_mut(b)).await.unwrap();
            }
            got.push((hdr[0], body));
        }
        feeder.await.unwrap();
        assert_eq!(got, frames);
    }

    #[tokio::test]
    async fn partial_iv_then_stall_then_continue() {
        // The 16-byte IV is peer-controlled and may arrive in pieces with an
        // arbitrary delay in between; a reader that lost the bytes read before
        // the stall (or derived the key from a partial IV) would garble
        // everything that follows.
        let key = key_of(b"tok");
        let iv = [0x5Au8; IV_LEN];
        let frames = vec![(b'2', b"{\"proxy_name\":\"web\"}".to_vec()), (b'h', Vec::new())];
        let wire = wire_frames(&key, &iv, &frames);

        let (mut peer, mine) = tokio::io::duplex(1 << 16);
        let reader = tokio::spawn(read_all(CryptoStream::new(mine, b"tok"), frames.len()));
        peer.write_all(&iv[..5]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        peer.write_all(&iv[5..12]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        peer.write_all(&iv[12..]).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        // a partial frame, then the rest
        let (head, tail) = wire.split_at(3);
        peer.write_all(head).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        peer.write_all(tail).await.unwrap();
        let got = reader.await.unwrap();
        assert_eq!(got, frames);
    }

    #[tokio::test]
    async fn hostile_ivs_are_accepted_without_state_damage() {
        // Any 16 bytes are a valid IV: all-zero, all-ones and a "close" value
        // must all decrypt correctly (the IV is not a secret and is not
        // validated by frp either).
        for iv in [[0u8; IV_LEN], [0xFFu8; IV_LEN], [0x42u8; IV_LEN]] {
            let key = key_of(b"");
            let frames = vec![(b'p', vec![7u8; 300]), (b'p', Vec::new())];
            let wire = wire_frames(&key, &iv, &frames);
            let (peer, mine) = tokio::io::duplex(1 << 16);
            let mut all = iv.to_vec();
            all.extend_from_slice(&wire);
            let feeder = tokio::spawn(feed_chunks(peer, all, &[16, 1, 1000]));
            // empty token: the key is derived from the empty string, not skipped
            let got = read_all(CryptoStream::new(mine, b""), frames.len()).await;
            feeder.await.unwrap();
            assert_eq!(got, frames);
        }
    }

    #[tokio::test]
    async fn eof_before_the_iv_is_an_error_not_a_hang() {
        let (mut peer, mine) = tokio::io::duplex(64);
        peer.write_all(&[1, 2, 3]).await.unwrap();
        drop(peer);
        let mut r = CryptoStream::new(mine, b"tok");
        let mut buf = [0u8; 32];
        let e = tokio::time::timeout(std::time::Duration::from_secs(5), r.read(&mut buf))
            .await
            .expect("read must not hang after a half IV")
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn our_writer_emits_one_continuous_stream() {
        // The mirror of the reader test: a peer that decrypts our writes with a
        // single Cfb (as golib does — one StreamWriter for the whole
        // connection) must recover the frames byte for byte, even though each
        // frame is written by its own `write_frame` call and the peer reads in
        // 7-byte pieces that never line up with a CFB block.
        let key = key_of(b"tok");
        let frames: Vec<(u8, Vec<u8>)> = (0..20)
            .map(|i| (b'p', vec![i as u8; if i % 3 == 0 { 0 } else { 1500 + i }]))
            .collect();
        let expected = plain_frames(&frames);
        let (mine, mut peer) = tokio::io::duplex(1 << 16);
        let writer = tokio::spawn(async move {
            let mut w = CryptoStream::new(mine, b"tok");
            for (tb, body) in &frames {
                msg::write_frame(&mut w, *tb, body).await.unwrap();
            }
            w.shutdown().await.unwrap();
        });
        // the peer's first 16 bytes are the writer's IV
        let mut ivbuf = [0u8; IV_LEN];
        peer.read_exact(&mut ivbuf).await.unwrap();
        let mut dec = Cfb::new(&key, &ivbuf, true);
        let mut plain = Vec::new();
        let mut buf = [0u8; 7];
        loop {
            match peer.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut chunk = buf[..n].to_vec();
                    dec.apply(&mut chunk);
                    plain.extend_from_slice(&chunk);
                }
            }
        }
        writer.await.unwrap();
        assert!(plain == expected, "keystream restarted mid-stream");
    }
}
