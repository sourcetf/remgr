//! frp control-channel crypto (post-login), mirroring
//! github.com/fatedier/golib `crypto.NewWriter/NewReader`:
//!
//! - key = PBKDF2-HMAC-SHA1(token, salt="frp", iterations=64, len=16)
//!   (verified against the official frps/frpc 0.61.2 release binaries; the
//!   salt in newer golib sources reads "crypto", the released binaries
//!   derive with "frp")
//! - each direction: 16-byte random IV prefix, then AES-128-CFB (full-block
//!   feedback) applied as one continuous byte stream over all subsequent data.
//!
//! The `Login` message and `LoginResp` travel in plaintext; every control
//! message after that is encrypted. Work connections are never encrypted.

use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const IV_LEN: usize = 16;

fn derive_key(token: &[u8]) -> [u8; IV_LEN] {
    let mut out = [0u8; IV_LEN];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(token, b"frp", 64, &mut out);
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
        let mut iv = [0u8; IV_LEN];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut iv);
        Self {
            inner,
            key: derive_key(read_pass),
            write_key: write_pass.map(derive_key),
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
