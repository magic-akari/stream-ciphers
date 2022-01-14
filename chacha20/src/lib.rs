//! The ChaCha20 stream cipher ([RFC 8439])
//!
//! ChaCha20 is a lightweight stream cipher which is amenable to fast,
//! constant-time implementations in software. It improves upon the previous
//! [ChaCha] stream cipher, providing increased per-round diffusion
//! with no cost to performance.
//!
//! Cipher functionality is accessed using traits from re-exported
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! This crate contains the following variants of the ChaCha20 core algorithm:
//!
//! - [`ChaCha20`]: standard IETF variant with 96-bit nonce
//! - [`ChaCha8`] / [`ChaCha12`]: reduced round variants of ChaCha20
//! - [`XChaCha20`]: 192-bit extended nonce variant
//! - [`XChaCha8`] / [`XChaCha12`]: reduced round variants of XChaCha20
//! - [`ChaCha20Legacy`]: "djb" variant with 64-bit nonce.
//! **WARNING:** This implementation interanlly uses 32-bit counter,
//! while the original implementation uses 64-bit coutner. In other words,
//! it does not allow encryption of more than 256 GiB of data.
//!
//! # ⚠️ Security Warning: [Hazmat!]
//!
//! This crate does not ensure ciphertexts are authentic, which can lead to
//! serious vulnerabilities if used incorrectly!
//!
//! If in doubt, use the [`chacha20poly1305`](https://docs.rs/chacha20poly1305)
//! crate instead, which provides an authenticated mode on top of ChaCha20.
//!
//! **USE AT YOUR OWN RISK!**
//!
//! # Diagram
//!
//! This diagram illustrates the ChaCha quarter round function.
//! Each round consists of four quarter-rounds:
//!
//! <img src="https://raw.githubusercontent.com/RustCrypto/meta/master/img/stream-ciphers/chacha20.png" width="300px">
//!
//! Legend:
//!
//! - ⊞ add
//! - ‹‹‹ rotate
//! - ⊕ xor
//!
//! # Usage
//!
//! ```
//! # #[cfg(feature = "cipher")]
//! # {
//! use chacha20::{ChaCha20, Key, Nonce};
//! use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
//!
//! let mut data = [1, 2, 3, 4, 5, 6, 7];
//!
//! let key = Key::from_slice(b"an example very very secret key.");
//! let nonce = Nonce::from_slice(b"secret nonce");
//!
//! // create cipher instance
//! let mut cipher = ChaCha20::new(&key, &nonce);
//!
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [73, 98, 234, 202, 73, 143, 0]);
//!
//! // seek to the keystream beginning and apply it again to the `data` (decrypt)
//! cipher.seek(0);
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
//! # }
//! ```
//!
//! [RFC 8439]: https://tools.ietf.org/html/rfc8439
//! [ChaCha]: https://docs.rs/salsa20
//! [Hazmat!]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/chacha20/0.8.1"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(
    all(feature = "neon", target_arch = "aarch64", target_feature = "neon"),
    feature(stdsimd, aarch64_target_feature)
)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

#[cfg(feature = "cipher")]
#[cfg_attr(docsrs, doc(cfg(feature = "cipher")))]
pub use cipher;

use cipher::{
    consts::{U10, U12, U32, U4, U6, U64},
    generic_array::{typenum::Unsigned, GenericArray},
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamClosure,
};
use core::{convert::TryInto, marker::PhantomData};

mod backends;
mod legacy;
mod xchacha;

pub use legacy::{ChaCha20Legacy, ChaCha20LegacyCore, LegacyNonce};
pub use xchacha::{hchacha, XChaCha12, XChaCha20, XChaCha8, XChaChaCore, XNonce};

/// State initialization constant ("expand 32-byte k")
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Number of 32-bit words in the ChaCha state
const STATE_WORDS: usize = 16;

/// Block type used by all ChaCha variants.
type Block = GenericArray<u8, U64>;

/// Key type used by all ChaCha variants.
pub type Key = GenericArray<u8, U32>;

/// Nonce type used by ChaCha variants.
pub type Nonce = GenericArray<u8, U12>;

/// ChaCha8 stream cipher (reduced-round variant of [`ChaCha20`] with 8 rounds)
pub type ChaCha8 = StreamCipherCoreWrapper<ChaChaCore<U4>>;

/// ChaCha12 stream cipher (reduced-round variant of [`ChaCha20`] with 12 rounds)
pub type ChaCha12 = StreamCipherCoreWrapper<ChaChaCore<U6>>;

/// ChaCha20 stream cipher (RFC 8439 version with 96-bit nonce)
pub type ChaCha20 = StreamCipherCoreWrapper<ChaChaCore<U10>>;

/// The ChaCha core function.
// TODO(tarcieri): zeroize support
pub struct ChaChaCore<R: Unsigned> {
    /// Internal state of the core function
    state: [u32; STATE_WORDS],
    /// Number of rounds to perform
    rounds: PhantomData<R>,
}

impl<R: Unsigned> KeySizeUser for ChaChaCore<R> {
    type KeySize = U32;
}

impl<R: Unsigned> IvSizeUser for ChaChaCore<R> {
    type IvSize = U12;
}

impl<R: Unsigned> BlockSizeUser for ChaChaCore<R> {
    type BlockSize = U64;
}

impl<R: Unsigned> KeyIvInit for ChaChaCore<R> {
    #[inline]
    fn new(key: &Key, iv: &Nonce) -> Self {
        let mut state = [0u32; STATE_WORDS];
        state[0..4].copy_from_slice(&CONSTANTS);
        let key_chunks = key.chunks_exact(4);
        for (val, chunk) in state[4..12].iter_mut().zip(key_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let iv_chunks = iv.chunks_exact(4);
        for (val, chunk) in state[13..16].iter_mut().zip(iv_chunks) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        Self {
            state,
            rounds: PhantomData,
        }
    }
}

impl<R: Unsigned> StreamCipherCore for ChaChaCore<R> {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        let rem = u32::MAX - self.get_block_pos();
        rem.try_into().ok()
    }

    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut backends::soft::Backend(self));
    }
}

impl<R: Unsigned> StreamCipherSeekCore for ChaChaCore<R> {
    type Counter = u32;

    #[inline(always)]
    fn get_block_pos(&self) -> u32 {
        self.state[12]
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u32) {
        self.state[12] = pos;
    }
}
