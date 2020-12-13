//! Generic implementations of CTR mode for block ciphers.
//!
//! Mode functionality is accessed using traits from re-exported
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! # ⚠️ Security Warning: [Hazmat!]
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # `Ctr128` Usage Example
//!
//! ```
//! use ctr::cipher::stream::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
//!
//! // `aes` crate provides AES block cipher implementation
//! type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
//!
//! let mut data = [1, 2, 3, 4, 5, 6, 7];
//!
//! let key = b"very secret key.";
//! let nonce = b"and secret nonce";
//!
//! // create cipher instance
//! let mut cipher = Aes128Ctr::new(key.into(), nonce.into());
//!
//! // apply keystream (encrypt)
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [6, 245, 126, 124, 180, 146, 37]);
//!
//! // seek to the keystream beginning and apply it again to the `data` (decrypt)
//! cipher.seek(0);
//! cipher.apply_keystream(&mut data);
//! assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
//! ```
//!
//! [Hazmat!]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;
use block_buffer::BlockBuffer;
use cipher::{
    block::{Block, BlockCipher, BlockEncrypt, ParBlocks},
    generic_array::{
        typenum::{Unsigned, U16},
        ArrayLength, GenericArray,
    },
    common::{FromBlockCipher},
    errors::{OverflowError, LoopError},
    stream::{SeekNum, StreamCipher, StreamCipherSeek},
};
use core::fmt;
use core::ops::Div;

pub mod flavors;
use flavors::CtrFlavor;

/// CTR mode with 128-bit big endian counter.
pub type Ctr128BE<B> = Ctr<B, flavors::Ctr128BE>;
/// CTR mode with 128-bit little endian counter.
pub type Ctr128LE<B> = Ctr<B, flavors::Ctr128LE>;
/// CTR mode with 64-bit big endian counter.
pub type Ctr64BE<B> = Ctr<B, flavors::Ctr64BE>;
/// CTR mode with 64-bit little endian counter.
pub type Ctr64LE<B> = Ctr<B, flavors::Ctr64LE>;
/// CTR mode with 32-bit big endian counter.
pub type Ctr32BE<B> = Ctr<B, flavors::Ctr32BE>;
/// CTR mode with 32-bit little endian counter.
pub type Ctr32LE<B> = Ctr<B, flavors::Ctr32LE>;

/// Generic CTR block mode isntance.
#[derive(Clone)]
pub struct Ctr<B, F>
where
    B: BlockEncrypt + BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    B::BlockSize: Div<F::Size>,
    F: CtrFlavor,
{
    cipher: B,
    nonce: GenericArray<F, F::Size>,
    counter: F,
    buffer: BlockBuffer<B::BlockSize>,
}

impl<B, F> Ctr<B, F>
where
    B: BlockEncrypt + BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    B::BlockSize: Div<F::Size>,
    F: CtrFlavor,
{
    fn check_data_len(&self, data: &[u8]) -> Result<(), LoopError> {
        let bs = B::BlockSize::USIZE;
        let leftover_bytes = self.buffer.remaining();
        if data.len() < leftover_bytes {
            return Ok(());
        }
        let blocks = 1 + (data.len() - leftover_bytes) / bs;
        self.counter
            .checked_add(blocks)
            .ok_or(LoopError)
            .map(|_| ())
    }

    /// Seek to the given block
    // TODO: replace with a trait-based method
    pub fn seek_block(&mut self, block: F::Backend) {
        self.counter = F::from_backend(block);
    }

    /// Return number of the current block
    // TODO: replace with a trait-based method
    pub fn current_block(&self) -> F::Backend {
        self.counter.to_backend()
    }
}

impl<B, F> FromBlockCipher for Ctr<B, F>
where
    B: BlockEncrypt + BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    B::BlockSize: Div<F::Size>,
    F: CtrFlavor,
{
    type BlockCipher = B;
    type NonceSize = B::BlockSize;

    #[inline]
    fn from_block_cipher(cipher: B, nonce: &Block<B>) -> Self {
        let nonce = F::load(nonce);
        Self {
            cipher,
            buffer: Default::default(),
            nonce,
            counter: Default::default(),
        }
    }
}

impl<B, F> StreamCipher for Ctr<B, F>
where
    B: BlockEncrypt + BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    B::BlockSize: Div<F::Size>,
    F: CtrFlavor,
{
    fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
        self.check_data_len(data)?;
        let Self { buffer, cipher, nonce, counter } = self;
        buffer.par_xor_data(
            data,
            counter,
            |ctr| {
                let mut t: Block<B> = ctr.generate_block(&nonce);
                ctr.increment();
                cipher.encrypt_block(&mut t);
                t
            },
            |ctr| {
                let mut blocks: ParBlocks<B> = Default::default();
                for block in blocks.iter_mut() {
                    *block = ctr.generate_block(&nonce);
                    ctr.increment();
                }
                cipher.encrypt_par_blocks(&mut blocks);
                blocks
            }
        );

        Ok(())
    }
}

impl<B, F> StreamCipherSeek for Ctr<B, F>
where
    B: BlockEncrypt + BlockCipher<BlockSize = U16>,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    B::BlockSize: Div<F::Size>,
    F: CtrFlavor,
{
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError> {
        let pos = self.buffer.get_pos() as u8;
        T::from_block_byte(self.counter.to_backend(), pos, B::BlockSize::U8)
    }

    fn try_seek<S: SeekNum>(&mut self, pos: S) -> Result<(), LoopError> {
        let (ctr, pos) = pos.to_block_byte(B::BlockSize::U8)?;
        self.counter = F::from_backend(ctr);
        if pos != 0 {
            let mut block = self.counter.generate_block(&self.nonce);
            self.counter.increment();
            self.cipher.encrypt_block(&mut block);
            self.buffer.set(block, pos as usize);
        } else {
            // `reset` sets cursor to 0 without updating the underlying buffer
            self.buffer.reset();
        }
        Ok(())
    }
}

impl<B, F> fmt::Debug for Ctr<B, F>
where
    B: BlockEncrypt + BlockCipher<BlockSize = U16> + fmt::Debug,
    B::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    B::BlockSize: Div<F::Size>,
    F: CtrFlavor + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Ctr-{:?}-{:?}", self.counter, self.cipher)
    }
}
