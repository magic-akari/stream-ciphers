//! HC-256 Stream Cipher

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_root_url = "https://docs.rs/hc-256/0.5.0"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    consts::{U32, U4},
    inout::InOutBuf,
    Block, BlockUser, Iv, IvUser, Key, KeyIvInit, KeyUser, StreamCipherCore,
    StreamCipherCoreWrapper,
};
use core::slice::from_ref;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const TABLE_SIZE: usize = 1024;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const INIT_SIZE: usize = 2660;
const KEY_BITS: usize = 256;
const KEY_WORDS: usize = KEY_BITS / 32;
const IV_BITS: usize = 256;
const IV_WORDS: usize = IV_BITS / 32;

/// The HC-256 stream cipher core
pub type Hc256 = StreamCipherCoreWrapper<Hc256Core>;

/// The HC-256 stream cipher core
pub struct Hc256Core {
    ptable: [u32; TABLE_SIZE],
    qtable: [u32; TABLE_SIZE],
    idx: u32,
}

impl BlockUser for Hc256Core {
    type BlockSize = U4;
}

impl KeyUser for Hc256Core {
    type KeySize = U32;
}

impl IvUser for Hc256Core {
    type IvSize = U32;
}

impl KeyIvInit for Hc256Core {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        fn f1(x: u32) -> u32 {
            x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
        }

        fn f2(x: u32) -> u32 {
            x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
        }

        let mut out = Self {
            ptable: [0; TABLE_SIZE],
            qtable: [0; TABLE_SIZE],
            idx: 0,
        };
        let mut data = [0; INIT_SIZE];

        for i in 0..KEY_WORDS {
            data[i] = key[4 * i] as u32 & 0xff
                | (key[(4 * i) + 1] as u32 & 0xff) << 8
                | (key[(4 * i) + 2] as u32 & 0xff) << 16
                | (key[(4 * i) + 3] as u32 & 0xff) << 24;
        }

        for i in 0..IV_WORDS {
            data[i + KEY_WORDS] = iv[4 * i] as u32 & 0xff
                | (iv[(4 * i) + 1] as u32 & 0xff) << 8
                | (iv[(4 * i) + 2] as u32 & 0xff) << 16
                | (iv[(4 * i) + 3] as u32 & 0xff) << 24;
        }

        for i in IV_WORDS + KEY_WORDS..INIT_SIZE {
            data[i] = f2(data[i - 2])
                .wrapping_add(data[i - 7])
                .wrapping_add(f1(data[i - 15]))
                .wrapping_add(data[i - 16])
                .wrapping_add(i as u32);
        }

        out.ptable[..TABLE_SIZE].clone_from_slice(&data[512..(TABLE_SIZE + 512)]);
        out.qtable[..TABLE_SIZE].clone_from_slice(&data[1536..(TABLE_SIZE + 1536)]);

        out.idx = 0;

        for _ in 0..4096 {
            out.gen_word();
        }

        out
    }
}

impl StreamCipherCore for Hc256Core {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn apply_keystream_blocks(
        &mut self,
        blocks: InOutBuf<'_, Block<Self>>,
        mut pre_fn: impl FnMut(&[Block<Self>]),
        mut post_fn: impl FnMut(&[Block<Self>]),
    ) {
        for mut block in blocks {
            pre_fn(from_ref(block.reborrow().get_in()));
            block
                .reborrow()
                .into_buf()
                .xor(&self.gen_word().to_le_bytes());
            post_fn(from_ref(block.reborrow().get_out()));
        }
    }
}

impl Hc256Core {
    #[inline]
    fn g1(&self, x: u32, y: u32) -> u32 {
        (x.rotate_right(10) ^ y.rotate_right(23))
            .wrapping_add(self.qtable[(x ^ y) as usize & TABLE_MASK])
    }

    #[inline]
    fn g2(&self, x: u32, y: u32) -> u32 {
        (x.rotate_right(10) ^ y.rotate_right(23))
            .wrapping_add(self.ptable[(x ^ y) as usize & TABLE_MASK])
    }

    #[inline]
    fn h1(&self, x: u32) -> u32 {
        self.qtable[(x & 0xff) as usize]
            .wrapping_add(self.qtable[(256 + ((x >> 8) & 0xff)) as usize])
            .wrapping_add(self.qtable[(512 + ((x >> 16) & 0xff)) as usize])
            .wrapping_add(self.qtable[(768 + ((x >> 24) & 0xff)) as usize])
    }

    #[inline]
    fn h2(&self, x: u32) -> u32 {
        self.qtable[(x & 0xff) as usize]
            .wrapping_add(self.qtable[(256 + ((x >> 8) & 0xff)) as usize])
            .wrapping_add(self.qtable[(512 + ((x >> 16) & 0xff)) as usize])
            .wrapping_add(self.qtable[(768 + ((x >> 24) & 0xff)) as usize])
    }

    fn gen_word(&mut self) -> u32 {
        let i = self.idx as usize;
        let j = self.idx as usize & TABLE_MASK;

        self.idx = (self.idx + 1) & (2048 - 1);

        if i < 1024 {
            self.ptable[j] = self.ptable[j]
                .wrapping_add(self.ptable[j.wrapping_sub(10) & TABLE_MASK])
                .wrapping_add(self.g1(
                    self.ptable[j.wrapping_sub(3) & TABLE_MASK],
                    self.ptable[j.wrapping_sub(1023) & TABLE_MASK],
                ));

            self.h1(self.ptable[j.wrapping_sub(12) & TABLE_MASK]) ^ self.ptable[j]
        } else {
            self.qtable[j] = self.qtable[j]
                .wrapping_add(self.qtable[j.wrapping_sub(10) & TABLE_MASK])
                .wrapping_add(self.g2(
                    self.qtable[j.wrapping_sub(3) & TABLE_MASK],
                    self.qtable[j.wrapping_sub(1023) & TABLE_MASK],
                ));

            self.h2(self.qtable[j.wrapping_sub(12) & TABLE_MASK]) ^ self.qtable[j]
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Hc256Core {
    fn zeroize(&mut self) {
        self.ptable.zeroize();
        self.qtable.zeroize();
        self.idx.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl core::ops::Drop for Hc256Core {
    fn drop(&mut self) {
        self.zeroize();
    }
}
