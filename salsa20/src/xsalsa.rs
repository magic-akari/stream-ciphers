//! XSalsa20 is an extended nonce variant of Salsa20

use super::{quarter_round, Backend, Key, Nonce, Salsa20Core, XNonce, CONSTANTS};
use cipher::{
    consts::{U16, U20, U24, U32, U64},
    generic_array::GenericArray,
    BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamClosure,
};
use core::convert::TryInto;

/// XSalsa20 is a Salsa20 variant with an extended 192-bit (24-byte) nonce.
///
/// Based on the paper "Extending the Salsa20 Nonce":
///
/// <https://cr.yp.to/snuffle/xsalsa-20081128.pdf>
///
/// The `xsalsa20` Cargo feature must be enabled in order to use this
/// (which it is by default).
pub type XSalsa20 = StreamCipherCoreWrapper<XSalsa20Core>;

/// The XSalsa20 core function.
pub struct XSalsa20Core(Salsa20Core<U20>);

impl KeySizeUser for XSalsa20Core {
    type KeySize = U32;
}

impl IvSizeUser for XSalsa20Core {
    type IvSize = U24;
}

impl BlockSizeUser for XSalsa20Core {
    type BlockSize = U64;
}

impl KeyIvInit for XSalsa20Core {
    fn new(key: &Key, iv: &XNonce) -> Self {
        let subkey = hsalsa20(key, iv[..16].as_ref().into());
        let mut padded_iv = Nonce::default();
        padded_iv.copy_from_slice(&iv[16..]);
        XSalsa20Core(Salsa20Core::new(&subkey, &padded_iv))
    }
}

impl StreamCipherCore for XSalsa20Core {
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        self.0.remaining_blocks()
    }

    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Backend(&mut self.0));
    }
}

impl StreamCipherSeekCore for XSalsa20Core {
    type Counter = u64;

    #[inline(always)]
    fn get_block_pos(&self) -> u64 {
        self.0.get_block_pos()
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: u64) {
        self.0.set_block_pos(pos);
    }
}

/// The HSalsa20 function defined in the paper "Extending the Salsa20 nonce"
///
/// <https://cr.yp.to/snuffle/xsalsa-20110204.pdf>
///
/// HSalsa20 takes 512-bits of input:
///
/// - Constants (`u32` x 4)
/// - Key (`u32` x 8)
/// - Nonce (`u32` x 4)
///
/// It produces 256-bits of output suitable for use as a Salsa20 key
#[cfg_attr(docsrs, doc(cfg(feature = "hsalsa20")))]
pub fn hsalsa20(key: &Key, input: &GenericArray<u8, U16>) -> GenericArray<u8, U32> {
    let mut state = [0u32; 16];

    state[0] = CONSTANTS[0];
    state[5] = CONSTANTS[1];
    state[10] = CONSTANTS[2];
    state[15] = CONSTANTS[3];

    for (i, chunk) in key.chunks(4).take(4).enumerate() {
        state[1 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    for (i, chunk) in key.chunks(4).skip(4).enumerate() {
        state[11 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    for (i, chunk) in input.chunks(4).enumerate() {
        state[6 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // 20 rounds consisting of 10 column rounds and 10 diagonal rounds
    for _ in 0..10 {
        // column rounds
        quarter_round(0, 4, 8, 12, &mut state);
        quarter_round(5, 9, 13, 1, &mut state);
        quarter_round(10, 14, 2, 6, &mut state);
        quarter_round(15, 3, 7, 11, &mut state);

        // diagonal rounds
        quarter_round(0, 1, 2, 3, &mut state);
        quarter_round(5, 6, 7, 4, &mut state);
        quarter_round(10, 11, 8, 9, &mut state);
        quarter_round(15, 12, 13, 14, &mut state);
    }

    let mut output = GenericArray::default();
    let key_idx: [usize; 8] = [0, 5, 10, 15, 6, 7, 8, 9];

    for (i, chunk) in output.chunks_mut(4).enumerate() {
        chunk.copy_from_slice(&state[key_idx[i]].to_le_bytes());
    }

    output
}
