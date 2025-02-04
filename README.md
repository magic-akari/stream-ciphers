# RustCrypto: stream ciphers [![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link] [![HAZMAT][hazmat-image]][hazmat-link]

Collection of [stream cipher][1] algorithms written in pure Rust.

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

Crates in this repository do not ensure ciphertexts are authentic (i.e. by
using a MAC to verify ciphertext integrity), which can lead to serious
vulnerabilities if used incorrectly!

Aside from the `chacha20` crate, no crates in this repository have yet
received any formal cryptographic and security reviews/audits.

**USE AT YOUR OWN RISK!**

## Crates
| Name         | Crates.io | Documentation | MSRV |
|--------------|-----------|---------------|------|
| [`cfb-mode`] | [![crates.io](https://img.shields.io/crates/v/cfb-mode.svg)](https://crates.io/crates/cfb-mode) | [![Documentation](https://docs.rs/cfb-mode/badge.svg)](https://docs.rs/cfb-mode) | 1.41 |
| [`cfb8`]     | [![crates.io](https://img.shields.io/crates/v/cfb8.svg)](https://crates.io/crates/cfb8) | [![Documentation](https://docs.rs/cfb8/badge.svg)](https://docs.rs/cfb8) | 1.41 |
| [`chacha20`] | [![crates.io](https://img.shields.io/crates/v/chacha20.svg)](https://crates.io/crates/chacha20) | [![Documentation](https://docs.rs/chacha20/badge.svg)](https://docs.rs/chacha20) | 1.51 |
| [`ctr`]      | [![crates.io](https://img.shields.io/crates/v/ctr.svg)](https://crates.io/crates/ctr) | [![Documentation](https://docs.rs/ctr/badge.svg)](https://docs.rs/ctr) | 1.41 |
| [`hc-256`]   | [![crates.io](https://img.shields.io/crates/v/hc-256.svg)](https://crates.io/crates/hc-256) | [![Documentation](https://docs.rs/hc-256/badge.svg)](https://docs.rs/hc-256) | 1.41 |
| [`ofb`]      | [![crates.io](https://img.shields.io/crates/v/ofb.svg)](https://crates.io/crates/ofb) | [![Documentation](https://docs.rs/ofb/badge.svg)](https://docs.rs/ofb) | 1.41 |
| [`rabbit`]  | [![crates.io](https://img.shields.io/crates/v/rabbit.svg)](https://crates.io/crates/rabbit) | [![Documentation](https://docs.rs/rabbit/badge.svg)](https://docs.rs/rabbit) | 1.41 |
| [`salsa20`]  | [![crates.io](https://img.shields.io/crates/v/salsa20.svg)](https://crates.io/crates/salsa20) | [![Documentation](https://docs.rs/salsa20/badge.svg)](https://docs.rs/salsa20) | 1.41 |

## MSRV Policy

Minimum Supported Rust Version (MSRV) can be changed in the future, but it will be
done with a minor version bump.

## Usage

Crates functionality is expressed in terms of traits defined in the [`cipher`][2] crate.

Let's use AES-128-OFB to demonstrate usage of synchronous stream cipher:

```rust
use aes::Aes128;
use ofb::Ofb;

// import relevant traits
use ofb::cipher::{NewStreamCipher, SyncStreamCipher};

// OFB mode implementation is generic over block ciphers
// we will create a type alias for convenience
type AesOfb = Ofb<Aes128>;

let key = b"very secret key.";
let iv = b"unique init vect";
let plaintext = b"The quick brown fox jumps over the lazy dog.";

let mut buffer = plaintext.to_vec();

// create cipher instance
let mut cipher = AesOfb::new_var(key, iv)?;

// apply keystream (encrypt)
cipher.apply_keystream(&mut buffer);

// and decrypt it back
AesOfb::new_var(key, iv)?.apply_keystream(&mut buffer);

// stream ciphers can be used with streaming messages
let mut cipher = AesOfb::new_var(key, iv).unwrap();
for chunk in buffer.chunks_mut(3) {
    cipher.apply_keystream(chunk);
}
```

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[deps-image]: https://deps.rs/repo/github/RustCrypto/stream-ciphers/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/stream-ciphers
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Stream_cipher
[2]: https://docs.rs/cipher

[//]: # (crates)

[`cfb-mode`]: https://github.com/RustCrypto/stream-ciphers/tree/master/cfb-mode
[`cfb8`]: https://github.com/RustCrypto/stream-ciphers/tree/master/cfb8
[`chacha20`]: https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20
[`ctr`]: https://github.com/RustCrypto/stream-ciphers/tree/master/ctr
[`hc-256`]: https://github.com/RustCrypto/stream-ciphers/tree/master/hc-256
[`ofb`]: https://github.com/RustCrypto/stream-ciphers/tree/master/ofb
[`rabbit`]: https://github.com/RustCrypto/stream-ciphers/tree/master/rabbit
[`salsa20`]: https://github.com/RustCrypto/stream-ciphers/tree/master/salsa20

