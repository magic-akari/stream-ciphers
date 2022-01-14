# RustCrypto: stream ciphers

[![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link] ![Apache2/MIT licensed][license-image] [![HAZMAT][hazmat-image]][hazmat-link]

Collection of [stream ciphers] written in pure Rust.

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

Crates in this repository do not ensure ciphertexts are authentic (i.e. by
using a MAC to verify ciphertext integrity), which can lead to serious
vulnerabilities if used incorrectly!

Aside from the `chacha20` crate, no crates in this repository have yet
received any formal cryptographic and security reviews/audits.

**USE AT YOUR OWN RISK!**

## Crates
| Name     | Crate name | Crates.io | Docs | MSRV |
|----------|------------|-----------|------|------|
| [ChaCha] | [`chacha20`] | [![crates.io](https://img.shields.io/crates/v/chacha20.svg)](https://crates.io/crates/chacha20) | [![Documentation](https://docs.rs/chacha20/badge.svg)](https://docs.rs/chacha20) | ![MSRV 1.51][msrv-1.51] |
| [HC-256] | [`hc-256`]   | [![crates.io](https://img.shields.io/crates/v/hc-256.svg)](https://crates.io/crates/hc-256) | [![Documentation](https://docs.rs/hc-256/badge.svg)](https://docs.rs/hc-256) | ![MSRV 1.49][msrv-1.49] |
| [Rabbit] | [`rabbit`]  | [![crates.io](https://img.shields.io/crates/v/rabbit.svg)](https://crates.io/crates/rabbit) | [![Documentation](https://docs.rs/rabbit/badge.svg)](https://docs.rs/rabbit) | ![MSRV 1.49][msrv-1.49] |
| [Salsa20] | [`salsa20`]  | [![crates.io](https://img.shields.io/crates/v/salsa20.svg)](https://crates.io/crates/salsa20) | [![Documentation](https://docs.rs/salsa20/badge.svg)](https://docs.rs/salsa20) | ![MSRV 1.49][msrv-1.49] |

### Minimum Supported Rust Version (MSRV) Policy

MSRV bump is considered a breaking change and will be performed only with a minor version bump.

## Usage

Crates functionality is expressed in terms of traits defined in the [`cipher`] crate.

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

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260049-stream-ciphers
[deps-image]: https://deps.rs/repo/github/RustCrypto/stream-ciphers/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/stream-ciphers
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md
[msrv-1.49]: https://img.shields.io/badge/rustc-1.49.0+-blue.svg
[msrv-1.51]: https://img.shields.io/badge/rustc-1.51.0+-blue.svg

[//]: # (footnotes)

[stream ciphers]: https://en.wikipedia.org/wiki/Stream_cipher
[`cipher`]: https://docs.rs/cipher

[//]: # (crates)

[`cfb-mode`]: https://github.com/RustCrypto/stream-ciphers/tree/master/cfb-mode
[`cfb8`]: https://github.com/RustCrypto/stream-ciphers/tree/master/cfb8
[`chacha20`]: https://github.com/RustCrypto/stream-ciphers/tree/master/chacha20
[`ctr`]: https://github.com/RustCrypto/stream-ciphers/tree/master/ctr
[`hc-256`]: https://github.com/RustCrypto/stream-ciphers/tree/master/hc-256
[`ofb`]: https://github.com/RustCrypto/stream-ciphers/tree/master/ofb
[`rabbit`]: https://github.com/RustCrypto/stream-ciphers/tree/master/rabbit
[`salsa20`]: https://github.com/RustCrypto/stream-ciphers/tree/master/salsa20

[//]: # (links)

[ChaCha]: https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
[HC-256]: https://en.wikipedia.org/wiki/HC-256
[Rabbit]: https://en.wikipedia.org/wiki/Rabbit_(cipher)
[Salsa20]: https://en.wikipedia.org/wiki/Salsa20
