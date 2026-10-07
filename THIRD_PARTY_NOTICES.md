# Third-party notices

The unchanged JSON fixtures and schemas under `contracts/identity-v1/` come from
the public Apache-2.0 Munarium platform hub at
`c46f86400732223a6a7c23f5d186250ab4a144eb`. Their original locks and expectations
are retained. The optional interoperability probe builds public Munarium Warden
at `e89367ca2ce613760d43ef3ef9139980b41c4dd2` in a temporary checkout and retains
its license/notices and locked dependencies there. Warden code is not vendored
into Registry or added to Registry's production dependency graph.

REG-01 pins four direct crates for JSON, base64url, hashing and Ed25519 verification.
All packages below come from crates.io; Cargo.lock records versions and checksums.
Repository links and license expressions were read from resolved package manifests.
This is a provenance/license inventory, not a vulnerability audit or independent review.
No upstream implementation source is vendored. Redistributors must retain applicable
upstream license terms and notices with dependency binaries/sources.

Direct choices: base64 0.22.1, serde_json 1.0.149 and sha2 0.10.9 use MIT OR Apache-2.0;
ed25519-dalek 2.2.0 uses BSD-3-Clause. Dalek uses std and fast features here; the library
does not generate keys, access a network or call provider APIs.

The table includes optional/target-specific lock entries, not a claim that all are linked.
Existing attribution in the repository's governance documents remains applicable.

| Package | Version | License expression | Upstream |
|---|---|---|---|
| base64 | 0.22.1 | MIT OR Apache-2.0 | [Source](https://github.com/marshallpierce/rust-base64) |
| base64ct | 1.8.3 | Apache-2.0 OR MIT | [Source](https://github.com/RustCrypto/formats) |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 | [Source](https://github.com/RustCrypto/utils) |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | [Source](https://github.com/rust-lang/cfg-if) |
| const-oid | 0.9.6 | Apache-2.0 OR MIT | [Source](https://github.com/RustCrypto/formats/tree/master/const-oid) |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 | [Source](https://github.com/RustCrypto/utils) |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 | [Source](https://github.com/RustCrypto/traits) |
| curve25519-dalek | 4.1.3 | BSD-3-Clause | [Source](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek) |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 | [Source](https://github.com/dalek-cryptography/curve25519-dalek) |
| der | 0.7.10 | Apache-2.0 OR MIT | [Source](https://github.com/RustCrypto/formats/tree/master/der) |
| digest | 0.10.7 | MIT OR Apache-2.0 | [Source](https://github.com/RustCrypto/traits) |
| ed25519 | 2.2.3 | Apache-2.0 OR MIT | [Source](https://github.com/RustCrypto/signatures/tree/master/ed25519) |
| ed25519-dalek | 2.2.0 | BSD-3-Clause | [Source](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek) |
| fiat-crypto | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause | [Source](https://github.com/mit-plv/fiat-crypto) |
| generic-array | 0.14.7 | MIT | [Source](https://github.com/fizyk20/generic-array.git) |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | [Source](https://github.com/rust-random/getrandom) |
| itoa | 1.0.18 | MIT OR Apache-2.0 | [Source](https://github.com/dtolnay/itoa) |
| libc | 0.2.189 | MIT OR Apache-2.0 | [Source](https://github.com/rust-lang/libc) |
| memchr | 2.8.3 | Unlicense OR MIT | [Source](https://github.com/BurntSushi/memchr) |
| pkcs8 | 0.10.2 | Apache-2.0 OR MIT | [Source](https://github.com/RustCrypto/formats/tree/master/pkcs8) |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 | [Source](https://github.com/dtolnay/proc-macro2) |
| quote | 1.0.47 | MIT OR Apache-2.0 | [Source](https://github.com/dtolnay/quote) |
| rand_core | 0.6.4 | MIT OR Apache-2.0 | [Source](https://github.com/rust-random/rand) |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 | [Source](https://github.com/djc/rustc-version-rs) |
| semver | 1.0.27 | MIT OR Apache-2.0 | [Source](https://github.com/dtolnay/semver) |
| serde | 1.0.229 | MIT OR Apache-2.0 | [Source](https://github.com/serde-rs/serde) |
| serde_core | 1.0.229 | MIT OR Apache-2.0 | [Source](https://github.com/serde-rs/serde) |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 | [Source](https://github.com/serde-rs/serde) |
| serde_json | 1.0.149 | MIT OR Apache-2.0 | [Source](https://github.com/serde-rs/json) |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | [Source](https://github.com/RustCrypto/hashes) |
| signature | 2.2.0 | Apache-2.0 OR MIT | [Source](https://github.com/RustCrypto/traits/tree/master/signature) |
| spki | 0.7.3 | Apache-2.0 OR MIT | [Source](https://github.com/RustCrypto/formats/tree/master/spki) |
| subtle | 2.6.1 | BSD-3-Clause | [Source](https://github.com/dalek-cryptography/subtle) |
| syn | 2.0.119 | MIT OR Apache-2.0 | [Source](https://github.com/dtolnay/syn) |
| syn | 3.0.6 | MIT OR Apache-2.0 | [Source](https://github.com/dtolnay/syn) |
| typenum | 1.20.1 | MIT OR Apache-2.0 | [Source](https://github.com/paholg/typenum) |
| unicode-ident | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 | [Source](https://github.com/dtolnay/unicode-ident) |
| version_check | 0.9.5 | MIT/Apache-2.0 | [Source](https://github.com/SergioBenitez/version_check) |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [Source](https://github.com/bytecodealliance/wasi) |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | [Source](https://github.com/RustCrypto/utils) |
| zmij | 1.0.23 | MIT | [Source](https://github.com/dtolnay/zmij) |
