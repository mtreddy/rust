# Cryptography examples in Rust

Each folder is its own Cargo crate. Run any of them with `cargo run` (add `--release` for the
heavier ones) and `cargo test` from inside the folder.

## Hashing, encoding, key derivation
| Crate | What it shows |
|---|---|
| [`sha`](sha) | SHA-256 hashing |
| [`encode`](encode) | Hex and base64 encoding |
| [`pbkdf`](pbkdf) | PBKDF2 password hashing (ring) |

## Symmetric encryption
| Crate | What it shows |
|---|---|
| [`aes_modes`](aes_modes) | ECB, CBC, CFB, OFB, CTR written by hand on AES, PKCS#7 padding, NIST test vectors, and each mode's weakness (ECB patterns, CBC bit flipping, CTR nonce reuse) |
| [`aes_gcm_example`](aes_gcm_example) | AES-256-GCM authenticated encryption with AAD |
| [`chacha20_example`](chacha20_example) | ChaCha20 from scratch (RFC 8439 vectors), ChaCha20-Poly1305, XChaCha20-Poly1305 |

## Public-key crypto and key exchange
| Crate | What it shows |
|---|---|
| [`rsa`](rsa) | RSA PKCS#1 v1.5 encryption |
| [`ecdsa`](ecdsa) | ECDSA signatures on secp256k1 (k256) |
| [`x25519_ecdh`](x25519_ecdh) | X25519 from scratch (RFC 7748 vectors), Ed25519 → X25519 key conversion, and an Ed25519-authenticated ECDH → HKDF → ChaCha20-Poly1305 exchange that resists man-in-the-middle attacks |

## Post-quantum
| Crate | What it shows |
|---|---|
| [`hash_sig`](hash_sig) | Hash-based signatures from scratch: Lamport, WOTS+, and a Merkle tree (simplified XMSS) |
| [`pqc_pki`](pqc_pki) | A post-quantum PKI on ML-DSA-65 (FIPS 204): keygen, certificate issuing, chain validation, document signing, and a CLI |

## Zero-knowledge proofs
| Crate | What it shows |
|---|---|
| [`fiat_shamir`](fiat_shamir) | The Fiat–Shamir identification protocol (square roots mod n), interactive and non-interactive |
| [`schnorr_zkp`](schnorr_zkp) | Schnorr, Chaum–Pedersen and Pedersen-opening proofs on Ristretto255, **with written security proofs** ([README](schnorr_zkp/README.md)) |
| [`nizk_examples`](nizk_examples) | Groth16 zk-SNARK (arkworks), Bulletproofs range proofs, and a STARK (Winterfell), compared side by side ([README](nizk_examples/README.md)) |
| [`zokrates`](zokrates) | ZoKrates circuits run in Docker: quadratic, square root, hash preimage, age range, with exported Solidity verifiers |

## Misc
| Crate | What it shows |
|---|---|
| [`sample`](sample) | Extended Euclidean algorithm |

> Everything written "from scratch" here is for learning. It is not constant-time and not
> hardened. Use the audited library versions (shown alongside in most crates) for real data.
