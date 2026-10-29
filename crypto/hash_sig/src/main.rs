// Hash-based post-quantum signatures, built up in three steps:
//   1. Lamport one-time signatures
//   2. WOTS+ (Winternitz) one-time signatures: smaller signatures via hash chains
//   3. Merkle tree over many WOTS keys (simplified XMSS): one public key, many signatures
//
// Security relies only on SHA-256 being one-way / collision resistant, which
// quantum computers don't break (Grover gives at most a square-root speedup),
// unlike RSA / ECDSA, which Shor's algorithm breaks.
// Standardised versions: XMSS / LMS (RFC 8391 / 8554, NIST SP 800-208) and
// SLH-DSA (SPHINCS+, FIPS 205).

mod hash;
mod lamport;
mod merkle;
mod wots;

use hash::N;

fn main() {
    println!("== 1. Lamport one-time signature ==");
    let (sk, pk) = lamport::keygen();
    let sig = lamport::sign(&sk, b"hello pqc");
    println!("public key: {} bytes, signature: {} bytes", 2 * 256 * N, 256 * N);
    println!("verify original: {}", lamport::verify(&pk, b"hello pqc", &sig));
    println!("verify tampered: {}", lamport::verify(&pk, b"hello pqc!", &sig));
    let one = lamport::revealed_secrets(&[b"msg-1"]);
    let two = lamport::revealed_secrets(&[b"msg-1", b"msg-2"]);
    println!("secrets revealed: 1 signature = {one}/512, 2 signatures = {two}/512 (reuse lets attackers mix and match)");

    println!("\n== 2. WOTS+ (w = {}) ==", wots::W);
    let sk_seed = hash::sha256(b"demo secret seed");
    let pub_seed = hash::sha256(b"demo public seed");
    let digest = hash::sha256(b"hello pqc");
    let wpk = wots::public_key(&sk_seed, &pub_seed, 0);
    let wsig = wots::sign(&digest, &sk_seed, &pub_seed, 0);
    println!("signature: {} chains x {N} = {} bytes", wots::LEN, wots::LEN * N);
    println!("verify original: {}", wots::public_key_from_sig(&wsig, &digest, &pub_seed, 0) == wpk);
    let other = hash::sha256(b"hello pqc!");
    println!("verify tampered: {}", wots::public_key_from_sig(&wsig, &other, &pub_seed, 0) == wpk);

    println!("\n== 3. Merkle tree / XMSS-style (height {}) ==", merkle::HEIGHT);
    let mut signer = merkle::Signer::keygen();
    println!("public key root: {}", hex::encode(signer.pk.root));
    println!("public key: {} bytes, signature: {} bytes, capacity: {} signatures",
        2 * N, merkle::Signature::SIZE, signer.remaining());
    for msg in [&b"tx #1"[..], b"tx #2", b"tx #3"] {
        let s = signer.sign(msg).unwrap();
        println!("signed {:?} with leaf {}: valid = {}", String::from_utf8_lossy(msg), s.index, merkle::verify(&signer.pk, msg, &s));
    }
    let s = signer.sign(b"pay alice 10").unwrap();
    println!("tampered message valid: {}", merkle::verify(&signer.pk, b"pay alice 99", &s));
    while signer.remaining() > 0 {
        signer.sign(b"filler").unwrap();
    }
    println!("after using all leaves, sign -> {:?}", signer.sign(b"one more").err().unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lamport_roundtrip() {
        let (sk, pk) = lamport::keygen();
        let sig = lamport::sign(&sk, b"m");
        assert!(lamport::verify(&pk, b"m", &sig));
        assert!(!lamport::verify(&pk, b"n", &sig));
    }

    #[test]
    fn wots_rejects_forward_hashed_forgery() {
        // Hashing a signature chain one step forward must not give a valid
        // signature for another message: the checksum digits catch it.
        let seed = hash::sha256(b"s");
        let ps = hash::sha256(b"p");
        let pk = wots::public_key(&seed, &ps, 0);
        let mut m = [0u8; N];
        let mut sig = wots::sign(&m, &seed, &ps, 0);
        let adrs = hash::Address { key: 0, chain: 0, step: 0 };
        sig[0] = hash::th(hash::Tag::Chain, &ps, adrs, &sig[0]); // digit 0 -> 1
        m[0] = 0x10;
        assert_ne!(wots::public_key_from_sig(&sig, &m, &ps, 0), pk);
    }

    #[test]
    fn merkle_all_leaves_verify_then_exhaust() {
        let mut s = merkle::Signer::keygen();
        for i in 0..1u32 << merkle::HEIGHT {
            let msg = i.to_be_bytes();
            let sig = s.sign(&msg).unwrap();
            assert_eq!(sig.index, i);
            assert!(merkle::verify(&s.pk, &msg, &sig));
        }
        assert_eq!(s.sign(b"x").err(), Some(merkle::Error::KeyExhausted));
    }

    #[test]
    fn merkle_rejects_tampering() {
        let mut s = merkle::Signer::keygen();
        let mut sig = s.sign(b"m").unwrap();
        assert!(!merkle::verify(&s.pk, b"n", &sig));
        sig.index = 1; // signature moved to another leaf
        assert!(!merkle::verify(&s.pk, b"m", &sig));
        sig.index = 0;
        sig.auth[2][0] ^= 1;
        assert!(!merkle::verify(&s.pk, b"m", &sig));
        let other = merkle::Signer::keygen();
        sig.auth[2][0] ^= 1;
        assert!(!merkle::verify(&other.pk, b"m", &sig));
    }
}
