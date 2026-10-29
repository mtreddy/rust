// X25519 from scratch (RFC 7748), using big integers for clarity.
//
// Curve25519 in Montgomery form:  v^2 = u^3 + 486662 u^2 + u   over  p = 2^255 - 19
// Ed25519 uses the *same* curve in twisted Edwards form (-x^2 + y^2 = 1 + d x^2 y^2);
// the two are birationally equivalent, so points/keys can be converted between them:
//   u = (1 + y) / (1 - y)
//
// X25519 only uses the u-coordinate. Scalar multiplication k*P is done with the
// Montgomery ladder: two running points (R0, R1) with R1 - R0 = P always holds,
// and each bit of k does one "add" and one "double". The same operations run for
// every bit, which is what makes it easy to implement in constant time.
//
// ECDH:  a = Alice secret, A = a*G;  b = Bob secret, B = b*G   (G has u = 9)
//        Alice computes a*B, Bob computes b*A; both equal (a*b)*G.
//
// NOT constant-time (BigUint ops and the branchy swap leak timing). For learning only.

use num_bigint::BigUint;
use num_traits::{One, Zero};

fn p() -> BigUint {
    (BigUint::one() << 255u32) - 19u32
}

/// Scalar clamping: clear the low 3 bits (multiple of the cofactor 8, kills
/// small-subgroup attacks), clear bit 255 and set bit 254 (fixed ladder length).
fn clamp(k: &[u8; 32]) -> BigUint {
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    BigUint::from_bytes_le(&k)
}

fn decode_u(u: &[u8; 32]) -> BigUint {
    let mut u = *u;
    u[31] &= 127; // ignore the top bit, as RFC 7748 requires
    BigUint::from_bytes_le(&u) % p()
}

fn encode_u(u: &BigUint) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = u.to_bytes_le();
    out[..b.len()].copy_from_slice(&b);
    out
}

pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let p = p();
    let k = clamp(scalar);
    let x1 = decode_u(u);
    let a24 = BigUint::from(121665u32); // (486662 - 2) / 4

    let add = |a: &BigUint, b: &BigUint| (a + b) % &p;
    let sub = |a: &BigUint, b: &BigUint| (a + &p - b) % &p;
    let mul = |a: &BigUint, b: &BigUint| (a * b) % &p;

    // Projective coordinates (X : Z), u = X / Z. Start with R0 = infinity, R1 = P.
    let (mut x2, mut z2) = (BigUint::one(), BigUint::zero());
    let (mut x3, mut z3) = (x1.clone(), BigUint::one());
    let mut swap = false;

    for t in (0..255).rev() {
        let bit = k.bit(t);
        swap ^= bit;
        if swap {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = bit;

        // Combined differential add (R0 + R1) and double (2 * R0).
        let a = add(&x2, &z2);
        let aa = mul(&a, &a);
        let b = sub(&x2, &z2);
        let bb = mul(&b, &b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        let s = add(&da, &cb);
        x3 = mul(&s, &s);
        let s = sub(&da, &cb);
        z3 = mul(&x1, &mul(&s, &s));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&aa, &mul(&a24, &e)));
    }
    if swap {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }

    // u = X / Z = X * Z^(p-2)  (Fermat inverse). Z = 0 (point at infinity) gives 0.
    let z_inv = z2.modpow(&(&p - 2u32), &p);
    encode_u(&mul(&x2, &z_inv))
}

pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASEPOINT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn rfc7748_scalar_mult_vector() {
        // RFC 7748 section 5.2
        let k = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(hex::encode(x25519(&k, &u)), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    #[test]
    fn rfc7748_diffie_hellman_vector() {
        // RFC 7748 section 6.1
        let a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let pa = public_key(&a);
        let pb = public_key(&b);
        assert_eq!(hex::encode(pa), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(hex::encode(pb), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(hex::encode(x25519(&a, &pb)), shared);
        assert_eq!(hex::encode(x25519(&b, &pa)), shared);
    }
}
