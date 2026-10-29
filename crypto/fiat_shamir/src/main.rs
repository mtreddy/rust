// Fiat-Shamir identification protocol and its non-interactive variant.
//
// Setup (trusted party):
//   n = p * q              (p, q large secret primes; factoring n is hard)
// Prover key:
//   secret  s  in Z_n*     (coprime with n)
//   public  v = s^2 mod n
//
// Interactive round (repeated `ROUNDS` times):
//   1. Commit:    prover picks random r, sends x = r^2 mod n
//   2. Challenge: verifier sends random bit e in {0, 1}
//   3. Response:  prover sends y = r * s^e mod n
//   4. Verify:    y^2 == x * v^e mod n
// A cheater who doesn't know s can pass one round with probability 1/2,
// so k rounds give soundness error 2^-k.
//
// Non-interactive (Fiat-Shamir heuristic): the prover computes all k
// commitments first, then derives the k challenge bits from
// H(n || v || msg || x_1 .. x_k). Binding `msg` into the hash turns the
// proof into a signature on msg.

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const PRIME_BITS: u64 = 512;
const ROUNDS: usize = 40;
const MR_ITERATIONS: usize = 40;

// ---------- number theory helpers ----------

fn is_probable_prime(n: &BigUint) -> bool {
    let two = BigUint::from(2u32);
    if *n < two {
        return false;
    }
    for p in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let p = BigUint::from(p);
        if *n == p {
            return true;
        }
        if (n % &p).is_zero() {
            return false;
        }
    }

    // Miller-Rabin: write n - 1 = d * 2^r with d odd
    let n_minus_1 = n - 1u32;
    let r = n_minus_1.trailing_zeros().unwrap();
    let d = &n_minus_1 >> r;

    let mut rng = OsRng;
    'witness: for _ in 0..MR_ITERATIONS {
        let a = rng.gen_biguint_range(&two, &n_minus_1);
        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }
        for _ in 1..r {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn gen_prime(bits: u64) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut c = rng.gen_biguint(bits);
        c.set_bit(bits - 1, true); // force full bit length
        c.set_bit(0, true); // force odd
        if is_probable_prime(&c) {
            return c;
        }
    }
}

/// Random element of Z_n* (1 <= r < n, gcd(r, n) == 1).
fn random_unit(n: &BigUint) -> BigUint {
    let mut rng = OsRng;
    loop {
        let r = rng.gen_biguint_range(&BigUint::one(), n);
        if r.gcd(n).is_one() {
            return r;
        }
    }
}

// ---------- keys ----------

pub struct PublicKey {
    pub n: BigUint,
    pub v: BigUint,
}

pub struct Prover {
    pub pk: PublicKey,
    s: BigUint,
}

impl Prover {
    pub fn keygen() -> Self {
        let p = gen_prime(PRIME_BITS);
        let q = loop {
            let q = gen_prime(PRIME_BITS);
            if q != p {
                break q;
            }
        };
        let n = &p * &q;
        // p and q are no longer needed; only n is published.
        let s = random_unit(&n);
        let v = s.modpow(&BigUint::from(2u32), &n);
        Prover { pk: PublicKey { n, v }, s }
    }

    /// Step 1: commitment. Returns (secret r, public x = r^2 mod n).
    pub fn commit(&self) -> (BigUint, BigUint) {
        let r = random_unit(&self.pk.n);
        let x = (&r * &r) % &self.pk.n;
        (r, x)
    }

    /// Step 3: response y = r * s^e mod n.
    pub fn respond(&self, r: &BigUint, e: bool) -> BigUint {
        if e {
            (r * &self.s) % &self.pk.n
        } else {
            r.clone()
        }
    }
}

// ---------- interactive protocol ----------

pub struct Verifier<'a> {
    pk: &'a PublicKey,
}

impl<'a> Verifier<'a> {
    pub fn new(pk: &'a PublicKey) -> Self {
        Verifier { pk }
    }

    /// Step 2: random challenge bit.
    pub fn challenge(&self) -> bool {
        rand::random::<bool>()
    }

    /// Step 4: check y^2 == x * v^e mod n (and that y, x are non-zero units).
    pub fn check(&self, x: &BigUint, e: bool, y: &BigUint) -> bool {
        verify_round(self.pk, x, e, y)
    }
}

fn verify_round(pk: &PublicKey, x: &BigUint, e: bool, y: &BigUint) -> bool {
    let n = &pk.n;
    // Reject y = 0 (would trivially satisfy the equation with x = 0).
    if y.is_zero() || x.is_zero() || y >= n || x >= n {
        return false;
    }
    let lhs = (y * y) % n;
    let rhs = if e { (x * &pk.v) % n } else { x.clone() };
    lhs == rhs
}

pub fn run_interactive(prover: &Prover, rounds: usize) -> bool {
    let verifier = Verifier::new(&prover.pk);
    for _ in 0..rounds {
        let (r, x) = prover.commit();
        let e = verifier.challenge();
        let y = prover.respond(&r, e);
        if !verifier.check(&x, e, &y) {
            return false;
        }
    }
    true
}

// ---------- non-interactive (Fiat-Shamir heuristic) ----------

pub struct Proof {
    pub commitments: Vec<BigUint>,
    pub responses: Vec<BigUint>,
}

/// Derive `k` challenge bits from H(n || v || msg || x_1 .. x_k).
/// Each value is length-prefixed so the encoding is unambiguous.
fn challenge_bits(pk: &PublicKey, msg: &[u8], commitments: &[BigUint]) -> Vec<bool> {
    let mut h = Sha256::new();
    let mut absorb = |bytes: &[u8]| {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    };
    absorb(b"fiat-shamir-v1");
    absorb(&pk.n.to_bytes_be());
    absorb(&pk.v.to_bytes_be());
    absorb(msg);
    for x in commitments {
        absorb(&x.to_bytes_be());
    }
    let digest = h.finalize(); // 256 bits, enough for ROUNDS <= 256
    assert!(commitments.len() <= digest.len() * 8);
    (0..commitments.len())
        .map(|i| (digest[i / 8] >> (i % 8)) & 1 == 1)
        .collect()
}

impl Prover {
    pub fn prove(&self, msg: &[u8], rounds: usize) -> Proof {
        let (rs, commitments): (Vec<_>, Vec<_>) = (0..rounds).map(|_| self.commit()).unzip();
        let es = challenge_bits(&self.pk, msg, &commitments);
        let responses = rs.iter().zip(&es).map(|(r, &e)| self.respond(r, e)).collect();
        Proof { commitments, responses }
    }
}

pub fn verify_proof(pk: &PublicKey, msg: &[u8], proof: &Proof) -> bool {
    if proof.commitments.len() != proof.responses.len() || proof.commitments.len() != ROUNDS {
        return false;
    }
    let es = challenge_bits(pk, msg, &proof.commitments);
    proof
        .commitments
        .iter()
        .zip(&proof.responses)
        .zip(&es)
        .all(|((x, y), &e)| verify_round(pk, x, e, y))
}

// ---------- demo ----------

fn main() {
    println!("Generating {}-bit modulus...", PRIME_BITS * 2);
    let prover = Prover::keygen();
    println!("n = {:x}", prover.pk.n);
    println!("v = {:x}", prover.pk.v);

    println!("\n== Interactive, {ROUNDS} rounds ==");
    println!("honest prover accepted: {}", run_interactive(&prover, ROUNDS));

    // A cheater who doesn't know s: guesses e in advance and prepares x accordingly.
    //   guess e=0: x = r^2,        y = r        (works only if e == 0)
    //   guess e=1: x = r^2 / v,    y = r        (works only if e == 1)
    let pk = &prover.pk;
    let verifier = Verifier::new(pk);
    let v_inv = pk.v.modinv(&pk.n).unwrap();
    let mut passed = 0;
    for _ in 0..ROUNDS {
        let guess: bool = rand::random();
        let r = random_unit(&pk.n);
        let r2 = (&r * &r) % &pk.n;
        let x = if guess { (&r2 * &v_inv) % &pk.n } else { r2 };
        let e = verifier.challenge();
        if !verifier.check(&x, e, &r) {
            break;
        }
        passed += 1;
    }
    println!("cheater survived {passed} of {ROUNDS} rounds (expected ~1)");

    println!("\n== Non-interactive (Fiat-Shamir heuristic) ==");
    let msg = b"hello fiat-shamir";
    let proof = prover.prove(msg, ROUNDS);
    println!("proof valid for original msg: {}", verify_proof(pk, msg, &proof));
    println!("proof valid for tampered msg: {}", verify_proof(pk, b"hello fiat-shamir!", &proof));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primality() {
        assert!(is_probable_prime(&BigUint::from(7919u32)));
        assert!(!is_probable_prime(&BigUint::from(7917u32)));
        assert!(!is_probable_prime(&BigUint::from(561u32))); // Carmichael number
    }

    #[test]
    fn interactive_honest_prover_passes() {
        let p = Prover::keygen();
        assert!(run_interactive(&p, ROUNDS));
    }

    #[test]
    fn non_interactive_roundtrip() {
        let p = Prover::keygen();
        let proof = p.prove(b"msg", ROUNDS);
        assert!(verify_proof(&p.pk, b"msg", &proof));
        assert!(!verify_proof(&p.pk, b"other", &proof));
    }

    #[test]
    fn tampered_response_rejected() {
        let p = Prover::keygen();
        let mut proof = p.prove(b"msg", ROUNDS);
        proof.responses[0] = (&proof.responses[0] + 1u32) % &p.pk.n;
        assert!(!verify_proof(&p.pk, b"msg", &proof));
    }

    #[test]
    fn wrong_secret_rejected() {
        let honest = Prover::keygen();
        let impostor = Prover { pk: PublicKey { n: honest.pk.n.clone(), v: honest.pk.v.clone() }, s: random_unit(&honest.pk.n) };
        let proof = impostor.prove(b"msg", ROUNDS);
        assert!(!verify_proof(&honest.pk, b"msg", &proof));
    }
}
