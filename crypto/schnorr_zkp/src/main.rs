// Zero-knowledge proofs with Schnorr over an elliptic curve (Ristretto255).
//
//   schnorr.rs     proof of knowledge of a private key: interactive, simulator,
//                  extractor, Fiat-Shamir NIZK, signatures, weak Fiat-Shamir forgery
//   sigma.rs       Chaum-Pedersen DLEQ and Pedersen commitment opening proofs
//   transcript.rs  Fiat-Shamir hashing

mod schnorr;
mod sigma;
mod transcript;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

fn hx(p: &curve25519_dalek::ristretto::RistrettoPoint) -> String {
    hex::encode(p.compress().as_bytes())
}

fn main() {
    let alice = schnorr::KeyPair::generate();
    println!("Alice public key P = x*G: {}", hx(&alice.p));

    println!("\n== 1. Interactive Schnorr proof (5 rounds) ==");
    for round in 1..=5 {
        let (k, r) = alice.commit(); // prover -> R
        let c = Scalar::random(&mut OsRng); // verifier -> c
        let s = alice.respond(&k, &c); // prover -> s
        println!("round {round}: verified = {}", schnorr::verify_interactive(&alice.p, &r, &c, &s));
    }
    // One round is already enough: a cheater must guess c, chance ~1 / 2^252.

    println!("\n== 2. Zero-knowledge: simulated transcript, no secret used ==");
    let (r, c, s) = schnorr::simulate(&alice.p);
    println!("simulated (R, c, s) verifies: {}", schnorr::verify_interactive(&alice.p, &r, &c, &s));
    println!("-> real transcripts carry no information the verifier couldn't fake itself.");

    println!("\n== 3. Soundness / nonce reuse: extract the secret ==");
    let (k, _r) = alice.commit();
    let (c1, c2) = (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng));
    let (s1, s2) = (alice.respond(&k, &c1), alice.respond(&k, &c2)); // same k twice!
    let x = schnorr::extract(&c1, &s1, &c2, &s2);
    println!("same R answered twice -> recovered x, x*G == P: {}", x * G == alice.p);

    println!("\n== 4. Non-interactive proof (Fiat-Shamir) ==");
    let proof = alice.prove(b"login session 42");
    println!("valid for its session:      {}", schnorr::verify(&alice.p, &proof, b"login session 42"));
    println!("replayed in another session: {}", schnorr::verify(&alice.p, &proof, b"login session 43"));
    let bob = schnorr::KeyPair::generate();
    println!("claimed for Bob's key:       {}", schnorr::verify(&bob.p, &proof, b"login session 42"));

    println!("\n== 5. Schnorr signature = NIZK bound to a message ==");
    let sig = alice.sign(b"transfer 5 to bob");
    println!("signature (R, s): ({}, {})", hx(&sig.r), hex::encode(sig.s.as_bytes()));
    println!("verify original: {}", schnorr::verify(&alice.p, &sig, b"transfer 5 to bob"));
    println!("verify tampered: {}", schnorr::verify(&alice.p, &sig, b"transfer 500 to bob"));

    println!("\n== 6. Weak Fiat-Shamir (challenge forgets P) is forgeable ==");
    let (p_forged, forged) = schnorr::forge_weak();
    println!("forged proof passes weak verifier:   {}", schnorr::verify_weak(&p_forged, &forged));
    println!("forged proof passes strong verifier: {}", schnorr::verify(&p_forged, &forged, b""));

    println!("\n== 7. Chaum-Pedersen: same secret behind two public values ==");
    let x = Scalar::random(&mut OsRng);
    let hh = sigma::h();
    let (a, b, pf) = sigma::dleq_prove(&x, &hh);
    println!("A = x*G, B = x*H, proof valid:    {}", sigma::dleq_verify(&hh, &a, &b, &pf));
    let b_other = Scalar::random(&mut OsRng) * hh;
    println!("with a different B (other secret): {}", sigma::dleq_verify(&hh, &a, &b_other, &pf));

    println!("\n== 8. Pedersen commitment + proof of knowing its opening ==");
    let vote = Scalar::from(1u64); // e.g. a "yes" vote, kept hidden
    let blind = Scalar::random(&mut OsRng);
    let (cm, pf) = sigma::prove_opening(&vote, &blind);
    println!("commitment C = v*G + r*H: {}", hx(&cm));
    println!("prover knows (v, r):      {}", sigma::verify_opening(&cm, &pf));
    let other = sigma::commit(&Scalar::from(0u64), &blind);
    println!("proof reused for other C: {}", sigma::verify_opening(&other, &pf));
    // Homomorphic: adding commitments adds the hidden values.
    let (v2, r2) = (Scalar::from(1u64), Scalar::random(&mut OsRng));
    let sum = cm + sigma::commit(&v2, &r2);
    println!("C(1) + C(1) == C(2):      {}", sum == sigma::commit(&Scalar::from(2u64), &(blind + r2)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_complete_and_sound() {
        let kp = schnorr::KeyPair::generate();
        let (k, r) = kp.commit();
        let c = Scalar::random(&mut OsRng);
        let s = kp.respond(&k, &c);
        assert!(schnorr::verify_interactive(&kp.p, &r, &c, &s));
        assert!(!schnorr::verify_interactive(&kp.p, &r, &(c + Scalar::ONE), &s));
    }

    #[test]
    fn simulator_and_extractor() {
        let kp = schnorr::KeyPair::generate();
        let (r, c, s) = schnorr::simulate(&kp.p);
        assert!(schnorr::verify_interactive(&kp.p, &r, &c, &s));
        let (k, _) = kp.commit();
        let (c1, c2) = (Scalar::from(3u64), Scalar::from(7u64));
        let x = schnorr::extract(&c1, &kp.respond(&k, &c1), &c2, &kp.respond(&k, &c2));
        assert_eq!(x * G, kp.p);
    }

    #[test]
    fn nizk_and_signature() {
        let kp = schnorr::KeyPair::generate();
        let sig = kp.sign(b"m");
        assert!(schnorr::verify(&kp.p, &sig, b"m"));
        assert!(!schnorr::verify(&kp.p, &sig, b"n"));
        let bad = schnorr::Proof { r: sig.r, s: sig.s + Scalar::ONE };
        assert!(!schnorr::verify(&kp.p, &bad, b"m"));
    }

    #[test]
    fn weak_fiat_shamir_forgery() {
        let (p, pf) = schnorr::forge_weak();
        assert!(schnorr::verify_weak(&p, &pf));
        assert!(!schnorr::verify(&p, &pf, b""));
    }

    #[test]
    fn dleq() {
        let hh = sigma::h();
        let x = Scalar::random(&mut OsRng);
        let (a, b, pf) = sigma::dleq_prove(&x, &hh);
        assert!(sigma::dleq_verify(&hh, &a, &b, &pf));
        assert!(!sigma::dleq_verify(&hh, &a, &(b + G), &pf));
    }

    #[test]
    fn pedersen_opening() {
        let (v, r) = (Scalar::from(42u64), Scalar::random(&mut OsRng));
        let (c, pf) = sigma::prove_opening(&v, &r);
        assert!(sigma::verify_opening(&c, &pf));
        assert!(!sigma::verify_opening(&(c + G), &pf));
    }
}
