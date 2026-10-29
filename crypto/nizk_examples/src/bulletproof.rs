// Bulletproofs: range proofs on a Pedersen commitment (Ristretto255).
//
// Statement: "the value v hidden in commitment V = v*B + r*B_blind lies in [0, 2^n)",
// without revealing v. Used for confidential transactions (Monero, Mimblewimble):
// amounts stay hidden, but nobody can create money by committing to a negative
// (= huge, wrapped-around) amount.
//
// How it works (sketch):
//   - write v in binary: a_L = bits of v, a_R = a_L - 1  (so each a_L[i] is 0 or 1)
//   - the constraints  <a_L, 2^n> = v,  a_L o a_R = 0,  a_L - a_R = 1  are folded
//     into ONE inner-product relation using verifier challenges (Fiat-Shamir)
//   - the inner-product argument proves <l, r> = t in log2(n) rounds, halving the
//     vectors each round, so the proof has 2*log2(n) + 9 group/scalar elements
//
// No trusted setup: generators come from hashing. Proof size is logarithmic
// (~672 B for 64 bits), aggregating m proofs costs only 2*log2(m) more elements.
// Verification is linear in n (slower than a SNARK verify).

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;

const BITS: usize = 64;

// The transcript label binds a proof to its protocol/application (domain separation).
fn transcript() -> Transcript {
    Transcript::new(b"nizk-examples/range-proof")
}

pub fn demo() {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(BITS, 4); // capacity: 64 bits, up to 4 aggregated values

    println!("-- single 64-bit range proof --");
    let amount = 1_000u64;
    let blinding = Scalar::random(&mut OsRng);
    let (proof, commitment) =
        RangeProof::prove_single(&bp_gens, &pc_gens, &mut transcript(), amount, &blinding, BITS).unwrap();
    println!("commitment V: {}", hex::encode(commitment.as_bytes()));
    println!("proof size:   {} bytes", proof.to_bytes().len());
    let ok = proof.verify_single(&bp_gens, &pc_gens, &mut transcript(), &commitment, BITS).is_ok();
    println!("verify 0 <= v < 2^64: {ok}");
    let wrong_label = proof
        .verify_single(&bp_gens, &pc_gens, &mut Transcript::new(b"other-app"), &commitment, BITS)
        .is_ok();
    println!("verify under another transcript label: {wrong_label}");

    // A value outside the range: 2^40 does not fit in 32 bits, so no valid proof exists.
    let too_big = 1u64 << 40;
    let r = RangeProof::prove_single(&bp_gens, &pc_gens, &mut transcript(), too_big, &blinding, 32);
    let forged_ok = r.map(|(p, v)| p.verify_single(&bp_gens, &pc_gens, &mut transcript(), &v, 32).is_ok()).unwrap_or(false);
    println!("2^40 claimed to fit in 32 bits verifies: {forged_ok}");

    println!("\n-- aggregated proof for 4 values --");
    let values = [5u64, 70, 300, 9_999];
    let blindings: Vec<Scalar> = values.iter().map(|_| Scalar::random(&mut OsRng)).collect();
    let (agg, commitments) =
        RangeProof::prove_multiple(&bp_gens, &pc_gens, &mut transcript(), &values, &blindings, BITS).unwrap();
    println!("4 proofs separately: {} bytes, aggregated: {} bytes", 4 * proof.to_bytes().len(), agg.to_bytes().len());
    let ok = agg.verify_multiple(&bp_gens, &pc_gens, &mut transcript(), &commitments, BITS).is_ok();
    println!("verify all 4: {ok}");

    println!("\n-- confidential transfer: inputs == outputs, amounts hidden --");
    // Pedersen commitments add up: if in = out1 + out2 and r_in = r_1 + r_2, the
    // commitments balance. Range proofs on the outputs stop "-5" (wrapped mod l) outputs.
    let (r1, r2) = (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng));
    let input = pc_gens.commit(Scalar::from(100u64), r1 + r2);
    let out1 = pc_gens.commit(Scalar::from(60u64), r1);
    let out2 = pc_gens.commit(Scalar::from(40u64), r2);
    println!("C(100) == C(60) + C(40): {}", input == out1 + out2);
    let neg = -Scalar::from(5u64); // "-5" is actually l - 5, a 253-bit number
    let cheat = pc_gens.commit(Scalar::from(105u64), r1) + pc_gens.commit(neg, r2);
    println!("C(105) + C(-5) also balances: {} -> the range proof on outputs is what prevents this", input == cheat);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_proof_roundtrip_and_rejects() {
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(64, 1);
        let r = Scalar::random(&mut OsRng);
        let (p, v) = RangeProof::prove_single(&bp, &pc, &mut transcript(), 42, &r, 64).unwrap();
        assert!(p.verify_single(&bp, &pc, &mut transcript(), &v, 64).is_ok());
        let other = pc.commit(Scalar::from(43u64), r).compress();
        assert!(p.verify_single(&bp, &pc, &mut transcript(), &other, 64).is_err());
    }

    #[test]
    fn out_of_range_fails() {
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(64, 1);
        let r = Scalar::random(&mut OsRng);
        let res = RangeProof::prove_single(&bp, &pc, &mut transcript(), 1 << 40, &r, 32);
        assert!(res.map(|(p, v)| p.verify_single(&bp, &pc, &mut transcript(), &v, 32).is_err()).unwrap_or(true));
    }
}
