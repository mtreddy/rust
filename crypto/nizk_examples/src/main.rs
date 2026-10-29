// Non-interactive zero-knowledge proof systems, one runnable example each.
// See README.md for how each one works and how they compare.
//
//   cargo run --release            all demos
//   cargo run --release -- snark   | age | kzg | bulletproofs | stark
//
// Sigma protocols (Schnorr, DLEQ, Pedersen opening) live in ../schnorr_zkp.

mod age_proof;
mod bulletproof;
mod kzg;
mod snark;
mod stark;

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    let run = |name: &str| which.is_empty() || which == name;

    if run("snark") {
        println!("===== zk-SNARK: Groth16 on BN254 (arkworks) =====");
        snark::demo();
    }
    if run("age") {
        println!("\n===== Use case: prove age >= 18 with hand-written R1CS (Groth16) =====");
        age_proof::demo();
    }
    if run("kzg") {
        println!("\n===== KZG polynomial commitments from scratch (BN254) =====");
        kzg::demo();
    }
    if run("bulletproofs") {
        println!("\n===== Bulletproofs: range proofs on Ristretto255 =====");
        bulletproof::demo();
    }
    if run("stark") {
        println!("\n===== STARK: Winterfell, hash-based, transparent =====");
        stark::demo();
    }
}
