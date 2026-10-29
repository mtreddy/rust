# NIZK proof systems in Rust

One runnable example for each major family of non-interactive zero-knowledge
proofs. Sigma protocols (Schnorr, Chaum–Pedersen, Pedersen opening) live in
[`../schnorr_zkp`](../schnorr_zkp/README.md), which also contains the written
security proofs.

```sh
cargo run --release                 # all demos
cargo run --release -- snark        # or: bulletproofs | stark
cargo test --release
```

## What a NIZK is

A **non-interactive zero-knowledge proof** is one message $\pi$ that convinces
anyone holding the public statement that the prover knows a secret *witness*
satisfying some relation, while revealing nothing else.

| Property | Meaning |
|---|---|
| Completeness | An honest prover with a valid witness always convinces the verifier |
| Soundness | Without a valid witness, convincing the verifier happens with negligible probability. *Knowledge* soundness: a witness can be extracted from any successful prover |
| Zero-knowledge | A simulator with no witness can produce proofs that are indistinguishable from real ones, so a proof leaks nothing |
| Non-interactive | One message, verifiable by anyone, any time (usually via Fiat–Shamir) |
| Succinct (SNARK/STARK) | The proof is much smaller than the witness, and verifying is much cheaper than re-running the computation |

## The four families compared

Numbers measured on this machine (Apple Silicon, `--release`) from the demos:

| | Sigma + Fiat–Shamir | Groth16 zk-SNARK | Bulletproofs | STARK (Winterfell) |
|---|---|---|---|---|
| Example | `../schnorr_zkp` | [`src/snark.rs`](src/snark.rs) | [`src/bulletproof.rs`](src/bulletproof.rs) | [`src/stark.rs`](src/stark.rs) |
| Statements | Algebraic relations between group elements | Any circuit (R1CS) | Range proofs and circuits on commitments | Any computation written as AIR |
| Proof size | 64 B (Schnorr) | **128 B**, constant | 672 B (64-bit range), log-size | 68.9 KB (65,536 steps) |
| Verify | 2 scalar mults | 3 pairings, constant | Linear in circuit size | Polylog in trace length (0.9 ms here) |
| Trusted setup | None | **Yes, per circuit** | None | None |
| Assumptions | Discrete log, random oracle | Pairings, knowledge assumptions | Discrete log, random oracle | Collision-resistant hashes only |
| Post-quantum | No | No | No | **Plausibly yes** |
| Used in | Signatures, VRFs, credentials | Zcash, Tornado, zkRollups (via ZoKrates / circom) | Monero, Mimblewimble | StarkNet, RISC Zero, Polygon Miden |

Rule of thumb:
- **Groth16:** you need the smallest proofs and cheapest verification, for example on a blockchain, and a trusted setup is acceptable.
- **Bulletproofs:** you need range proofs on hidden amounts without any setup.
- **STARKs:** you need large computations, no trusted setup, or post-quantum security, and can afford larger proofs.
- **Sigma protocols:** the statement is a simple algebraic relation.

---

## 1. zk-SNARK: Groth16 ([`src/snark.rs`](src/snark.rs))

This is the same proof system ZoKrates generates in [`../zokrates`](../zokrates),
defined directly in Rust with arkworks on the BN254 curve (the curve Ethereum supports).

### Arithmetisation: R1CS

The statement becomes a *rank-1 constraint system*. Each row has the form

$$\langle a_i, w\rangle \cdot \langle b_i, w\rangle = \langle c_i, w\rangle$$

where $w = (1, \text{public inputs}, \text{private witness}, \text{intermediate values})$. Each row
allows exactly **one multiplication**. Additions are free because they go inside
the linear combinations. `satisfied()` checks exactly this, row by row.

**Circuit 1**, the asecuritysite / ZoKrates example: public $a, b, c, y$, private $x$,
with the statement $a x^2 + b x + c = y$. That's 4 constraints: three
multiplications ($a\cdot x$, $\cdot x$, $b\cdot x$) and one equality.

**Circuit 2**, knowledge of a factorisation: public $N$, private $p, q$, with
$pq = N$, $p \ne 1$, $q \ne 1$. R1CS can't say "$\ne$" directly. The standard trick is
to prove that $p - 1$ has an inverse: witness $t$ and constrain $(p-1)\,t = 1$. With
$p = 1$ no such $t$ exists, so the trivial factorisation $1 \times 3233$ can't be proven.

### Protocol

1. **Setup** (`circuit_specific_setup`). Random secrets $\alpha, \beta, \gamma, \delta, \tau$ are turned
   into a proving key (2,256 B here) and a verifying key (392 B). These secrets are the
   **toxic waste**: anyone who keeps them can forge proofs for false statements. Real
   systems run a multi-party ceremony, where one honest participant is enough.
2. **Prove.** The R1CS becomes a QAP: one polynomial identity
   $A(X)\,B(X) - C(X) = H(X)\,Z(X)$ that holds if and only if every constraint holds. The prover evaluates
   it "in the exponent" at the hidden point $\tau$ and adds random $r, s$ for zero-knowledge.
   The result is $\pi = (A \in \mathbb{G}_1,\ B \in \mathbb{G}_2,\ C \in \mathbb{G}_1)$, **128 bytes**.
3. **Verify.** One pairing equation:
   $e(A, B) = e(\alpha, \beta)\cdot e\big(\textstyle\sum_i x_i\,\mathrm{IC}_i,\ \gamma\big)\cdot e(C, \delta)$.
   Its cost doesn't depend on circuit size, only on the number of public inputs.

### What the demo shows
- A valid proof for $y = 8$ verifies. The same proof with public input $y = 9$ fails.
- A wrong secret ($x = 2$) doesn't satisfy the constraints, so no proof can be made.
- The trivial factorisation is rejected by the $\ne 1$ constraints.

### Pitfalls
- **Assert, don't return a bool.** The ZoKrates tutorial returns `true`/`false`, and a valid proof
  of `false` still verifies. Constrain the statement itself, as both circuits here do.
- **Under-constrained circuits** are the most common real-world SNARK bug. A value the prover
  computes but never constrains can be set to anything.
- **Proofs are malleable.** Anyone can re-randomise a Groth16 proof into a different valid proof
  of the same statement. Don't use a proof as a unique ID, and bind context (sender, nonce)
  as a public input.

---

## 1b. Use case: prove you're at least 18 without revealing your birth year ([`src/age_proof.rs`](src/age_proof.rs))

`cargo run --release -- age`. The R1CS here is written **row by row**, with no gadgets, and the
demo prints the rows with named variables.

| Role | Does |
|---|---|
| Issuer (ID office) | Knows birth year $B$, picks a random salt $S$, and publishes or signs the credential $C = \text{MiMC}_S(B) + B$ |
| Alice | Proves "I know $(B, S)$ with $\text{Hash}(B,S) = C$ and $Y - B \ge 18$" |
| Website | Verifies against the public values $(C,\ Y{=}2026,\ M{=}18)$ and learns nothing else about $B$ |

**The circuit, 374 rows:**

```
w = (1, C, Y, M | B, S, t2_0, t4_0, t6_0, x_1, ..., d0..d7)

hash, 365 rows: 91 MiMC rounds, x' = (x + S + c_i)^7 as 4 multiplications
  #0   (c0 + B + S) * (c0 + B + S) = (t2_0)
  #1   (t2_0) * (t2_0) = (t4_0)
  #2   (t4_0) * (t2_0) = (t6_0)
  #3   (t6_0) * (c0 + B + S) = (x_1)
  ...
  #364 (B + S + x_91) * (1) = (C)

age, 9 rows: D = Y - B - M must fit in 8 bits
  #365 (d0) * (1 - d0) = (0)        each d_i is a bit
  ...
  #373 (d0 + 2·d1 + ... + 128·d7) * (1) = (Y - M - B)
```

Additions and multiplying by a constant ($+S$, $+c_i$, $2^i\cdot d_i$, $Y - M - B$) cost nothing.
Only multiplying two variables together takes a row.

**What the demo shows:**
- Alice, born 1990, gets a valid 128-byte proof.
- The same proof fails against another person's credential, or for "age ≥ 50".
- Alice can't lie about her birth year, because the hash rows break.
- Bob, born 2015, can't satisfy the circuit. His $D = -7$ is really $p - 7$ in the field, a 254-bit
  number, and no 8 bits add up to it.
- **The bug:** the same circuit *without* the 9 range-check rows accepts Bob, and his proof
  verifies. Nothing constrained $Y - B - M$ at all. This is the under-constrained circuit
  bug, the most common real-world SNARK vulnerability.

**Limits of this learning version:**
- **Hash:** production systems use Poseidon and audited gadget libraries instead of MiMC.
- **Credential:** in a real system the issuer would also sign $C$, and the circuit would verify that signature.
- **Age range:** with 8 bits, the circuit covers ages 18 to 273.

---

## 1c. KZG polynomial commitments, from scratch ([`src/kzg.rs`](src/kzg.rs))

`cargo run --release -- kzg`. The polynomial arithmetic and the commit, open and verify steps
are all written by hand. Only the BN254 curve operations and the pairing come from arkworks.

A **polynomial commitment** lets the prover commit to $f(X)$ with one short value, then prove
"$f(z) = y$" for any $z$ without revealing $f$. It's the part of PLONK, Halo2 and STARKs that
makes them succinct. Groth16 uses the same powers-of-$\tau$ idea internally.

| Step | Formula |
|---|---|
| Setup (trusted) | $\text{SRS} = (G, \tau G, \ldots, \tau^d G;\ H, \tau H)$, then destroy $\tau$ |
| Commit | $C = \sum f_i\,(\tau^i G) = f(\tau)\,G$, one 32-byte point for any degree |
| Open at $z$ | $y = f(z)$, $\ q(X) = \dfrac{f(X) - y}{X - z}$, $\ \pi = q(\tau)\,G$ |
| Verify | $e(C - yG,\ H) = e(\pi,\ \tau H - zH)$, i.e. $f(\tau) - y = q(\tau)(\tau - z)$ |

Why it's sound: $(X - z)$ divides $f(X) - y$ exactly when $y = f(z)$, by the factor theorem.
Claiming a wrong $y$ leaves a remainder, so no polynomial $q$ exists, and computing a fake
$q(\tau)G$ would require knowing $\tau$.

**What the demo shows:**
- **A true claim verifies:** commit to $3X^3 + 2X + 5$ and prove $f(2) = 33$.
- **A false claim fails:** the claim $f(2) = 34$ is rejected, because the division leaves remainder $-1$.
- **Toxic waste:** with a leaked $\tau$, a forged proof for $f(2) = 34$ **verifies**. This is why the setup secret must be destroyed.
- **Batch opening:** $f$ and $g$ are opened at one point with a single proof, using $h = f + \gamma g$.
- **A PLONK-style zero-knowledge proof that a hidden 8-entry vector contains only bits:**
  1. Encode the vector as $f$, with $f(\omega^i) = v_i$ on the 8th roots of unity.
  2. Every $v_i$ is 0 or 1 exactly when $f(X)(f(X) - 1) = q(X)(X^8 - 1)$.
  3. The prover commits to $f$ and $q$.
  4. Fiat–Shamir picks a random point $\zeta$.
  5. The prover opens both polynomials at $\zeta$ with one batched proof.
  6. The verifier checks the identity at $\zeta$. By Schwartz–Zippel, that one point is enough.

  The whole proof is 160 bytes. Adding $(b_0 + b_1X)(X^8 - 1)$ to $f$ makes the proof hiding,
  since it doesn't change any $v_i$. A vector containing a 2 can't produce a valid $q$, and a
  cheater who ignores the remainder is rejected.

---

## 2. Bulletproofs: range proofs ([`src/bulletproof.rs`](src/bulletproof.rs))

**Statement:** the value $v$ hidden in the Pedersen commitment $V = vB + r\tilde B$ satisfies
$0 \le v < 2^n$.

### How it works
1. Write $v$ in binary as $a_L \in \{0,1\}^n$ and set $a_R = a_L - \mathbf{1}^n$. Then
   - $\langle a_L, \mathbf{2}^n\rangle = v$: the bits really encode $v$
   - $a_L \circ a_R = \mathbf{0}^n$: each bit is 0 or 1
   - $a_L - a_R = \mathbf{1}^n$: consistency
2. Verifier challenges $y, z$, derived with Fiat–Shamir in a Merlin transcript, combine all
   $3n$ equations into one inner-product claim $\langle l, r\rangle = t$.
3. The **inner-product argument** proves that claim in $\log_2 n$ rounds, halving the vectors
   each round. The proof has $2\log_2 n + 9$ elements: **672 B** for 64 bits.
4. **Aggregation:** proving $m$ values together adds only $2\log_2 m$ elements. In the demo,
   4 separate proofs take 2,688 B and one aggregated proof takes **800 B**.

There's no trusted setup: generators come from hash-to-curve. Verification is linear in $n$.

### Why range proofs matter: confidential transactions
Pedersen commitments add up: $C(v_1, r_1) + C(v_2, r_2) = C(v_1+v_2,\ r_1+r_2)$. So a
transaction with hidden amounts can show $C(\text{in}) = C(\text{out}_1) + C(\text{out}_2)$, meaning
the inputs balance the outputs. But amounts live modulo the group order $\ell$, so "$-5$" is
really $\ell - 5$. The demo shows that $C(105) + C(-5)$ also balances $C(100)$, which would
create money from nothing. A range proof on every output rules this out.

### What the demo shows
- A valid 64-bit range proof, which fails under a different transcript label (domain separation).
- $2^{40}$ can't be proven to fit in 32 bits.
- Aggregation saves 70% of the size.
- The negative-amount problem that makes range proofs necessary.

---

## 3. STARK: Winterfell ([`src/stark.rs`](src/stark.rs))

**Statement:** starting from $s_0 = 3$ and applying $s_{i+1} = s_i^3 + 42$ for 65,536 steps
gives the claimed result. This is a MiMC-style hash chain over a 128-bit prime field.

### How it works
1. **Execution trace:** a table of every intermediate state, here 1 column × 65,536 rows.
2. **AIR (algebraic intermediate representation):** polynomial constraints that every row
   must satisfy.
   - Transition: $s_{i+1} - (s_i^3 + 42) = 0$, degree 3.
   - Boundary: row 0 equals the start value, and the last row equals the result.
3. **Low-degree extension.** Interpolate the trace as a polynomial $T(X)$ over a domain of size
   $n$, then evaluate it on a domain 8× larger (the "blowup factor"). Commit to the
   evaluations with a **Merkle tree**.
4. If the constraints hold on every row, then
   $\dfrac{T(gX) - T(X)^3 - 42}{\prod_i (X - g^i)}$ is a polynomial of low degree. If even one row is
   wrong, it isn't.
5. **FRI** proves that low-degree claim by repeatedly folding the polynomial in half and
   spot-checking random positions against the Merkle commitments (32 queries here).
6. Fiat–Shamir turns the verifier's random query positions into hashes.

The verifier checks a few Merkle paths and the FRI folds. That's polylogarithmic work:
**0.9 ms** in the demo, while the proof is **68.9 KB** at 95-bit conjectured security.

### Properties
- **Transparent:** no trusted setup, since all randomness is public.
- **Hash-based only:** no elliptic curves or pairings, so the system is plausibly post-quantum
  (compare [`../hash_sig`](../hash_sig)).
- **Larger proofs:** tens to hundreds of KB, compared with 128 B for Groth16.

### Caveat: integrity, not privacy
Winterfell proves **computational integrity**: the result is correct and the verifier didn't
re-run the computation. Its proofs are **not zero-knowledge**, because the trace isn't masked.
In this demo every value is public anyway. Production zk-STARKs add random masking columns
and randomised polynomials so private inputs stay hidden.

---

## Pitfalls that apply to all of them

| Pitfall | Example in this repo |
|---|---|
| Fiat–Shamir must hash the statement and all public parameters | `schnorr_zkp`: `forge_weak` forges a proof when $P$ is left out of the hash |
| Domain-separate transcripts | Bulletproof fails under a different transcript label |
| Never reuse or bias nonces | `schnorr_zkp`: two responses with one nonce reveal the key |
| Constrain everything, and assert rather than return | SNARK circuits here vs. the `-> bool` ZoKrates tutorial |
| Trusted setup secrets must be destroyed | Groth16 `circuit_specific_setup` |
| Watch out for modular wrap-around | Bulletproofs "$-5$" output |

## References
- Groth, *On the Size of Pairing-based Non-interactive Arguments* (2016)
- Bünz et al., *Bulletproofs: Short Proofs for Confidential Transactions and More* (2018)
- Ben-Sasson et al., *Scalable, transparent, and post-quantum secure computational integrity* (STARK, 2018)
- Thaler, *Proofs, Arguments, and Zero-Knowledge* (free book), the best single overview
- Libraries: [arkworks](https://github.com/arkworks-rs), [dalek bulletproofs](https://github.com/dalek-cryptography/bulletproofs), [Winterfell](https://github.com/facebook/winterfell)
