# Schnorr zero-knowledge proofs on Ristretto255

Sigma protocols on an elliptic curve, each with a runnable demo and the written proof that
it is complete, sound and zero-knowledge.

```sh
cargo run      # 8 demo sections
cargo test
```

| File | Contents |
|---|---|
| [`src/schnorr.rs`](src/schnorr.rs) | Schnorr proof of knowledge: interactive, simulator, extractor, Fiat–Shamir NIZK, signatures, weak Fiat–Shamir forgery |
| [`src/sigma.rs`](src/sigma.rs) | Chaum–Pedersen DLEQ proof, Pedersen commitments and the Okamoto opening proof |
| [`src/transcript.rs`](src/transcript.rs) | Fiat–Shamir transcript (length-prefixed, domain-separated SHA-512) |

For SNARKs, Bulletproofs and STARKs see [`../nizk_examples`](../nizk_examples/README.md).

## Setting

- $\mathbb{G}$: the Ristretto255 group, of **prime order** $\ell \approx 2^{252}$, written additively. Prime order
  matters: every nonzero scalar is invertible, and there are no small subgroups.
- $G$: the standard generator. $H$: a second generator from hash-to-curve, so nobody knows $\log_G H$.
- **Discrete log assumption:** given $P = xG$, finding $x$ is infeasible.
- Scalars live in $\mathbb{Z}_\ell$. "Uniform" means uniformly random in $\mathbb{Z}_\ell$.

A **sigma protocol** has three moves: commitment $R$, challenge $c$, response $s$. It is secure
if it has three properties:
1. **Completeness:** an honest prover always passes.
2. **Special soundness:** two accepting transcripts with the same commitment and different
   challenges let anyone compute the witness.
3. **Honest-verifier zero-knowledge (HVZK):** a simulator without the witness can produce
   transcripts with exactly the same distribution as real ones.

---

## 1. Schnorr proof of knowledge of a discrete log

**Relation:** $\{(P;\ x) : P = xG\}$, where $P$ is public and $x$ is the witness.

| Prover | | Verifier |
|---|---|---|
| $k \leftarrow \mathbb{Z}_\ell$, $R = kG$ | $\xrightarrow{\ R\ }$ | |
| | $\xleftarrow{\ c\ }$ | $c \leftarrow \mathbb{Z}_\ell$ |
| $s = k + cx$ | $\xrightarrow{\ s\ }$ | accept iff $sG = R + cP$ |

Code: `commit`, `respond`, `verify_interactive`.

### Completeness
$$sG = (k + cx)G = kG + c(xG) = R + cP. \qquad\blacksquare$$

### Special soundness
Suppose $(R, c_1, s_1)$ and $(R, c_2, s_2)$ both verify, with $c_1 \ne c_2$. Then
$$s_1G - c_1P = R = s_2G - c_2P \;\Longrightarrow\; (s_1 - s_2)G = (c_1 - c_2)P.$$
Since $\ell$ is prime and $c_1 \ne c_2$, the difference $c_1 - c_2$ is invertible, so
$$x = (s_1 - s_2)(c_1 - c_2)^{-1} \bmod \ell. \qquad\blacksquare$$

Code: `extract`. Demo §3 recovers $x$ and checks $xG = P$.

**What follows from it:**
- **Knowledge soundness.** A prover that succeeds with probability noticeably above $1/\ell$ must be
  able to answer two different challenges for the same $R$. Rewinding it after it sends $R$
  produces two such transcripts, and the extractor turns them into $x$. So any convincing prover
  "knows" $x$. The soundness error is $1/\ell \approx 2^{-252}$, so one round is enough.
- **Nonce reuse is fatal.** Signing two messages with the same $k$ hands an attacker two
  transcripts with the same $R$. That's exactly how the PlayStation 3 ECDSA key was recovered
  in 2010. Even a slightly *biased* $k$ leaks the key through lattice attacks. Always use a
  fresh uniform $k$, or derive it deterministically from the key and message (RFC 6979 / EdDSA).

### Honest-verifier zero-knowledge
**Simulator** (`simulate`), with no $x$: pick $c, s$ uniformly and set $R = sG - cP$.

**Claim:** simulated transcripts have exactly the same distribution as real ones.

- **Real.** $k$ and $c$ are independent and uniform. For fixed $c$, the map $k \mapsto s = k + cx$ is a
  bijection on $\mathbb{Z}_\ell$, so $s$ is uniform and independent of $c$. Then $R$ is determined by
  $R = sG - cP$, because the transcript verifies.
- **Simulated.** $c$ and $s$ are independent and uniform, and $R = sG - cP$.

These are the same distribution. So a transcript contains nothing the verifier couldn't have
produced on its own, and it leaks nothing about $x$. $\blacksquare$

The simulator only works because it picks $c$ *before* $R$, which a real verifier never lets the
prover do. That's also why an interactive transcript proves nothing to a third party.

---

## 2. Fiat–Shamir: making it non-interactive

Replace the verifier with a hash, modelled as a random oracle:
$$c = \mathcal{H}(\texttt{domain},\ G,\ P,\ R,\ \texttt{context}), \qquad \pi = (R, s).$$
Code: `prove`, `verify`, and `challenge`, which uses `Transcript`.

**Soundness (sketch, random oracle model).** This uses the *forking lemma* (Pointcheval–Stern).
Run a forger until it outputs a valid $(R, s)$. Rewind it to the hash query that produced
$c$, and answer that query with a fresh random $c'$. With probability about $\varepsilon^2/q_H$ (for a forger
with success $\varepsilon$ making $q_H$ hash queries), it outputs a second valid proof with the same $R$
and $c' \ne c$. Special soundness then extracts $x$, which contradicts the discrete log assumption.

**Zero-knowledge (sketch).** The simulator *programs* the random oracle: it picks $c, s$, sets
$R = sG - cP$, and defines $\mathcal{H}(\ldots, P, R, \ldots) := c$.

**Signatures.** Putting a message $m$ into `context` gives a **Schnorr signature** (`sign`). The
same forking argument gives unforgeability under chosen-message attack. EdDSA (Ed25519) is
this construction with a deterministic nonce.

### Why the statement must be hashed ("strong" Fiat–Shamir)
Suppose the challenge omits $P$, so $c = \mathcal{H}(R)$. Then the prover can choose the
statement *after* seeing the challenge:
$$\text{pick } R, s \text{ at random};\quad c = \mathcal{H}(R);\quad P := c^{-1}(sG - R).$$
Now $sG = R + cP$ holds, which is a valid proof for a $P$ whose discrete log nobody knows.
Code: `forge_weak`. Demo §6 shows that the weak verifier accepts it and `verify` rejects it.
This is the "Frozen Heart" bug class (2022), found in several production ZK libraries.
**Rule: hash the domain, all public parameters, the statement, and every commitment.**

Binding `context` also stops replay. Demo §4 shows a proof for session 42 failing for session 43,
and a proof for Alice's key failing for Bob's.

---

## 3. Chaum–Pedersen: equality of discrete logs (DLEQ)

**Relation:** $\{(A, B;\ x) : A = xG \ \wedge\ B = xH\}$.

Prover: $k \leftarrow \mathbb{Z}_\ell$, $R_1 = kG$, $R_2 = kH$, $c = \mathcal{H}(G, H, A, B, R_1, R_2)$, $s = k + cx$.
Verifier: $sG = R_1 + cA$ and $sH = R_2 + cB$. Code: `dleq_prove`, `dleq_verify`.

- **Completeness:** $sG = kG + cxG = R_1 + cA$, and the same holds with $H$.
- **Special soundness:** two transcripts give $(s_1 - s_2)G = (c_1 - c_2)A$ and $(s_1 - s_2)H = (c_1 - c_2)B$.
  So $A = x'G$ and $B = x'H$ for the *same* $x' = (s_1 - s_2)/(c_1 - c_2)$. A single response answering
  both equations forces a single exponent.
- **HVZK:** pick $c, s$ uniformly; set $R_1 = sG - cA$ and $R_2 = sH - cB$.

Used in VRFs (RFC 9381), threshold decryption, verifiable shuffles, and to prove that a
Diffie–Hellman result was computed correctly: $B = xH$ with $H$ the other party's key.

---

## 4. Pedersen commitments and the Okamoto opening proof

**Commitment:** $C = vG + rH$ with $r$ uniform. Code: `commit`.

- **Perfectly hiding.** For any $v$, a uniform $r$ makes $rH$, and therefore $C$, uniform in $\mathbb{G}$.
  So $C$ carries no information about $v$, even against an unbounded adversary.
- **Computationally binding.** Suppose there are two openings $(v, r) \ne (v', r')$ of the same $C$.
  Then $(v - v')G = (r' - r)H$. Here $r \ne r'$, since otherwise $v = v'$. So
  $\log_G H = (v - v')/(r' - r)$, which breaks discrete log. That's why $H$ must come from
  hash-to-curve, with nobody knowing $\log_G H$.
- **Additively homomorphic.** $C(v_1, r_1) + C(v_2, r_2) = C(v_1 + v_2,\ r_1 + r_2)$. Demo §8 shows this;
  it's the basis of confidential transactions (see Bulletproofs in `../nizk_examples`).

**Opening proof** (Okamoto). Relation: $\{(C;\ v, r) : C = vG + rH\}$.
Prover: $k_1, k_2 \leftarrow \mathbb{Z}_\ell$, $T = k_1G + k_2H$, $c = \mathcal{H}(G, H, C, T)$, $s_1 = k_1 + cv$, $s_2 = k_2 + cr$.
Verifier: $s_1G + s_2H = T + cC$. Code: `prove_opening`, `verify_opening`.

- **Completeness:** $s_1G + s_2H = (k_1G + k_2H) + c(vG + rH) = T + cC$.
- **Special soundness:** $v = (s_1 - s_1')/(c - c')$ and $r = (s_2 - s_2')/(c - c')$. By binding, this is the
  only opening anyone can know.
- **HVZK:** pick $c, s_1, s_2$ uniformly and set $T = s_1G + s_2H - cC$.

---

## Demo map

| § | Shows | Property |
|---|---|---|
| 1 | Interactive rounds pass | Completeness |
| 2 | Simulated transcript verifies without $x$ | Zero-knowledge |
| 3 | Same $R$, two challenges → $x$ recovered | Special soundness, nonce reuse |
| 4 | NIZK fails in another session or for another key | Fiat–Shamir binding |
| 5 | Signature fails on a tampered message | Schnorr signature |
| 6 | Weak Fiat–Shamir forgery accepted by the weak verifier only | Strong Fiat–Shamir |
| 7 | DLEQ fails if $B$ uses a different secret | Chaum–Pedersen |
| 8 | Opening proof is bound to its commitment; $C(1) + C(1) = C(2)$ | Pedersen / Okamoto |

## References
- Schnorr, *Efficient Signature Generation by Smart Cards* (1991)
- Pointcheval & Stern, *Security Arguments for Digital Signatures and Blind Signatures* (2000), the forking lemma
- Chaum & Pedersen, *Wallet Databases with Observers* (1992)
- Bernhard, Pereira & Warinschi, *How Not to Prove Yourself: Pitfalls of the Fiat–Shamir Heuristic* (2012)
- Boneh & Shoup, *A Graduate Course in Applied Cryptography*, ch. 19 (sigma protocols)
- [ristretto.group](https://ristretto.group), on why prime-order groups matter
