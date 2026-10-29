// ECDH key exchange on Curve25519 (X25519) and how it relates to Ed25519.
//
//   Ed25519  = signatures on the twisted Edwards form of Curve25519
//   X25519   = Diffie-Hellman on the Montgomery form of the same curve
//
// 1. X25519 from scratch (x25519_scratch.rs), checked against x25519-dalek
// 2. Ephemeral ECDH with x25519-dalek
// 3. Converting Ed25519 identity keys into X25519 keys (as libsodium / age do)
// 4. Authenticated ECDH: ephemeral X25519 keys signed with Ed25519 identities,
//    then HKDF -> ChaCha20-Poly1305 session keys. Plain ECDH has no
//    authentication, so without the signatures a man-in-the-middle can swap keys.

mod x25519_scratch;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// ---------- 4. authenticated key exchange ----------
//
//  Alice (identity key IK_A)                    Bob (identity key IK_B)
//  e_a = random, E_A = e_a*G     --- E_A --->
//                                <-- E_B, sig_B(B|E_A|E_B) ---  e_b = random, E_B = e_b*G
//  verify sig_B with IK_B
//                                --- sig_A(A|E_A|E_B) --->      verify sig_A with IK_A
//  shared = e_a * E_B                                           shared = e_b * E_A
//  keys   = HKDF(shared, salt = E_A|E_B)                        same keys
//
// Signing both ephemeral keys binds them to this session and these identities.
// Ephemeral secrets are thrown away afterwards, giving forward secrecy: stealing
// an identity key later doesn't decrypt past sessions.

fn transcript(role: &[u8], ea: &PublicKey, eb: &PublicKey) -> Vec<u8> {
    [b"x25519-demo/v1/".as_slice(), role, ea.as_bytes(), eb.as_bytes()].concat()
}

struct SessionKeys {
    alice_to_bob: [u8; 32],
    bob_to_alice: [u8; 32],
}

fn derive_keys(shared: &[u8; 32], ea: &PublicKey, eb: &PublicKey) -> SessionKeys {
    // Never use the raw DH output as a key: it's not uniformly random.
    // HKDF extracts a uniform key and expands it into one key per direction.
    let salt = [ea.as_bytes().as_slice(), eb.as_bytes()].concat();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 64];
    hk.expand(b"x25519-demo/v1 session keys", &mut okm).unwrap();
    SessionKeys {
        alice_to_bob: okm[..32].try_into().unwrap(),
        bob_to_alice: okm[32..].try_into().unwrap(),
    }
}

/// Bob's side: reply to Alice's ephemeral key. Returns (E_B, signature, Bob's ephemeral secret).
fn bob_respond(bob_id: &SigningKey, ea: &PublicKey) -> (PublicKey, Signature, EphemeralSecret) {
    let eb_secret = EphemeralSecret::random_from_rng(OsRng);
    let eb = PublicKey::from(&eb_secret);
    let sig = bob_id.sign(&transcript(b"B", ea, &eb));
    (eb, sig, eb_secret)
}

fn authenticated_exchange() {
    let alice_id = SigningKey::generate(&mut OsRng);
    let bob_id = SigningKey::generate(&mut OsRng);
    // Assume each side already knows the other's identity public key
    // (from a certificate, a QR code, a key server, ...).
    let (alice_id_pub, bob_id_pub) = (alice_id.verifying_key(), bob_id.verifying_key());

    // Alice -> Bob: E_A
    let ea_secret = EphemeralSecret::random_from_rng(OsRng);
    let ea = PublicKey::from(&ea_secret);

    // Bob -> Alice: E_B, sig_B
    let (eb, sig_b, eb_secret) = bob_respond(&bob_id, &ea);

    // Alice verifies Bob, then signs too.
    let ok = bob_id_pub.verify(&transcript(b"B", &ea, &eb), &sig_b).is_ok();
    println!("Alice verifies Bob's signature:   {ok}");
    let sig_a = alice_id.sign(&transcript(b"A", &ea, &eb));
    let ok = alice_id_pub.verify(&transcript(b"A", &ea, &eb), &sig_a).is_ok();
    println!("Bob verifies Alice's signature:   {ok}");

    // Both compute the same shared secret; ephemeral secrets are consumed (dropped) here.
    let shared_a = ea_secret.diffie_hellman(&eb);
    let shared_b = eb_secret.diffie_hellman(&ea);
    // Rejects all-zero outputs from malicious low-order public keys.
    assert!(shared_a.was_contributory());
    let ka = derive_keys(shared_a.as_bytes(), &ea, &eb);
    let kb = derive_keys(shared_b.as_bytes(), &ea, &eb);
    println!("same session keys:                {}", ka.alice_to_bob == kb.alice_to_bob && ka.bob_to_alice == kb.bob_to_alice);

    // Use the keys. Separate keys per direction mean a counter nonce can't collide
    // between the two sides.
    let nonce = Nonce::from_slice(&[0u8; 12]); // message #0 in this direction
    let ct = ChaCha20Poly1305::new(&ka.alice_to_bob.into()).encrypt(nonce, b"hi bob, it's alice".as_ref()).unwrap();
    let pt = ChaCha20Poly1305::new(&kb.alice_to_bob.into()).decrypt(nonce, ct.as_ref()).unwrap();
    println!("Bob decrypts:                     {:?}", String::from_utf8_lossy(&pt));

    // Man-in-the-middle: Mallory replaces E_B with her own key. She can't
    // produce Bob's signature over it, so Alice rejects the exchange.
    let mallory_id = SigningKey::generate(&mut OsRng);
    let (em, sig_m, _) = bob_respond(&mallory_id, &ea);
    let ok = bob_id_pub.verify(&transcript(b"B", &ea, &em), &sig_m).is_ok();
    println!("MITM with Mallory's key accepted: {ok}");
    // Replaying Bob's real signature with Mallory's key fails too.
    let ok = bob_id_pub.verify(&transcript(b"B", &ea, &em), &sig_b).is_ok();
    println!("MITM replaying Bob's signature:   {ok}");
}

fn main() {
    println!("== 1. X25519 from scratch ==");
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut a);
    OsRng.fill_bytes(&mut b);
    let (pa, pb) = (x25519_scratch::public_key(&a), x25519_scratch::public_key(&b));
    let s1 = x25519_scratch::x25519(&a, &pb);
    let s2 = x25519_scratch::x25519(&b, &pa);
    println!("Alice public: {}", hex::encode(pa));
    println!("Bob public:   {}", hex::encode(pb));
    println!("shared (a*B): {}", hex::encode(s1));
    println!("shared (b*A): {}", hex::encode(s2));
    let dalek = StaticSecret::from(a).diffie_hellman(&PublicKey::from(pb));
    println!("equal: {}, matches x25519-dalek: {}", s1 == s2, &s1 == dalek.as_bytes());

    println!("\n== 2. Ephemeral ECDH (x25519-dalek) ==");
    let alice = EphemeralSecret::random_from_rng(OsRng);
    let bob = EphemeralSecret::random_from_rng(OsRng);
    let (alice_pub, bob_pub) = (PublicKey::from(&alice), PublicKey::from(&bob));
    let sa = alice.diffie_hellman(&bob_pub); // `alice` is consumed: can only be used once
    let sb = bob.diffie_hellman(&alice_pub);
    println!("shared secrets equal: {}", sa.as_bytes() == sb.as_bytes());

    println!("\n== 3. Ed25519 keys -> X25519 keys ==");
    // An Ed25519 secret key is a seed; SHA-512(seed)[..32] is the scalar.
    // The X25519 public key is the Edwards point mapped with u = (1 + y) / (1 - y).
    let alice_ed = SigningKey::generate(&mut OsRng);
    let bob_ed = SigningKey::generate(&mut OsRng);
    let ed_to_x_secret = |k: &SigningKey| StaticSecret::from(k.to_scalar_bytes());
    let ed_to_x_public = |k: &VerifyingKey| PublicKey::from(k.to_montgomery().to_bytes());
    let alice_x = ed_to_x_secret(&alice_ed);
    let consistent = PublicKey::from(&alice_x) == ed_to_x_public(&alice_ed.verifying_key());
    println!("converted secret matches converted public key: {consistent}");
    // Alice only needs Bob's Ed25519 public key (e.g. his signing identity) to agree on a key.
    let s1 = alice_x.diffie_hellman(&ed_to_x_public(&bob_ed.verifying_key()));
    let s2 = ed_to_x_secret(&bob_ed).diffie_hellman(&ed_to_x_public(&alice_ed.verifying_key()));
    println!("static-static shared secrets equal: {}", s1.as_bytes() == s2.as_bytes());
    println!("(works, but reusing one key for signing and DH is discouraged; no forward secrecy)");

    println!("\n== 4. Authenticated ECDH (Ed25519-signed ephemeral X25519) ==");
    authenticated_exchange();
}
