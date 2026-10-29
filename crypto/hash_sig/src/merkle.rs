// Merkle signature scheme (simplified XMSS): many one-time keys, one public key.
//
//                 root  <- public key (plus pub_seed)
//               /      \
//            n10        n11
//           /   \      /   \
//         L0    L1   L2    L3     L_i = WOTS public key #i
//
// sign #i:  WOTS signature with key i + authentication path (sibling hashes)
// verify:   recompute L_i from the WOTS signature, hash up the path, compare to root
//
// STATEFUL: the signer must never reuse an index, otherwise the WOTS key
// signs two messages and forgeries become possible. SPHINCS+ (SLH-DSA)
// removes this state by picking leaves pseudo-randomly from a huge hypertree.

use crate::hash::{th, Address, Hash, Tag, N};
use crate::wots;
use rand::{rngs::OsRng, RngCore};

pub const HEIGHT: usize = 5; // 2^5 = 32 signatures per key pair

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    pub root: Hash,
    pub pub_seed: Hash,
}

pub struct Signature {
    pub index: u32,
    pub wots: wots::Signature,
    pub auth: [Hash; HEIGHT],
}

impl Signature {
    pub const SIZE: usize = 4 + wots::LEN * N + HEIGHT * N;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    KeyExhausted,
}

pub struct Signer {
    sk_seed: Hash,
    pub pk: PublicKey,
    tree: Vec<Vec<Hash>>, // tree[h][i]: node i at height h (h = 0 are leaves)
    next_index: u32,
}

fn node_hash(pub_seed: &Hash, height: usize, index: usize, left: &Hash, right: &Hash) -> Hash {
    let adrs = Address { key: 0, chain: height as u32, step: index as u32 };
    th(Tag::Tree, pub_seed, adrs, &[*left, *right].concat())
}

fn message_digest(pk: &PublicKey, index: u32, msg: &[u8]) -> Hash {
    let adrs = Address { key: index, ..Default::default() };
    th(Tag::Message, &pk.pub_seed, adrs, &[&pk.root[..], msg].concat())
}

impl Signer {
    pub fn keygen() -> Self {
        let mut sk_seed = [0u8; N];
        let mut pub_seed = [0u8; N];
        OsRng.fill_bytes(&mut sk_seed);
        OsRng.fill_bytes(&mut pub_seed);

        let leaves: Vec<Hash> = (0..1u32 << HEIGHT)
            .map(|i| wots::public_key(&sk_seed, &pub_seed, i))
            .collect();
        let mut tree = vec![leaves];
        for h in 0..HEIGHT {
            let level = tree[h]
                .chunks(2)
                .enumerate()
                .map(|(i, pair)| node_hash(&pub_seed, h + 1, i, &pair[0], &pair[1]))
                .collect();
            tree.push(level);
        }
        let root = tree[HEIGHT][0];
        Signer { sk_seed, pk: PublicKey { root, pub_seed }, tree, next_index: 0 }
    }

    pub fn remaining(&self) -> u32 {
        (1 << HEIGHT) - self.next_index
    }

    pub fn sign(&mut self, msg: &[u8]) -> Result<Signature, Error> {
        if self.remaining() == 0 {
            return Err(Error::KeyExhausted);
        }
        // Advance state before producing the signature. In a real system the
        // new index must be persisted to disk first, so a crash can't cause reuse.
        let index = self.next_index;
        self.next_index += 1;

        let d = message_digest(&self.pk, index, msg);
        let wots = wots::sign(&d, &self.sk_seed, &self.pk.pub_seed, index);
        let auth = std::array::from_fn(|h| self.tree[h][(index as usize >> h) ^ 1]);
        Ok(Signature { index, wots, auth })
    }
}

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    if sig.index >= 1 << HEIGHT {
        return false;
    }
    let d = message_digest(pk, sig.index, msg);
    let mut node = wots::public_key_from_sig(&sig.wots, &d, &pk.pub_seed, sig.index);
    let mut idx = sig.index as usize;
    for (h, sibling) in sig.auth.iter().enumerate() {
        node = if idx % 2 == 0 {
            node_hash(&pk.pub_seed, h + 1, idx / 2, &node, sibling)
        } else {
            node_hash(&pk.pub_seed, h + 1, idx / 2, sibling, &node)
        };
        idx /= 2;
    }
    node == pk.root
}
