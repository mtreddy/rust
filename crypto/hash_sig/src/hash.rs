// Tweakable hash: every hash call is bound to a public seed and an address
// (which key / chain / step / tree node it is for). This domain separation
// stops multi-target attacks, where an attacker attacks many hash outputs at once.
// SPHINCS+ / XMSS use the same idea.

use sha2::{Digest, Sha256};

pub const N: usize = 32; // hash output size in bytes (SHA-256)
pub type Hash = [u8; N];

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Tag {
    Prf = 0,      // derive secret values from the secret seed
    Chain = 1,    // one step of a WOTS chain
    WotsPk = 2,   // compress the WOTS public key
    Tree = 3,     // Merkle tree inner node
    Message = 4,  // message digest
}

#[derive(Clone, Copy, Default)]
pub struct Address {
    pub key: u32,    // leaf / one-time key index
    pub chain: u32,  // WOTS chain index, or tree height
    pub step: u32,   // WOTS chain step, or node index at that height
}

impl Address {
    fn to_bytes(self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.key.to_be_bytes());
        b[4..8].copy_from_slice(&self.chain.to_be_bytes());
        b[8..12].copy_from_slice(&self.step.to_be_bytes());
        b
    }
}

pub fn th(tag: Tag, seed: &Hash, adrs: Address, data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([tag as u8]);
    h.update(seed);
    h.update(adrs.to_bytes());
    h.update(data);
    h.finalize().into()
}

pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}
