//use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
//use std::sync::{Arc, Mutex};
//use warp::Filter;




/// ========== Block Definition ==========
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp_ms: u128,
    pub data: String,
    pub previous_hash: String,
    pub nonce: u64,
    pub hash: String,
}


impl Block {
    pub fn genesis() -> Self {
        let mut b = Block {
            index : 0,
            timestamp_ms : now_ms(),
            data : "genesis".into(),
            previous_hash : "0".into(),
            nonce : 0,
            hash : String::new(),
        };
        b.hash = b.compute_hash();
        b
    }

    pub fn compute_hash_with_nonce(&self, nonce : u64) -> String  {
        let payload = format!{ 
            "{}|{}|{}|{}|{}", 
            self.index, self.timestamp_ms, self.data, self.previous_hash, nonce 
        };
        let digest = Sha256::digest(payload.as_bytes());
        hex::encode(digest)
    }

    pub fn compute_hash(&self) -> String {
        self.compute_hash_with_nonce(self.nonce)
    }
    // Incrementally add 1 and calculate hash until we reach leading
    // difficulty number zeros
    pub fn mine(&mut self, difficulty : usize )  {
        // appends difficlyt no of leading zeros
        let target_prefix = "0".repeat(difficulty);
        loop {
            //calculate hash
            let h = self.compute_hash_with_nonce(self.nonce);
            if h.starts_with(&target_prefix) {
                //if new hash matches with leading zeros break
                self.hash = h;
                break;
            } else {
                //else keep going
                self.nonce = self.nonce.wrapping_add(1);
            }
        }
    }
}

fn now_ms() -> u128{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
pub struct Blockchain {
    pub chain : Vec <Block>,
    pub difficulty : usize,
}

impl Blockchain {
    pub fn new (difficulty : usize) -> Self {
        Blockchain {
            chain : vec![Block::genesis()],
            difficulty : difficulty,
        }
    }
}
fn main() {
    let blockchain = Blockchain::new(3);
    println!("Hello, world!");
}
