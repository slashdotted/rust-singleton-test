#![feature(once_cell)]
use std::{lazy::SyncLazy, sync::Mutex};
use sha2::{Sha256, Sha512, Digest};
#[macro_use]
use lazy_static::lazy_static;

static THEHASHER : SyncLazy<Mutex<Box<dyn Hasher + Send + Sync>>> 
                    = SyncLazy::new(|| Mutex::new(Box::new(Hasher512::new())));

lazy_static! {
    static ref SHA256ALGO: Box<Sha256> = Box::new(Sha256::new());
    static ref SHA512ALGO: Box<Sha256> = Box::new(Sha256::new());
}


trait Hasher {
    fn hash_str(&mut self, data : &str) -> String;
}

struct Hasher256 {
    hasher : crypto::sha2::Sha256
}

impl Hasher256 {
    pub fn new() -> Self {
        Self {
            hasher : crypto::sha2::Sha256::new()
        }
    }
}

impl Hasher for Hasher256 {
    fn hash_str(&mut self, data : &str) -> String {
        crypto::digest::Digest::input(&mut self.hasher, data.as_bytes());
        crypto::digest::Digest::result_str(&mut self.hasher)
    }
}

struct Hasher512 {
    hasher : crypto::sha2::Sha512
}

impl Hasher512 {
    pub fn new() -> Self {
        Self {
            hasher : crypto::sha2::Sha512::new()
        }
    }
}

impl Hasher for Hasher512 {
    fn hash_str(&mut self, data : &str) -> String {
        crypto::digest::Digest::input(&mut self.hasher, data.as_bytes());
        crypto::digest::Digest::result_str(&mut self.hasher)
    }
}

fn main() {
     println!("Hash value {}", THEHASHER.lock().unwrap().hash_str("hello world"));
}
