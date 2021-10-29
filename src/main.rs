#![feature(cell_leak)]
use std::{cell::{RefCell, RefMut}};
use sha2::{Sha256, Sha512, Digest};
use lazy_static::lazy_static;

lazy_static! {
    static ref THEHASHER : Box<dyn Hasher + Sync + Send> = Box::new(Hasher256::new());
    static ref SHA256ALGO: Box<Sha256> = Box::new(Sha256::new());
    static ref SHA512ALGO: Box<Sha256> = Box::new(Sha256::new());
}

trait Hasher : Sync + Send {
    fn hash_str(&self, data : &str) -> String;
}

struct Hasher256 {
    hasher : RefCell<crypto::sha2::Sha256>
}

impl Hasher256 {
    pub fn new() -> Self {
        Self {
            hasher : RefCell::new(crypto::sha2::Sha256::new())
        }
    }
}

unsafe impl Sync for Hasher256 {
}

impl Hasher for Hasher256 {
    fn hash_str(&self, data : &str) -> String {
        let ch = RefMut::leak(self.hasher.borrow_mut());
        crypto::digest::Digest::reset(ch);
        crypto::digest::Digest::input(ch, data.as_bytes());
        crypto::digest::Digest::result_str(ch)
    }
}

struct Hasher512 {
    hasher : RefCell<crypto::sha2::Sha512>
}

impl Hasher512 {
    pub fn new() -> Self {
        Self {
            hasher : RefCell::new(crypto::sha2::Sha512::new())
        }
    }
}

unsafe impl Sync for Hasher512 {
}

impl Hasher for Hasher512 {
    fn hash_str(&self, data : &str) -> String {
        let ch = RefMut::leak(self.hasher.borrow_mut());
        crypto::digest::Digest::reset(ch);
        crypto::digest::Digest::input(ch, data.as_bytes());
        crypto::digest::Digest::result_str(ch)
    }
}

fn main() {
    println!("Hash value {}", THEHASHER.hash_str("hello world"));
}
