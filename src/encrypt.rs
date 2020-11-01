use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

pub fn create_chacha<K: AsRef<[u8]>, S: AsRef<[u8]>>(key: K, salt: S) -> ChaCha20Rng {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(salt);
    let result = hasher.finalize();
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = result[i];
    }
    ChaCha20Rng::from_seed(seed)
}

pub fn chacha_encrypt(buf: &mut [u8], xor_key_buf: &mut [u8], chacha: &mut ChaCha20Rng) {
    chacha.fill_bytes(xor_key_buf);
    for i in 0..buf.len() {
        buf[i] ^= xor_key_buf[i];
    }
}

pub fn create_salted_hash<H, K, S>(key: K, salt: S, buffer: &mut [u8])
where
    H: Digest,
    K: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    let mut hasher = H::new();
    hasher.update(key);
    hasher.update(salt);
    finalize_hash_into_buffer(hasher, buffer)
}

pub fn finalize_hash_into_buffer<H: Digest>(hasher: H, buffer: &mut [u8]) {
    let hash = hasher.finalize();
    for i in 0..hash.len() {
        buffer[i] = hash[i];
    }
}
