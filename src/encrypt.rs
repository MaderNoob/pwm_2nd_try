use rand_chacha::ChaCha20Rng;
use rand::{RngCore,SeedableRng};
use sha2::{Digest,Sha256};

pub fn create_chacha<K:AsRef<[u8]>>(key:K)->ChaCha20Rng{
    let mut hasher = Sha256::new();
    hasher.update(key);
    let result=hasher.finalize();
    let mut seed = [0u8;32];
    for i in 0..32{
        seed[i]=result[i];
    }
    ChaCha20Rng::from_seed(seed)
}
pub fn chacha_encrypt(buf:&mut [u8],xor_key_buf:&mut [u8],chacha:&mut ChaCha20Rng){
    chacha.fill_bytes(xor_key_buf);
    for i in 0..buf.len(){
        buf[i]^=xor_key_buf[i];
    }
}
