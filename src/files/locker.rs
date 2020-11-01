use crate::errors;
use crate::files::*;
use rand::RngCore;
use rand::rngs::ThreadRng;
use sha2::Sha512;
use std::fs;

pub trait LockFile{
    fn lock(&mut self,key:&str,salt_length:usize,thread_random:&mut ThreadRng)->Result<(),errors::Error>;
}
impl LockFile for fs::File{
    fn lock(&mut self, key:&str,salt_length:usize,thread_random:&mut ThreadRng) ->Result<(),errors::Error> {
        let mut salted_key: Vec<u8> = vec![0u8;key.len()+salt_length];
        for (index,byte) in key.bytes().enumerate(){
            salted_key[index]=byte;
        }
        thread_random.fill_bytes(&mut salted_key[key.len()..]);
        let mut salted_key_hasher=Sha512::new();
        salted_key_hasher.update(salted_key);
        let mut salted_key_hash = salted_key_hasher.finalize();
        Ok(())
    }
}