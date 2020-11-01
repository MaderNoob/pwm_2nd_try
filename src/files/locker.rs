use crate::encrypt::*;
use crate::errors;
use crate::files::*;
use rand::rngs::ThreadRng;
use rand::RngCore;
use sha2::Sha512;
use std::fs;
use std::io::{BufRead, BufReader};

pub trait LockFile {
    fn lock(
        &mut self,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
    ) -> Result<(), errors::Error>;
}
#[cfg(target_family = "unix")]
impl LockFile for fs::File {
    fn lock(
        &mut self,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
    ) -> Result<(), errors::Error> {
        let mut hash_salt_buffer = vec![0u8; salt_length + 1];
        thread_random.fill_bytes(&mut hash_salt_buffer[..salt_length]);

        let mut encryption_salt_buffer = vec![0u8; salt_length + 1];
        thread_random.fill_bytes(&mut encryption_salt_buffer[..salt_length]);

        // generate salted key hash
        let mut salted_key_hash_buffer = [0u8; 65];
        create_salted_hash::<Sha512, _, _>(&key, &hash_salt_buffer, &mut salted_key_hash_buffer);
        // 64 bytes for the hmac itself
        // and one more byte for the null byte at the end
        let mut hmac_buffer = [0u8; 65];
        let mut hmac_hasher = Sha512::new();

        // get file flags before locking
        let flags = self.get_unix_flags()?;

        // calculate headers size
        let headers_size = salted_key_hash_buffer.len()
            + hmac_buffer.len()
            + std::mem::size_of::<i32>()
            + hash_salt_buffer.len()
            + encryption_salt_buffer.len();

        // leave the headers empty for now,
        // as some of the values like the hmac havn't been calculated yet
        file_seek(self, SeekFrom::Start(headers_size as u64))?;

        // encrypt the file. used extra scope to dispose large buffers
        {
            let mut file_buffer = [0u8; 1024];
            let mut xor_key_buffer = [0u8; 1024];
            let mut chacha = create_chacha(&key, &encryption_salt_buffer[..salt_length]);
            loop {
                let amount = file_read(self, &mut file_buffer)?;
                if amount == 0 {
                    break;
                }
                chacha_encrypt(
                    &mut file_buffer[..amount],
                    &mut xor_key_buffer[..amount],
                    &mut chacha,
                );
                file_seek(self, SeekFrom::Current(-(amount as i64)))?;
                file_write_all(self, &mut file_buffer[..amount])?;
                hmac_hasher.update(&file_buffer[..amount]);
            }
        }

        // finalize hmac after updating it with encrypted file content
        finalize_hash_into_buffer(hmac_hasher, &mut hmac_buffer);

        // go back to the start of the file to write the headers
        file_seek(self, SeekFrom::Start(0))?;

        file_write_all(self, &mut salted_key_hash_buffer)?;
        file_write_all(self, &mut hmac_buffer)?;
        file_write_all(self, &mut flags.to_ne_bytes())?;
        file_write_all(self, &mut hash_salt_buffer)?;
        file_write_all(self, &mut encryption_salt_buffer)
    }
}
